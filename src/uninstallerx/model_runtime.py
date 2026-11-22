from __future__ import annotations

import ctypes
import hashlib
import http.client
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
from collections.abc import Callable
from ctypes import wintypes
from pathlib import Path
from threading import Event

from .model_provider import LocalGranite, ModelError
from .windows import has_reparse_component, system_directory


HOST = "127.0.0.1"
STARTUP_TIMEOUT = 90


class MemoryStatus(ctypes.Structure):
    _fields_ = [
        ("length", wintypes.DWORD), ("load", wintypes.DWORD),
        ("total_physical", ctypes.c_uint64), ("available_physical", ctypes.c_uint64),
        ("total_page_file", ctypes.c_uint64), ("available_page_file", ctypes.c_uint64),
        ("total_virtual", ctypes.c_uint64), ("available_virtual", ctypes.c_uint64),
        ("available_extended_virtual", ctypes.c_uint64),
    ]


def available_ram_gib() -> float:
    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    if not kernel.GlobalMemoryStatusEx(ctypes.byref(status)):
        raise ctypes.WinError(ctypes.get_last_error())
    return status.available_physical / (1024 ** 3)


class ManagedModel:
    """Start the configured local server and own only the process we launch."""

    def __init__(self, repo_root: Path, port: int) -> None:
        self.repo_root = repo_root.resolve()
        self.port = port
        self.process: subprocess.Popen[bytes] | None = None

    def prepare(self, show: Callable[[str], None], closing: Event) -> LocalGranite | None:
        if not 1 <= self.port <= 65535:
            raise ModelError("The model port must be between 1 and 65535.")
        manifest = json.loads((self.repo_root / "docs" / "model-manifest.json").read_text(encoding="utf-8"))
        runtime = self.repo_root / ".local" / "runtime"
        release = manifest["runtime"]["release"]
        binary = runtime / f"llama-{release}-cpu" / "llama-server.exe"
        model_file = manifest["model"]["file"]
        weights = self.repo_root / ".local" / "models" / Path(model_file).stem / model_file
        key_file = runtime / "api-key.txt"
        if not binary.is_file() or not weights.is_file():
            if (self.repo_root / "scripts" / "setup_local_model.ps1").is_file():
                raise ModelError("Model files or runtime are missing.\nRun ./scripts/setup_local_model.ps1 in PowerShell and retry.")
            raise ModelError("Model files or runtime are missing.\nKeep the .local model folder next to the app and retry.")
        if has_reparse_component(key_file, self.repo_root):
            raise ModelError("The local model API key location is redirected.")

        pid = self._existing_pid(binary)
        if pid is None:
            config = manifest["serving"]
            minimum_ram = config["minimum_free_ram_gib"]
            free_ram = available_ram_gib()
            if free_ram < minimum_ram:
                raise ModelError(f"Available RAM: {free_ram:.1f} GiB. The model requires {minimum_ram} GiB.\nClose other apps and retry.")

            show("Checking the local model file.")
            digest = hashlib.sha256()
            with weights.open("rb") as stream:
                while not closing.is_set() and (chunk := stream.read(8 * 1024 ** 2)):
                    digest.update(chunk)
            if closing.is_set():
                return None
            if digest.hexdigest() != manifest["model"]["sha256"]:
                raise ModelError("The model file failed the SHA-256 check.")

            self._prepare_key(key_file)
            show("Loading the model into memory.")
            log_path = runtime / f"ui-model-{self.port}.log"
            with log_path.open("wb") as log:
                self.process = subprocess.Popen(
                    [str(binary), "-m", str(weights), "--host", HOST, "--port", str(self.port),
                     "--api-key-file", str(key_file), "--cors-origins", f"http://{HOST}:{self.port}",
                     "-c", str(config["context_tokens"]), "-t", str(config["threads"]),
                     "--parallel", str(config["parallel_requests"]), "--reasoning", config["reasoning"],
                     "--no-warmup", "-ngl", "0"],
                    cwd=binary.parent, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
            pid = self.process.pid
        else:
            show("Connecting to the running local model.")

        deadline = time.monotonic() + STARTUP_TIMEOUT
        while not closing.is_set() and time.monotonic() < deadline:
            if self.process is not None and self.process.poll() is not None:
                raise ModelError(f"The model process exited. See .local/runtime/ui-model-{self.port}.log for details.")
            if self._get_json("/health") == {"status": "ok"}:
                if self._existing_pid(binary) != pid:
                    raise ModelError(f"The model process on port {self.port} changed. Retry model setup.")
                if closing.is_set():
                    return None
                model = LocalGranite(self.repo_root, port=self.port)
                models = self._get_json("/v1/models", headers={"Authorization": f"Bearer {model.api_key}"})
                entries = models.get("data") if models is not None else None
                if not isinstance(entries, list) or not any(
                    isinstance(entry, dict) and isinstance(entry.get("id"), str)
                    and Path(entry["id"]).name.casefold() == model_file.casefold()
                    for entry in entries
                ):
                    raise ModelError(f"Could not verify the project model on port {self.port}. Check the model file and settings.")
                return model
            closing.wait(0.25)
        if closing.is_set():
            return None
        raise ModelError(f"The model did not start within {STARTUP_TIMEOUT} seconds. Retry model setup.")

    def _prepare_key(self, key_file: Path) -> None:
        if key_file.is_file():
            return
        with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", dir=key_file.parent, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(secrets.token_urlsafe(32))
        try:
            # Windows rename publishes the complete key without replacing a concurrent install's key.
            temporary.rename(key_file)
        except FileExistsError:
            pass
        finally:
            temporary.unlink(missing_ok=True)

    def _existing_pid(self, binary: Path) -> int | None:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((HOST, self.port)) != 0:
                return None
        # Verify the listening executable before reusing a server on the port.
        result = subprocess.run(
            [str(system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"),
             "-NoProfile", "-NonInteractive", "-Command",
             "$listener = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort $env:UNINSTALLERX_MODEL_PORT "
             "-State Listen -ErrorAction SilentlyContinue); "
             "if ($listener.Count -eq 1) { $server = Get-Process -Id $listener.OwningProcess -ErrorAction SilentlyContinue; "
             "if ($server.Path -ieq $env:UNINSTALLERX_MODEL_EXE) { $server.Id } }"],
            env={**os.environ, "UNINSTALLERX_MODEL_PORT": str(self.port), "UNINSTALLERX_MODEL_EXE": str(binary.resolve())},
            capture_output=True, check=False, timeout=8, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        output = result.stdout.strip()
        if result.returncode != 0 or not output.isdigit():
            raise ModelError(f"Another program is using port {self.port}.\nClose it or launch UninstallerX on another port.")
        return int(output)

    def _get_json(self, path: str, *, headers: dict[str, str] | None = None) -> dict | None:
        connection = http.client.HTTPConnection(HOST, self.port, timeout=0.75)
        try:
            connection.request("GET", path, headers=headers or {})
            response = connection.getresponse()
            if response.status == 200:
                result = json.loads(response.read(65536))
                return result if isinstance(result, dict) else None
        except (OSError, http.client.HTTPException, ValueError):
            return None
        finally:
            connection.close()
        return None

    def stop(self) -> None:
        process = self.process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        self.process = None
