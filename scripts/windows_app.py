import argparse
import ctypes
import sys
from pathlib import Path
from tkinter import messagebox

from uninstallerx.ui import launch


class AppArguments(argparse.ArgumentParser):
    def _print_message(self, message, file=None):
        if message:
            messagebox.showinfo("UninstallerX", message)

    def error(self, message):
        messagebox.showerror("UninstallerX", message)
        raise SystemExit(2)


def main() -> None:
    parser = AppArguments(prog="UninstallerX.exe", description="Open the UninstallerX desktop app.")
    parser.add_argument("--port", type=int, default=18089, help="Local model server port")
    parser.add_argument("--portable-root", type=Path, action="append", default=[],
                        help="Add a local folder to the portable-app search (can be repeated)")
    args = parser.parse_args()
    app_dir = Path(sys.executable).resolve().parent
    try:
        # Restore Windows DLL lookup before starting the model or any system tools.
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        if not kernel.SetDllDirectoryW(None):
            raise ctypes.WinError(ctypes.get_last_error())
        launch(app_dir, args.port, apply=True, portable_roots=tuple(args.portable_root))
    except Exception as exc:
        messagebox.showerror("UninstallerX", str(exc))
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
