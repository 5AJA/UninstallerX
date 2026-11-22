# 외부 합성 샌드박스 실행 계약

다른 팀이 작성한 합성 앱을 내부 fixture 생성기와 정답 목록 없이 시험할 때 사용한다. 샌드박스는 저장소의 `.local/external/<사례 이름>/` 아래에 둔다. `sandbox` 명령은 시험 환경을 만들거나 제거하지 않는다. **계획과 정확한 대상별 승인을 입력해야** 변경을 수행한다.

필요한 구조:

```text
.local/external/<case>/
  .uninstallerx-sandbox.json
  installed/<app name>/...   # 설치형
  portable/<app name>/...    # 포터블
  appdata/<app name>/...
  vendor/...                # 설치형 제거기, 필요할 때
```

`.uninstallerx-sandbox.json`에는 `app_name`, `kind`(`installed` 또는 `portable`), `registry_scope_key`를 적는다. 예:

```json
{"app_name":"Sample Editor","kind":"portable","registry_scope_key":"Software\\UninstallerXFixtures\\ExternalCase1"}
```

HKCU의 `Software\UninstallerXFixtures\ExternalCase1\Apps\Sample Editor` 아래에 앱 전용 설정값을 둔다. 설치형은 HKCU `Software\Microsoft\Windows\CurrentVersion\Uninstall`의 고유 하위 키에 `DisplayName`, `InstallLocation`, `AppDataLocation`, `SettingsKey`, `UninstallString`을 둔다. 모든 파일 경로와 제거기 파일은 샌드박스 안에 있어야 한다. 설치·데이터 영역의 넓은 경계와 앱 이름을 검사하지만 특정 정답 파일 목록은 입력받지 않는다. 중첩 파일은 소유권 근거 부족으로 거부한다.

PowerShell 두 번째 창에서:

```powershell
$env:PYTHONPATH = 'src'
python -m uninstallerx sandbox --root '.local/external/ExternalCase1' --app 'Sample Editor' --kind portable --registry-root 'Software\UninstallerXFixtures\ExternalCase1'
```

모델 서버 실행법은 [README](../README.md)에 있다. 보고서에는 실행·거부·승인 기록이 남는다. 외부 샌드박스의 **정답 목록이 없으므로** `execution_completed_unscored`는 모든 잔여물이 정리됐다는 뜻이 아니다. 작성자가 별도 정답과 전후 스냅샷으로 채점해야 독립 평가가 된다. 실제 사용자 앱이나 개인 자료를 이 샌드박스에 넣지 않는다.
