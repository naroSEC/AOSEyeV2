# wheel 독립 설치 검증

## 사용자 설치

개발용 editable 설치 없이 wheel과 의존성을 설치할 수 있다. Python, Java 21 및
Core API 실행을 허용하는 로컬 JEB는 별도로 필요하다. 아래 경로는 예시다.

```powershell
python -m venv C:\AOSEyeRuntime
C:\AOSEyeRuntime\Scripts\python.exe -m pip install C:\Develop\AOSEyeV2\dist\aoseye-0.1.0-py3-none-any.whl
C:\AOSEyeRuntime\Scripts\aoseye.exe probe --jeb-path 'C:\path\to\jeb'
C:\AOSEyeRuntime\Scripts\aoseye.exe
```

GUI에서는 JEB settings로 경로를 저장한다. CLI의 `--jeb-path`는 해당 명령에만 적용된다.
wheel에는 JEB/JAR/APK가 포함되지 않는다. pip 설치 시 Python 의존성 다운로드가 발생할
수 있지만 분석 대상 APK나 분석 결과를 외부로 전송하는 기능은 없다.

## 재현

저장소에서 fixture와 wheel을 준비한 후 실행한다. 이 검증의 `--apk`는 임의 앱이 아닌
`tools/build_fixture.py`로 생성한 `flow-fixture.apk`를 지정해야 한다.

```powershell
python -m pip wheel . --no-deps -w dist
python tools/validate_wheel_install.py dist/aoseye-0.1.0-py3-none-any.whl `
  --jeb-path 'C:\Users\<user>\Desktop\Security\tools\Mobile\jeb\JB-5.47' `
  --apk build/fixtures/flow-fixture.apk
```

도구는 시스템 임시 폴더에 새 가상환경을 만들며 system-site-packages를 사용하지 않는다.
모든 설치/실행 명령의 작업 폴더는 저장소 밖이다. PYTHONPATH/PYTHONHOME을 제거하고
모듈 명령은 `-I`로 실행한다. 실제 analyzer 위치가 가상환경 내부인지 검사한다.
LOCALAPPDATA는 검증 폴더로 분리해 기존 AOSEye 설정/캐시/로그를 변경하지 않는다.
표준 출력/오류와 validation.json, evidence.json, project.json, venv를 보존하며
완료 시 경로를 출력한다. 검증 도구 자체의 timeout 또는 명령 실패는 실패로 기록한다.
분석 명령의 exit 2는 부분 분석일 수 있으므로 보고서 재열기 검사까지 수행한다.

## 2026-10-02 실행 결과

Windows / Python 3.14.2 / Java 21.0.10 / JEB 5.47 환경에서 다음을 통과했다.

- wheel 설치 및 pip check, 패키지 위치/필수 QML·YAML·bridge 자원 확인
- console entry point와 `python -m analyzer` 도움말 실행
- offscreen QML GUI smoke: exit 0, stderr 없음
- 실제 JEB probe, fixture DEX/디컴파일/AST/XREF inspect
- fixture 분석 저장 및 설치된 패키지로 재열기: 25개 본문, 18개 finding, complete=true

설치 버전: AOSEye 0.1.0, PySide6 6.11.2, PyYAML 6.0.3, defusedxml 0.7.1.
검증 도구의 환경 격리·실패 기록·부분 분석 반환 코드 처리를 mock 회귀 3개로 추가 검사했고,
실제 JEB 통합을 포함한 전체 회귀는 348 passed (28.89초)였다.
검증한 wheel SHA-256:
`e6a17ffc8525891317bb0da12936aabd334d1f49660262d3d053e6a0a2584b03`.
원본 로그 디렉터리:
`C:\validation-temp\aoseye-wheel-65jtvn3q`.

이는 같은 Windows 호스트에서 Python 패키지를 격리한 검증이다. JDK/JEB/라이선스 및
OS 구성은 기존 호스트 것을 사용했다. 완전히 새 OS, Python 3.11~3.13, 다른 Qt/JDK,
설치형 EXE·서명·오프라인 설치·장시간 안정성을 검증한 것은 아니다. offscreen smoke는
수동 화면 조작 인수를 대체하지 않는다. 이번에는 사용자 APK 2개를 재분석하지 않았다.
fixture의 complete=true를 실제 앱 전체 분석의 완전성으로 일반화할 수 없다.

## 2026-10-02 후속: 배포 실패 처리

CLI의 예상 가능한 파일/입력/backend 오류는 traceback 대신 오류 메시지와 exit 2로
반환하도록 보강했다. JEB 경로 override도 설정 검증을 거친다. 명시한 `settings.java`는
번들 런타임보다 우선하며, 기본값 `java`일 때만 번들 → 유효한 JAVA_HOME → PATH 순으로
찾는다. Java 실행 실패는 실제 선택한 실행 경로와 설정 확인 안내를 제공하고 세션 자원을
정리한다. 예상하지 못한 프로그래밍 오류를 일괄 숨기는 처리는 하지 않는다.

별도 설치의 Python 경로를 지정해 실패 검증을 재현할 수 있다.

```powershell
python tools/validate_install_failures.py --python C:\AOSEyeRuntime\Scripts\python.exe
```

다음 8개 시나리오가 exit 2, traceback 없음, 설정 및 기존 보고서 바이트 보존을 통과했다:
깨진 JSON, 잘못된 설정 값, 없는 JEB, 없는 Java, 공백 JEB override, 없는 분석 입력,
로그 경로가 디렉터리가 아닌 경우, inspect의 backend 실패.
Java 실패는 JAR 경로만 존재하는 가짜 설치에서 실행 파일 누락을 검사했다.
파일 시스템 ACL에 의한 접근 거부나 손상된 실제 JAR/라이선스 만료를 재현한 것은 아니다.
GUI 대화형 복구는 이번 오류 검사 범위 밖이다.

갱신 wheel SHA-256:
`b2f8f2cc476918bcd1aae21673e29457cf9df8a2ac013f6157127269eb72de8b`.
새 가상환경의 정상 설치/CLI/GUI/JEB/분석·재열기 10개 검사도 모두 통과했다.
정상 로그: `C:\validation-temp\aoseye-wheel-uateko7b`.
오류 로그: `C:\validation-temp\aoseye-failures-7mtlm6i3`.
검증 중 Windows 출력 디코딩 실패가 발견돼 자식 Python에 `-X utf8`을 명시하도록
검증 도구를 수정한 뒤 8개 시나리오를 다시 통과했다.
최종 전체 회귀는 실제 JEB 통합을 포함해 **351 passed (33.58초)**였다.
Java 설정 우선순위와 실패 후 자원 정리/재시도를 mock 검사하고, 소스 회귀용 subprocess와
wheel 전용 격리 실행을 구분했다. 소스 회귀에서는 개발 환경 의존성 경로를 명시적으로
전달하지만 위 wheel 검증은 저장소 및 개발 환경 의존성 경로를 추가하지 않는다.
