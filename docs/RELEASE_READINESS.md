# 출시 준비 및 승인 기준

현재 상태: **출시 승인 전 / 원래 요청 전체 미완료**. 테스트 통과나 wheel 생성은 출시 승인과 다르다.
남은 기능을 임의로 삭제하거나 “1차 출시”로 축소 승인하지 않는다. 상세 미구현 목록은
COMPLETION_PLAN.md에 유지한다. 2026-10-11 소유자는 오픈소스 배포와 MIT 라이선스를 선택했다.
지원 범위와 최종 인수는 별도 확정이 필요하다. 소스 저장소는
https://github.com/naroSEC/AOSEyeV2 이며 2026-10-12 main 최초 푸시를 완료했다.
소스 게시와 제품 출시 승인은 별개다.

최신 민감정보 저장 문맥 묶음의 wheel은
`e64de1e81ebd25c317baffde493791617a3caf5982f856750d0de000d80ee599`다.
2026-10-12 전체 회귀 2366개 및 독립 설치 14개가 통과했다. 이전 묶음의 2250개 결과와
혼용하지 않고 이 wheel에 결합된 새 증거를 사용한다. 새 PC/대형 APK/수동 인수와
아래의 기능·출시 차단 항목은 남아 있다.

## 이번 출시 준비 작업

- 새 설치의 JEB 경로는 미설정이다. 사용자가 GUI/CLI/AOSEYE_JEB_PATH로 지정해야 한다.
  현재 폴더나 홈을 자동 탐색하지 않으며 저장된 사용자 경로를 유지한다.
- release_gate.py는 wheel의 Python/QML/YAML을 현재 소스와 바이트 단위로 비교한다.
  중복 ZIP 항목과 JAR/APK 포함, 다른 wheel의 설치 결과, 빠진 설치 검증 단계를 차단한다.
- 같은 wheel SHA-256을 suite 이름에 기록한 JUnit 회귀 결과를 요구한다.
  실패/오류/skip, 비어 있는 결과 및 불일치를 차단한다.
- 요구사항 범위, 대화형 GUI, 별도 PC, 실제 APK/제한, 라이선스, 배포/지원에 대한
  담당자·근거·명시적 승인을 요구한다. template의 false를 도구가 임의 변경하지 않는다.
- 통과해도 READY_FOR_OWNER_RELEASE_REVIEW일 뿐 자동 게시/서명/상용 출시가 아니다.
  로컬 증거의 일관성 검사이지 독립 인증, 증거 위변조 방지 또는 법률 판단은 아니다.
- 소유자가 선택한 MIT를 LICENSE 및 wheel 메타데이터에 적용했다. release gate는
  License-Expression/License-File과 실제 포함된 고지 파일의 바이트도 대조한다.
- 소스 sdist는 MANIFEST.in으로 구성한다. validate_source_distribution.py는 추출 없이
  허용 경로/확장자, 필수 파일, 중복·경로 탈출·링크·크기 예산을 검사한다.
  APK/DEX/JAR, 실제 보고서 JSON, 첨부 파일과 가상환경은 배포 대상이 아니다.
  문서의 역사적 로컬 경로·앱 이름은 남아 있으므로 이 검사는 익명화나 secret scan이 아니다.
- PACKAGE_README.md는 개인 설치 경로가 없는 공개 패키지 소개다. SECURITY.md의
  비공개 신고 채널과 지원 정책은 저장소 운영 정책에 맞춰 별도 확정해야 한다.
- 독립 설치에서 관측한 의존성 버전/라이선스 메타데이터는 DEPENDENCY_VALIDATION.md에
  기록했다. 패키지 메타데이터 관측은 취약점 검사나 제3자 라이선스 준수 승인이 아니다.

## 재현 순서 (PowerShell)

소스 수정 후에는 새 wheel을 만들고 회귀/독립 설치를 다시 실행한다.
회귀 실행 이후 소스/테스트를 변경하면 기존 결과를 재사용하지 않는다.

```powershell
$env:AOSEYE_JEB_PATH = 'C:\path\to\licensed-jeb'
$env:AOSEYE_RUN_JEB = '1'
$env:AOSEYE_TEST_AAPT2 = 'C:\path\to\aapt2.exe'
python -m pip wheel . --no-deps -w dist
$releaseHash = (Get-FileHash dist/aoseye-0.1.0-py3-none-any.whl -Algorithm SHA256).Hash.ToLowerInvariant()
python -m pytest -q --junitxml=build/release-regression.xml -o "junit_suite_name=aoseye.$releaseHash"
python tools/validate_wheel_install.py dist/aoseye-0.1.0-py3-none-any.whl --jeb-path $env:AOSEYE_JEB_PATH --apk build/fixtures/flow-fixture.apk
python tools/release_gate.py --wheel dist/aoseye-0.1.0-py3-none-any.whl --installation 'C:\path\to\validation.json' --regression build/release-regression.xml --acceptance docs/release-acceptance.template.json
```

마지막 명령의 template은 미승인 상태이므로 exit 2 / BLOCKED가 정상이다.
실제 승인 문서는 template과 별도 파일로 보존하고 승인 대상 wheel hash와 근거를 기록한다.
synthetic 단위 테스트의 승인 데이터는 실제 제품 승인 증거가 아니다.

소스 배포는 별도 빌드 환경에 `build`를 설치한 뒤 다음처럼 확인한다.

```powershell
python -m build --sdist --outdir dist
python tools/validate_source_distribution.py dist/aoseye-0.1.0.tar.gz
```

SOURCE_BOUNDARY_PASS는 파일 경계 검사만 통과했다는 뜻이다. 공개 업로드는 수행하지 않는다.
build/dist를 포함하는 작업 폴더 전체를 업로드하지 말고 검토한 소스만 새 저장소에 포함한다.
현재 작업 폴더는 Git 저장소이며 origin은 https://github.com/naroSEC/AOSEyeV2.git 이다.
APK/JEB/개인 설정/빌드 및 실제 분석 결과는 추적하지 않는다. 문서의 개인 사용자 경로는
공개용 자리표시자로 일반화했다. 전체 secret scan이나 제3자 검토 완료를 의미하지 않는다.

## 출시 차단 항목

- 원 요청 대비 TLS/WebView, 민감 데이터, 암호/IPC/인증, 규칙 등의 미완료 범위.
- 최신 대형 APK 검증은 시스템 메모리 보호 기준 때문에 미완료. 이전 성공으로 대체 불가.
- 독립 wheel 가상환경 검증은 같은 Windows PC의 Java/JEB/라이선스를 사용한다.
  Python 3.11 이상을 선언하지만 현재 실제 통합 검증은 Python 3.14.2이며 나머지 버전/새 PC는 미검증.
- offscreen GUI smoke는 실제 사용자 화면 조작·업무 인수를 대체하지 않는다.
- 배포 조건: AOSEye는 소유자가 선택한 MIT이며 제3자 소프트웨어까지 MIT로 바꾸지 않는다.
  의존성 재배포 고지, Qt 배포 조건 및 사용자의 JEB 라이선스 조건 확인이 필요하다.
- 소스 저장소 main 게시를 완료했다. 비공개 보안 신고 채널 및 지원 정책은 아직 미정이며
  릴리스 담당자의 확인이 필요하다.
- EXE 설치 프로그램/코드 서명/오프라인 의존성 묶음은 현재 wheel 검증 범위가 아니다.

## 운영과 복구

분석 결과 complete=False 또는 CLI exit 2는 일부 분석/실패이며 전체 APK 안전 판정이 아니다.
설정/캐시/로그는 LOCALAPPDATA/AOSEye에 저장된다. 프로젝트에는 원본 코드/문자열이 포함될 수
있어 민감 자료로 취급하고 공유 전에 검토한다. APK는 설치/실행하지 않는다.
업그레이드 전 기존 프로젝트·설정을 별도 보관하고 새 가상환경에서 wheel을 검증한다.
문제가 있으면 기존 가상환경과 원본 프로젝트로 복귀한다. 원본을 새 결과로 덮어쓰지 않는다.
사용하지 않는 검증용 임시 가상환경 삭제는 검증 로그 보존 여부를 정한 뒤 소유자가 수행한다.
