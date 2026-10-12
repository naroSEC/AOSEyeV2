# AOSEye

Android APK 정적 보안 분석을 위한 데스크톱 워크벤치.

AOSEye는 JEB에서 추출한 DEX 명령어, 제어 흐름과 참조 정보를 바탕으로 보안 점검 후보를 찾고 원본 코드의 근거를 연결합니다. API 사용 여부, 구성상 노출, 데이터 흐름을 구분하며 분석하지 못한 범위도 결과에 남깁니다.

Python · PySide6 / Qt Quick · JEB Core API · MIT

## 주요 기능

- **공격 표면** — 컴포넌트, 권한, Deep Link, Network Security Config, 백업 및 FileProvider 설정 검토
- **데이터 흐름** — 레지스터, 인자·반환값, 제한된 객체·컬렉션 모델을 통한 source-to-sink 추적
- **보안 문맥** — WebView 설정과 bridge 등록, TLS 콜백, 암호 초기화, PendingIntent, 민감정보 저장·로그·클립보드 경로 분석
- **근거 탐색** — 디컴파일, 바이트코드, CFG, AST, 호출 그래프와 JEB XREF
- **검토와 공유** — 분석가 메모, 프로젝트 저장·재열기, HTML·CSV 보고서 및 정규화 DEX JSON 내보내기

분석 대상 APK를 설치하거나 실행하지 않습니다. JEB 바이너리와 라이선스는 배포물에 포함하지 않습니다.

## 시작하기

### 요구 환경

- Python 3.11 이상 — 현재 통합 검증 환경은 Windows / Python 3.14.2입니다.
- Java 21
- Core API 사용이 허용된 로컬 JEB 설치 — JEB 5.47에서 검증했습니다.

```powershell
git clone https://github.com/naroSEC/AOSEyeV2.git
cd AOSEyeV2
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[test]"
python -m analyzer
```

GUI의 **JEB settings**에서 설치 경로를 지정합니다. 기본 경로는 제공하지 않으며 사용자 디렉터리를 자동 검색하지 않습니다. 명시적인 환경 변수도 사용할 수 있습니다.

```powershell
$env:AOSEYE_JEB_PATH = 'C:\tools\jeb'
python -m analyzer probe
```

JEB를 연결하지 않아도 저장된 프로젝트를 열거나 보고서를 내보낼 수 있습니다.

### CLI

```powershell
# APK 분석 및 프로젝트 저장
python -m analyzer analyze C:\samples\app.apk -o C:\reports\app.json

# 저장 결과를 HTML로 내보내기
python -m analyzer export C:\reports\app.json --format html -o C:\reports\app.html

# GUI 초기화 확인
python -m analyzer gui-smoke
```

분석 명령은 정상 완료 시 `0`, 범위 제한이나 일부 실패가 있는 결과를 저장하면 `2`를 반환합니다. GUI에서는 Diagnostics에서 원인을 확인할 수 있습니다.

## 결과 해석

탐지 결과에는 유형, 심각도, 신뢰도, 검증 상태와 원본 DEX 위치가 함께 기록됩니다. 위험 API가 존재한다는 사실만으로 취약점을 확정하지 않습니다.

- `REVIEW` — 사용 문맥을 확인해야 하는 검토 대상
- `EXPOSURE` — Manifest 등에서 확인된 노출
- 데이터 흐름 후보 — 지원 모델 안에서 source와 sink가 연결된 경로
- `UNKNOWN` — 근거 부족 또는 미지원 범위. 안전하다는 뜻이 아닙니다.

현재 분석은 호출 깊이·경로·시간·메모리 예산이 있는 제한적 모델입니다. 일반적인 가상 호출, 암시적 IPC, 네이티브 코드, 리플렉션 및 모든 비동기 실행 순서를 해결하지 않습니다. 정적 연결은 런타임 실행이나 공격 가능성의 증명이 아니며, `complete=False`인 결과는 부분 분석입니다.

## 개발 및 테스트

```powershell
python -m pytest -q
```

JEB 통합 시험에는 별도 설정이 필요합니다. 기본 테스트 실행에서 통합 시험이 생략될 수 있습니다.

```powershell
$env:AOSEYE_JEB_PATH = 'C:\tools\jeb'
$env:AOSEYE_RUN_JEB = '1'
$env:AOSEYE_TEST_AAPT2 = 'C:\Android\Sdk\build-tools\35.0.0\aapt2.exe'
python -m pytest -m jeb -v
```

일부 시험은 로컬 Android SDK, 생성 fixture 또는 별도 샘플을 요구합니다. 실제 APK, JEB 설치 파일, 라이선스와 분석 보고서는 저장소에 추가하지 마세요.

## 문서

- [아키텍처](docs/ARCHITECTURE.md)
- [민감정보 흐름과 저장 문맥](docs/SENSITIVE_FLOW.md)
- [WebView 객체 문맥](docs/RECEIVER_CONTEXT.md)
- [컴포넌트 간 전달](docs/COMPONENT_DELIVERY.md)
- [규칙 조건](docs/RULE_CONDITIONS.md)
- [지원 범위와 남은 작업](docs/COMPLETION_PLAN.md)
- [설치 안내](docs/WHEEL_INSTALLATION.md)

## 보안과 라이선스

프로젝트와 내보낸 보고서에는 원본 코드 및 문자열이 포함될 수 있습니다. 비밀정보 후보가 마스킹되더라도 보고서 전체가 익명화되는 것은 아닙니다. 분석 권한이 있는 앱만 점검하고, 공유 전에 결과를 검토하세요.

AOSEye는 [MIT License](LICENSE)를 따릅니다. JEB와 의존성에는 각각의 라이선스가 적용됩니다. [제3자 고지](THIRD_PARTY_NOTICES.md), [보안 안내](SECURITY.md), [기여 안내](CONTRIBUTING.md)를 참고하세요.
