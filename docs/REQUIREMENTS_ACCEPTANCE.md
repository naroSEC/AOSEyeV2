# 원래 요구사항 대조 및 완료 기준

2026-10-08: 현재 개발 backlog와 완료 조건은 `COMPLETION_PLAN.md`를 참조한다.
이하 항목은 초기 요구사항 대조 기록이며 전체 완료 선언이 아니다.

기준일: 2026-10-01. 이 문서는 작업 범위와 인수 기준의 **제안**이다.
원래 요구사항을 축소하거나 사용자의 최종 인수를 대신하지 않는다.

2026-10-05 후속: 최신 회귀 수와 구현 범위는 `IMPLEMENTATION_STATUS.md`를 우선 참조한다.
아래 초기 근거 수치는 당시 기록이다. 후보 GUI 재열기/제한 확장과 기본 HTML/CSV/정규화
DEX JSON 출력은 `CANDIDATE_EXPANSION_AND_REPORTS.md`, FileProvider/백업 선언 인벤토리와
대용량 부분 결과의 출력 검증은 `STORAGE_CONFIGURATION.md`에 있다. 전체 제품 완료는 아니다.

## 결론

현재 상태는 실제 JEB와 사용자 제공 APK에서 검증된 초기 분석 도구다.
기반 구조가 동작한다는 사실과 고급 보안 분석 플랫폼 전체가 완성됐다는 주장은 다르다.
테스트 수는 요구사항 충족률이나 취약점 탐지율이 아니다. 임의의 완료 백분율은 산출하지 않는다.

현재까지의 근거: 전체 테스트 111개, JEB 5.47/Java 21/Python 3.14.2 로컬 실행,
사용자 제공 1 DEX/17 DEX APK와 자체 생성한 분석용 fixture.
실제 APK 결과는 모델/예산 한계가 남은 부분 분석이다. 설치 가능한 fixture,
독립적으로 라벨링된 정답 데이터셋, 다양한 OS/JDK/Python 조합, 100MB 이상 APK 및
장시간 내구성 검증까지 완료한 것은 아니다.

## 근거 문서와 판정 방법

- 원문 A: 사용자가 제공한 최초 요구사항 `붙여넣은 텍스트.txt`, §1–25.
  위치: `C:/Users/<user>/.codex/attachments/3bcb28c6-23ad-4531-9034-893cd926455d/붙여넣은 텍스트.txt`.
- 원문 B: JEB Integration Environment 보충 요구사항.
  위치: `C:/Users/<user>/.codex/attachments/33acfb5e-32c6-4afe-a0ba-22c25d032a7e/붙여넣은 텍스트.txt`.
- 구현 근거: `src/analyzer/`, `tests/`, `tools/`, `pyproject.toml`.
- 실행 근거: `IMPLEMENTATION_STATUS.md`, `REAL_APK_VALIDATION.md`, `build/real-apk-tests-*/`.

판정은 **검증 범위 내 충족 / 부분 구현 / 미구현 / 후속 확장 / 미검증**으로 구분한다.
enum·인터페이스·탭·규칙 이름이 존재한다는 것만으로 실제 분석 기능을 구현했다고 보지 않는다.
권장 완료 기준은 반드시 테스트 또는 재현 절차로 확인할 수 있어야 한다.

## 요구사항 추적

### R01 — 환경과 UI/Core 분리 (원문 A §1, §3, §21–23)

검증 범위 내 충족. Python/PySide6/QML, Application/Core/Backend 분리를 갖췄다.
근거: `app/application.py`, `core/models.py`, `backends/base.py`, `gui/`, `test_gui.py`.
유지 기준: core가 Qt나 상용 Java 타입에 의존하지 않으며 변경마다 회귀 테스트를 통과한다.
파일/디렉터리 배치는 원문의 예시와 달라도 책임 분리가 유지되면 된다.

### R02 — 설치된 JEB와 지속 Custom Client (원문 A §2, 원문 B)

검증 범위 내 충족. 설치 경로를 전달한 Core/Engines 초기화, 지속 JVM, 프로젝트 교체,
종료·취소·타임아웃·정규화 IPC를 구현했다. 상용 구성 요소를 번들하지 않는다.
근거: `backends/jeb/`, `test_backend.py`, `test_jeb.py`, 실제 취소 검증 기록.
한계: 임의 Java 실행 래퍼의 프로세스 트리 종료, 타 라이선스/플랫폼 조합은 미검증이다.
JEB IR/추가 deobfuscation DTO는 원문 B에서 향후 기능으로 명시되어 있어 초기 인수 필수와 분리한다.
JADX/Androguard 실제 구현도 원문에서 후속 확장이다.

### R03 — JEB 증거 추출 (원문 A §2, 원문 B Step 1–10)

검증 범위 내 충족: DEX 클래스/메서드/필드, 명령어·CFG, 원본 XREF,
decompile/Java AST 및 정규화 모델 소비. 원본 XREF와 실제 DEX operand 일치 여부도 구분한다.
부분 구현: 호출 그래프는 선언 참조이며 정밀한 가상 dispatch 해석이 아니다.
근거: `AOSEyeBridge.py`, `backends/base.py`, `core/graph.py`, `test_jeb.py`.
추가 기준: 미지원 capability는 명시하고, 그래프 소비자마다 서로 다른 해석을 조용히 적용하지 않는다.

### R04 — APK ZIP·민감 파일 분석 (원문 A §4)

부분 구현. ZIP 인벤토리와 assets/res/raw/res/xml의 제한된 내용 읽기, 파일 후보,
credential/JWT/private-key/일부 내부 URL 패턴과 값 마스킹이 있다.
근거: `analyzers/apk.py`, `test_application.py`.
미완료: DB·인증서·keystore 실제 내용 의미 분석, Firebase 설정·전체 사설 IP/클라우드
credential 유형의 정밀 문맥 분석. 파일 확장자 탐지를 해당 내용 분석의 완료로 세지 않는다.
기준: 지원 유형별 양성·음성 fixture, 읽기 예산/미지원 형식 표시, 원문 secret 비노출 테스트.

### R05 — Manifest와 공격 표면 (원문 A §5, §7)

부분 구현. SDK/권한/컴포넌트/alias/필터/링크 인벤토리, exported/기본 permission,
debug/backup/명시적 cleartext 설정을 다룬다. binary Manifest는 실제 JEB로 검증했다.
근거: `analyzers/manifest.py`, `test_manifest.py`, 두 사용자 APK.
중요 미완료: 리소스 참조값 해석, 설치 유효성, network security/backup/FileProvider XML의
실효 정책, provider의 세부 권한·경로, task 설정 의미 분석.
현재 `enabled` 리소스 참조는 문자열 비교 때문에 False가 될 수 있다. 이는 안전 판정이
아니지만 분석 진입점을 누락시킬 수 있으므로 UNKNOWN과 명시적 False를 구분해야 한다.

### R06 — Category 및 Finding 분류 (원문 A §6, §9–12)

모델은 검증 범위 내 충족. type/severity/confidence/verification/level, 위치·흐름·근거·
validation·standards를 분리했다. API 존재만으로 확정하지 않는다.
근거: `core/models.py`, `analyzers/context.py`, `security.py`, 데이터 흐름 테스트.
주의: AUTH/NETWORK/DEPENDENCY/PRIVACY 등의 enum이 있다는 사실은 해당 탐지기의 완료가 아니다.
CWE 일부만 매핑했고 MASVS/MASWE/MASTG 정밀 매핑은 후속 확장이다. 임의 ID를 채우지 않는다.

### R07 — Component/IPC·Deep Link 탐지 (원문 A §7–8)

부분 구현. 노출 인벤토리, 일부 외부 callback 입력, 명시적 앱 내부 activity Intent 전달을 지원한다.
키별 extra/data와 대상 클래스, 객체 별칭을 제한적으로 구분한다.
근거: `manifest.py`, `core/objectflow.py`, `test_boundaries.py`, 실제 boundary DEX fixture.
미완료: 암시적 Intent, 서비스/receiver 간 전달, PendingIntent/URI grant/provider 공격 경로,
app-link 도메인 소유권/검증, 일반적인 redirect·권한 검증 의미 분석.

### R08 — WebView (원문 A §7–8)

부분 구현. 보안 관련 API REVIEW, 일부 상수 설정, URL/HTML/JavaScript 인자별 sink,
Intent-derived 흐름과 문맥 검토를 제공한다. 안전한 인자·다른 인자 음성 테스트가 있다.
미완료: JavascriptInterface의 실제 노출/권한 문맥, TLS 오류 처리 조건,
WebViewClient callback과 검증 정책의 정밀 관계. API REVIEW를 이 분석의 대체물로 보지 않는다.

### R09 — Storage/Crypto/Network/Auth/Dynamic/Resilience (원문 A §7)

부분 구현: SQL/process/dynamic-loader 일부 sink, crypto 알고리즘 상수, 로그·반사·native-load REVIEW.
미구현: 민감 데이터의 preferences/file/cache/clipboard 흐름, key/IV/KDF/PRNG 의미 분석,
TrustManager/HostnameVerifier/TLS/auth·biometric/토큰 검증, 다운로드→코드 로딩 연결.
Resilience 부재를 근거 없이 취약점으로 만드는 동작은 하지 않는다. 구체적인 hardening
검토를 구현할 경우에도 탐지 범위/불확실성을 명시하고 일반 취약점과 분리해야 한다.
위 항목들은 원문의 제품 탐지 범위에 남아 있으며, 초기 milestone 밖으로 둔다고 삭제되지 않는다.

### R10 — Source/Sink·고급 흐름 (원문 A §8–11)

부분 구현. 레지스터 kill/move, 인자·반환·제한 필드, CFG 경로, bounded 호출,
제한 Intent/Runnable 객체, L3/L4/L5 경로를 실제 DEX와 synthetic fixture에서 확인했다.
미완료: 일반 객체/배열/컨테이너, 정밀 dispatch, 광범위 입력 source,
sanitizer 의미/accepting branch/같은 값의 동일성 증명, 검증에 따른 안전한 path pruning.
`verification.py`의 dominance/도달성은 구조 분석이며 sanitizer 증명이 아니다.
초기 미완성은 원문에서도 허용하지만, 지원 모델과 누락 원인은 정확히 공개해야 한다.

### R11 — Rule Engine (원문 A §13)

검증 범위 내 충족: YAML source/transfer/sink와 Python 규칙 확장, 스키마·중복 일부 검사,
규칙 fingerprint. 원문의 모든 required_conditions/validation 선언을 범용 실행하는
DSL을 제공하는 것은 아니다. 추가 detector는 지원 조건과 오탐 회귀 쌍을 갖춰야 한다.

### R12 — GUI와 증거 검증 동선 (원문 A §14–16)

부분 구현. dark QML, resize, 가상 목록, 검색/심각도 필터, 상세·코드·bytecode·AST·
XREF/CFG/Call Graph 데이터·Data Flow·Review·Boundaries 및 메모를 제공한다.
근거: `gui/qml/Main.qml`, `gui/controllers/workspace.py`, `test_gui.py`.
핵심 미완료: 경로/XREF 단계 클릭→정확한 메서드/DEX 오프셋, caller/callee 이동,
탐색 이력, 코드 내 검색·줄 번호·finding/source/sink 마커, 탐색 가능한 DEX 트리.
현재 CFG/Call Graph는 주로 데이터 표시이며 완전한 그래프 UI가 아니다.
light 테마/dock 분리/장식적 UI는 핵심 증거 탐색보다 후순위다.

### R13 — 성능·작업 관리 (원문 A §17–18)

부분 구현 및 검증. worker, 단계/진행률, 취소, 캐시, 지연 decompile,
NDJSON 본문 전송, 복사 없는 저장, 목록/그래프 출력 상한이 있다.
두 사용자 APK와 실제 취소·재시작을 검증했지만 파일 크기는 약 6.4MB/11.2MB다.
17 DEX 시험을 100MB 이상 대용량/장시간 성능 보장으로 표현하지 않는다.
GUI의 일부 로컬 XREF/그래프 검색은 결과를 자르기 전에 전체 모델을 동기 순회한다.
세밀한 증분 갱신·GIL/이벤트 루프 지연·대형 검색 및 반복 실행 메모리 검증은 미완료다.

### R14 — 저장·보고서 (원문 A §19–20)

초기 요구 범위 내 충족: 프로젝트/정규화 모델/Finding/메모 JSON 저장·재열기,
원자적 교체, 구형 선택 필드 기본값, 지원하지 않는 schema 거부.
미완료: 엄격한 외부 입력 스키마/크기 검증, migration 정책, 배포용 호환성 테스트.
HTML/CSV는 원문에서 향후 기능이며 초기 GUI 단계에서는 JSON만으로도 허용한다.
프로젝트 파일에는 민감 원본 코드가 남을 수 있으므로 마스킹된 배포용 보고서와 구분한다.

### R15 — 테스트·개발 기록·제품 목적 (원문 A §21–25)

검증 범위 내 충족: 단위/통합/JEB/규칙/흐름/GUI 테스트와 재현 문서, backend abstraction,
불확실성 공개 및 DEX를 근거로 삼는 구조. 프로젝트는 단순 API grep만으로 끝나지 않는다.
미검증: 설치 가능한 signed APK fixture, 독립 정답 기반 오탐/누락 평가,
장시간 실행·비정상 종료·클린 설치·지원 환경 매트릭스·사용자 수동 인수.
패키지 wheel 빌드 성공을 이 항목들의 완료로 대체하지 않는다.

## 먼저 처리할 정확도·일관성 항목

다음은 코드에서 확인한 개선 필요점이며, 후속 구현 상태를 함께 기록한다.

- P0-A: Manifest의 미해결 enabled/권한/리소스와 명시적 비활성 상태를 구분한다.
  미확인 값이 분석 제외 또는 안전성 근거로 조용히 사용되지 않아야 한다.
  후속 구현: tri-state와 미확정 진입점 분리 및 회귀 검증 완료. 리소스 실제 평가와
  provider의 연산별 권한 해석은 남아 있다.
- P0-B: `external_entries`, 후보 reviewer, GUI/backend 호출 조회의 선언/상속 해석을
  공통 계약으로 맞춘다. 후속 구현: 흐름 분석/reviewer는 공통 entry_catalog로 상속,
  override와 본문 없는 선언을 처리한다. GUI/backend DEX 호출 조회도 엔진의 공통
  DeclarationResolver를 사용하도록 연결했다. lifecycle/일반 선언의 본문 없는 override와
  구형 메타데이터도 동일한 중단 정책으로 통합하고 교차 회귀를 검증했다. 이는 runtime
  dispatch나 인터페이스 default method 해석의 완성을 의미하지 않는다.
  원본/해석된 참조는 구분해 보존한다.
- P0-C: 사용자 제공 설정/프로젝트의 잘못된 스키마·값·크기 입력에 대한 실패 정책을
  명확히 하고, 기존 프로젝트/메모와 GUI 세션이 손상되지 않는지 검사한다.
  후속 구현: 외부 JSON/모델 타입 및 설정 범위 검증, 크기·깊이 제한, GUI 재열기
  실패 시 결과/선택/메모 보존, 설정 저장 실패 rollback, 파일 원자적 교체 실패 보존을
  검증했다. 확장 메타데이터의 모든 의미 검증이나 프로세스 메모리 상한은 포함하지 않는다.

## 제안하는 단계별 완료선

### M1 — 보수적이고 일관된 분석 기반

대상: P0-A/B/C. 상태: 미완료.
완료 기준: 명시 true/false/리소스/미해결 값, 상속/override/alias/권한,
잘못된 입력을 포함한 양성·음성 회귀를 통과한다. 불확실성 때문에 경로를 포함하더라도
신뢰도를 낮추고, 누락/제한을 기록한다. GUI·엔진·reviewer에서 서로 모순되는 진입점을
조용히 표시하지 않는다. 두 사용자 APK 비교와 기존 111개 회귀 기준을 유지한다.

### M2 — 분석가가 근거를 따라갈 수 있는 초기 릴리스

대상: M1 + R12의 핵심 탐색 동선, R13의 해당 동선 비동기화. 상태: 미완료.
후속 구현: flow/attack path/Finding→정확한 DEX offset, 정규화된 XREF/call graph의
caller/선언 callee 클릭과 DEX 위치 이력, 프로젝트 재열기 후 위치 재현을 추가했다.
조회는 worker에서 취소 가능하고 300개 edge 상한/잘림을 표시한다. 원본 JEB 참조도
실제 unit/offset/operand 검증을 통과한 항목만 클릭하도록 연결했다. JEB XREF GUI
페이지 이동과 실패/취소 시 상태 보존도 추가했다. 전체 트리·소스 줄 매핑과 일반적인 UI 성능 인수는 남아 있다.
완료 기준: Finding→flow step→bytecode 오프셋→실제 caller/callee를 왕복하고,
프로젝트 재열기 후에도 동일 위치에 도달한다. 존재하지 않거나 다른 unit의 위치는
명시적으로 거부한다. 페이지/검색 상한과 작업 취소가 유지되며 GUI 이벤트 루프 지연을
측정한다. source 위치 매핑이 없을 때 임의 줄 번호를 만들지 않는다.

### M3 — 검증 로직의 제한된 의미 분석

대상: R10의 최소 sanitizer 모델. 상태: 미완료.
후속 구현: 동일 메서드의 Uri.parse→getScheme/getHost→String.equals 상수 비교와
허용 분기·sink 인자 identity를 모든 열거된 정상 경로에서 확인하는 검토 모델을 추가했다.
MODELED_EXACT_MATCH는 제한된 문자열 제약이며 안전성 판정이 아니다. 예외 완전성,
파서 동등성·redirect 등이 미검증이므로 자동 suppression은 하지 않는다.
후속 확장: 정확한 static `(String)boolean` helper의 공통 true-return 제약을 최대 2단계
전달한다. 추가로 JEB try 범위·handler와 정상 successor를 분리해 보수적인 예외 CFG를
탐색한다. 지원 fixture에서 false 반환/종료 catch는 제약을 유지하고 true 반환/sink 우회
catch는 UNKNOWN이다. 범위 정보가 없거나 불완전한 경우는 거부하며 전체 예외 의미나
파서 동등성을 증명하지 않으므로 suppression은 여전히 하지 않는다.
완료 기준: 지원 대상으로 정한 정확한 scheme/host 검사에 대해 같은 입력값의 비교,
허용 branch, sink 지배 관계를 모두 입증한 경우만 제한된 안전 경로 처리를 한다.
검사 후 재대입, 거꾸로 된 조건, 우회 branch, 접두어 위장, 다른 객체 검사, 예외 흐름을
음성 fixture로 포함한다. 증명할 수 없으면 UNKNOWN을 유지하며 단순 문자열 검사로 억제하지 않는다.

### M4 — 구성 정책과 추가 detector

대상: Network Security Config / FileProvider / backup 리소스 해석부터 시작해 R07–R09 확장.
상태: 미완료. 각 detector마다 지원 환경/조건, 양성·음성 fixture, evidence와 제한을
등록한다. category별 API 이름 발견만으로 해당 detector의 인수를 완료하지 않는다.

### M5 — 배포·성능 인수

상태: 미검증. 위 milestone과 별도로 클린 환경 설치, JEB 누락/오류 안내,
작업 중 종료/재시작, 대용량·장시간 실행, 프로젝트 round trip, 수동 GUI 검증을 수행한다.
지연/메모리 예산은 대상 하드웨어와 지원 APK 규모를 정한 뒤 측정 가능한 수치로 합의한다.
이번 단계에서 검증하지 않은 시간·메모리 SLA나 릴리스 날짜를 약속하지 않는다.

## 다음 구현 작업

**M1의 Manifest 미해결 값과 흐름 분석/reviewer 상속 callback 일관성**을 보강했다.
P0-C의 잘못된 설정/프로젝트 입력 처리와 기존 데이터 보존 회귀도 추가했다.
M2의 초기 증거 위치 탐색과 DEX 호출 조회 일관성을 보강했고 lifecycle/일반 선언의
본문 없는 override와 구형 메타데이터 처리도 공통화했다. 원본 JEB XREF의 검증된 DEX
참조 클릭과 M3의 첫 단계인 정상 흐름 scheme/host 정확 비교 검토를 추가했다.
static boolean helper와 예외 CFG의 양성·우회 fixture를 추가했고 두 실제 APK를 재분석했다.
새 검증 근거의 GUI 요약과 비교·분기·handler 위치 탐색도 추가했다. JEB XREF의 GUI
페이지 이동과 페이지 변경/취소 시 상태 보존 검증을 완료했다. 이어서 M2의
DEX 클래스/메서드 탐색을 추가했다. 클래스→메서드의 2단계 패널, worker 검색과 300개
페이지, Finding 비의존 코드 조회를 제공한다. 80,000개 합성 메서드의 조회 상한과 취소를
검증했으며 일반적인 대형 APK UI 성능 인수를 완료한 것은 아니다. unit/package/field
탐색 범위와 복수 unit 출처 표시를 추가했고 다른 unit 본문 대체를 거부한다. 필드의
실제 읽기/쓰기 operand 참조를 검증된 DEX 위치로 연결했고 필드 참조의 페이지 이동과
읽기/쓰기 필터도 추가했다. 두 대형 저장 프로젝트의 필드 검색/취소/UI 타이머를 측정하고
offset 검증 및 JSON 화면 배치를 개선했다. 알려진 caller unit의 클릭 가능한 링크 300개와
프로젝트 로딩의 UI 응답·메모리도 독립 프로세스에서 측정했다. 중복 버퍼/DTO 보유를 줄여
로딩 피크 메모리를 개선했지만 큰 프로젝트의 약 388ms UI 타이머 간격은 남아 있다.
프로젝트 로딩 중 협력적 취소와 늦은 로딩 결과 적용 방지도 추가했다. 두 대형 프로젝트를
교차하여 4회 취소/4회 재열기를 검증했고 이전 모델을 보유하던 콜백/백엔드 참조를 정리했다.
명시적 GC 후 과거 result/program은 사라졌지만 RSS 잔류와 최대 약 1.5초 UI 지연은 남는다.
wheel 기반 독립 가상환경 설치·CLI/GUI smoke·실제 JEB fixture 분석/재열기를 검증했다.
같은 Windows 호스트의 Python 3.14.2 결과이며 새 OS 클린 설치나 지원 버전 전체 검증은 아니다.
상세 재현 절차는 WHEEL_INSTALLATION.md를 참고한다.
배포 환경의 잘못된 설정·JEB/Java 경로 등 8개 실패 처리와 기존 파일 보존을 검증했다.
GUI에서 JEB 연결 실패 후 설정 수정·재연결과 기존 분석 세션 보존을 검증했다.
재연결 후 원본 APK 누락·변경 시 live 조회 차단과 저장 근거·메모 보존을 검증했다.
대형 원본 해싱의 청크별 취소를 추가하고 128MiB 합성 파일로 응답과 중복 읽기 비용을 측정했다.
후속으로 live 검증을 backend 공개 함수에 모아 GUI 요청당 해싱을 한 번으로 줄였다.
캐시 반환과 직접 호출도 검증하고 다음 요청은 재해싱한다. 분석 시작 단계의 이중 해싱은 남는다.
Network Security Config의 명명된 텍스트 XML cleartext 상속 목록과 미해결 진단을 추가했다.
JEB의 compiled XML 및 기본 리소스 테이블 숫자 ID→ZIP 경로 연결을 실제 APK에서 검증했다.
기본 구성 한계를 유지한 호스트별 가장 구체적인 cleartext 도메인 정책 선택 및 CLI 조회를 추가했다.
저장된 네트워크 정책의 GUI host 조회와 근거 파일 경로/정규화 정책 표시를 추가했다.
Network Security Config의 trust anchors/debug overrides 목록, 상속과 불확실성 분석을 추가했다.
pin-set의 알고리즘/값/만료일 목록과 기준일·미확정 조건 분석을 추가했다.
CA의 명명된 raw 경로 후보 및 PEM/DER 형식 검사와 JEB 숫자 raw ID의 기본 구성 연결을 추가했다.
명명된 raw 참조를 선택적 aapt2 설정·CLI·GUI 자동 분석에서 JEB와 교차 확인한다.
대용량 amoremall 전체 분석은 메모리 감시로 두 차례 인덱싱 중 취소됐으며 완료/저장 검증은 미완료다.
JEB 힙 설정과 실패 분류를 추가했다. 2GiB 힙 재시험은 합산 약 2.38GiB에서 120초 시간 guard로 취소됐다.
장시간 시험은 내보내기 약 428MB까지 진행했지만 334초에 시스템 여유 메모리 guard로 취소됐다.
메서드 내보내기 예산·부분 결과 진단을 추가했다. amoremall은 8MiB에서 내보내기를 멈췄지만
JEB OOM으로 메서드 없이 기본 APK 부분 보고서만 저장했다. 단계 계측으로 artifact open 직후
힙 약 93%, 선언 18만 개까지의 진행을 확인했고 응답 직렬화 시작은 관측하지 못했다.
선언 인덱스 예산을 추가했고 종류별 1,000개 제한에서 amoremall 본문 959개가 포함된
부분 프로젝트 저장/재열기에 성공했다. 전체 분석 완료는 아니다. GUI의 저장 범위·제외 수와
검색 공백 안내 및 누락 본문 탐색 보존을 검증했다. 선택적 Manifest/package 우선 수집을
unit 내부에 구현했고 amoremall 본문 1,000개 부분 분석·저장·재열기를 검증했다.
GUI 정책 선택/요청·유효 정책 표시와 기존 결과 보존을 구현했다. 후속으로 종류별 전역
unit 우선순위를 구현하고 합성 다중 unit 및 실제 Jython fixture에서 검증했다.
실제 다중 unit 성능, 호출 대상 확보, alias, 기기별 구성,
인증서 체인/런타임 TLS 검증은 별도 미완료다.
저장된 정확한 invoke 대상의 본문 누락/출처 모호성 계측과 GUI 요약/상세는 구현했다
(`CALL_TARGET_COVERAGE.md`). 이 통계는 런타임 대상 해석이나 자동 본문 확보가 아니다.
후속으로 분류별 호출 위치 페이지와 검증된 호출자 이동을 추가했다(`CALL_TARGET_BROWSER.md`).
단일 직접 호출 대상의 읽기 전용 JEB 후보 조회·예산 검증도 추가했다
(`CALL_TARGET_CANDIDATE.md`). GUI 독립 미리보기도 연결했다(`GUI_CALL_CANDIDATE.md`).
후보 독립 내보내기/출처 보존/전용 검증 로더를 추가했다(`CANDIDATE_EXPORT.md`).
후보 GUI 재열기/출처 비교, 실제 JEB 재검증을 거친 단일 후보의 제한 확장/재분석과
HTML/CSV/정규화 DEX JSON 내보내기를 추가했다(`CANDIDATE_EXPANSION_AND_REPORTS.md`).
일반 자동 확장이나 고유 JEB optimizer IR 추출은 미구현이다.
이름→ID→기본 경로 교차 확인은 구현됐지만 기기별 구성/alias 해석은 별도 미완료 항목이다.
전반적인 GUI 성능
인수나 메모리 상한 보장을 완료한 것은 아니다.
catch가 있다는 사실만으로
안전하다고 판단하지 않는다.
M2의 남은 트리/소스 위치 탐색 기능과 M1의 resource/provider 의미 분석 한계는 별도로 남아 있다.
이 순서는 분석 누락을 먼저 줄이고 사용자가 근거를 검증할 수 있게 한 뒤 의미 분석을
확장하려는 제안이다. 원래 전체 제품 목표가 모두 끝났다는 선언은 별도 인수 전에는 하지 않는다.

후속 구현 검증: 전체 127개 회귀와 사용자 APK 2개 재분석. 결과는
`build/real-apk-tests-entrypoints`에 별도 저장했으며 이전 분석 결과는 보존했다.
입력 검증 보강 후 전체 173개 회귀와 위 두 프로젝트 재열기 호환성 검증도 통과했다.
이번 입력 검증 단계에서는 APK 보안 분석을 새로 실행한 것이 아니라 기존 저장 결과를
새 로더로 읽었으며, 기존 분석 결과 파일을 수정하지 않았다.
증거 탐색 보강 후 전체 182개 회귀와 두 실제 저장 프로젝트의 위치 왕복 검증을 통과했다.
공통 선언 해석기 후속 검증은 전체 191개 회귀와 사용자 APK 2개 실제 재분석이다.
`build/real-apk-tests-declarations`에 별도 저장했으며 유형/분석 수준별 개수는 유지됐다.
JEB XREF 클릭 보강 후 전체 203개 회귀와 MyAcademy의 실제 JEB XREF 재조회도 통과했다.
URL guard 검토 후 전체 216개 회귀를 통과했고 실제 JEB DEX fixture에서 양성/접두어/
재대입 음성을 확인했다. MyAcademy 저장 프로젝트의 기존 L4 후보는 새 검토에서도 UNKNOWN이다.
helper/예외 테이블 보강 후 전체 230개 회귀와 MyAcademy 실제 재분석을 통과했다.
제한적 예외 CFG 후 전체 241개 회귀와 두 APK 실제 재분석을 완료했다.
GUI Review 탐색 후 전체 248개 회귀, QML 렌더링 및 MyAcademy 저장 프로젝트 재검토를
통과했다. 저장된 판정이나 메모는 바꾸지 않았다.
JEB XREF 페이지 이동 후 전체 259개 회귀를 통과했다. 실제 JEB fixture 왕복 조회 및
603개 합성 참조의 경계·실패·취소·늦은 응답 검증이며, 사용자 APK의 새 전체 재분석은 아니다.
DEX 탐색 후 전체 265개 회귀를 통과했다. Finding이 없는 상태의 AST/XREF/디컴파일을
실제 JEB fixture에서 검증했고, 저장 Finding/메모 보존과 본문 없는 위치 거부를 확인했다.
출처 탐색 확장 후 269개 회귀를 통과했다. 신규 인덱스 저장/재열기, 구형 기본값,
unit 범위 내 검색/페이지/필드 표시 및 다른 unit 본문 대체 거부를 검증했다.
필드 참조 연결 후 306개 회귀를 통과했다. 실제 fixture의 READ/WRITE와 위치 이동,
Unknown unit 비링크 정책, 취소/오래된 응답, 고유 오프셋과 300개 상한을 검증했다.
필드 페이지/필터 후 316개 회귀를 통과했다. 603개 참조의 마지막 페이지, 필터별 총 개수,
빈 결과, 오류·취소·늦은 취소·오래된 응답 시 이전 결과 보존과 실제 JEB 왕복을 확인했다.
필드 검색 성능 보강 후 323개 회귀를 통과했다. 사용자 저장 프로젝트 각 3회의 ALL 조회
중앙값은 약 244→119ms, 362→178ms였다. 상세 범위와 취소 전달 지연은 REAL_APK_VALIDATION에 기록했다.
로딩 메모리 개선 후 327개 회귀를 통과했다. owned DTO 소비 전 전체 검증, 기존 입력
보존, 메서드 순서, Unicode/프로젝트 왕복 및 독립 프로세스 QML 측정 회귀를 추가했다.
로딩 취소 후 339개 회귀를 통과했다. 단계별 취소·오류·반영 직전 취소·오래된 응답,
기존 화면/세션/메모 보존과 취소 후 정상 재시도를 검증했다. native decoder 및
할당된 큰 모델 해제 중에는 즉시 중단을 보장하지 않는다.
반복 세션 참조 정리 후 전체 345개 회귀를 통과했다. 작업 성공/실패/취소의 captured model
해제, callback 재진입, 이전 backend program 교체 및 작은 독립 반복 도구 실행을 포함한다.
