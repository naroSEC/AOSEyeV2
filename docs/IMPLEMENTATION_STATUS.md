# 구현 및 검증 기록

## 2026-10-12 민감정보 저장 문맥 우선 구현

민감정보 finding의 SQLite bindString→같은 statement/슬롯의 execute 호출 연결과
openFileOutput 반환→byte[] write의 내부 파일 요청 문맥을 추가했다. 다른 receiver,
같은 슬롯 덮어쓰기, clearBindings, 알 수 없는 호출/인덱스, 예외/분기/본문 및 슬롯 예산을
보수적으로 처리한다. 실제 저장·트랜잭션 성공·암호화·타 앱 접근은 UNKNOWN으로 유지한다.
상세 지원 API와 미지원 항목은 SENSITIVE_FLOW.md를 참조한다.

최종 전체 회귀 **2366 passed / 163.33초**, 실패/skip 0. 실제 JEB fixture에서
SQL 실행/초기화, 내부 파일/다른 stream의 4개 민감 경로와 연결 여부를 구분했다.
단위 시험은 결과 저장 왕복, 값 비노출, 취소 및 128개 슬롯 예산을 포함한다.
독립 설치 **14개 모두 exit 0**:
`C:\validation-temp\aoseye-wheel-tjcxrina\validation.json`.
wheel SHA-256: `e64de1e81ebd25c317baffde493791617a3caf5982f856750d0de000d80ee599`.
`build/release-regression.xml`은 이 wheel hash에 연결된 결과다.

사용자 APK 두 개의 이전 같은 날짜 검증은 아래 component 묶음 기준이다. 이번 저장
문맥으로 실제 사용자 APK를 다시 분석한 결과로 혼용하지 않는다. 이번 작업은 민감정보
전체 미구현 범위 또는 제품 출시 완료가 아니며 ContentValues/cache/external 경로,
암호화 저장소 및 SDK 고유 source 등은 남아 있다.

## 2026-10-12 component / 객체 참조 / WebView bridge / 인증 / 규칙 묶음

- 명시적 service·receiver 전달, Intent 복사, package/class setClassName 연결을 추가했다.
  상대 클래스명 자동 확장 및 다른 패키지의 같은 클래스 연결을 하지 않는다.
- 추적 객체의 참조 필드로 캡처된 Intent→Runnable 흐름을 지원한다. 외부 호출에 넘긴
  객체와 그 참조 그래프는 보수적으로 무효화하며 일반 heap 완성을 의미하지 않는다.
- 같은 WebView의 JavaScript bridge 등록/해제와 외부 입력 로딩을 연결했다.
  실제 노출 메서드/iframe/런타임 실행은 미확정이다.
- Signature.verify 반환값 무시와 정상 경로 상수 true 반환을 REVIEW로 추가했다.
- 규칙 argument_bits 조건의 32비트 마스크, 입력 타입/범위와 UNKNOWN 처리를 추가했다.

최종 소스의 전체 회귀 **2250 passed / 147.09초**, skip/실패 0. 실제 JEB 및 새 DEX
fixture, GUI, 프로젝트 저장 왕복을 포함한다. 독립 설치 검사 **14개 모두 exit 0**:
`C:\validation-temp\aoseye-wheel-w1x8wybb\validation.json`.
wheel SHA-256: `fa8e9f00565d99e122f5f253ed2592e2248689a7302948dcc39bfd06fff791be`.
`build/release-regression.xml`은 이 wheel hash를 suite 이름으로 기록했다.
그 이전 중간 2238개 결과는 마지막 package 수정 전이므로 최종 증거로 사용하지 않는다.

release gate의 자동 소스/라이선스 파일/회귀/설치 증거 대조는 통과했다. 미승인 template을
사용한 전체 상태는 BLOCKED이며 6개 소유자 인수 항목과 hash 결합이 남는다. template을
자동 승인하거나 공개 배포하지 않았다. 원 요청 전체 완료와 별개이며 남은 구현은
COMPLETION_PLAN.md를 따른다.

실제 사용자 APK 두 개도 별도 출력 `build/real-apk-20261012-components`에서 재검증했다.
본문 14,536개/12,952개, 증거 조회 오류 0, 프로젝트 저장 성공, bridge 정상 종료를 확인했다.
둘 다 complete=False인 부분 분석이다. 대형 APK는 메모리 여유 부족으로 재실행하지 않았다.
설정과 시간/메모리 측정은 REAL_APK_VALIDATION.md에 기록했다.

## 2026-10-12 기능 묶음 통합 검증 재개 완료

가용 메모리 3,508,477,952 bytes 확인 후 이전에 중단된 동일 코드의 전체 회귀를
재개했다. **2161 passed / 142.38초**, 실제 JEB/Jython/GUI 및 Base64 fixture 포함.
같은 wheel의 독립 가상환경 검사 **14개 모두 exit 0**:
`C:\validation-temp\aoseye-wheel-6snue07p\validation.json`.
wheel SHA-256: `daf49263fb72942bb90045c6e72430f0370ad21181765e6ca8d135d5001ed5fe`.
`build/release-regression.xml`도 이 hash에 연결된 새 2161개 결과로 갱신됐다.
이전 중단 기록은 아래에 역사적 기록으로 보존한다. 이번 재실행은 새 PC/실제 대형 APK
검증이나 수동 인수를 대신하지 않으며 미구현 전체 완료를 의미하지 않는다.


## 2026-10-11 미구현 기능 묶음 확장 — 전체 통합 재검증 보류

변경 대상 단위/애플리케이션 회귀 **152 passed / 4.93초**.
추가 내용: 동일 WebView 설정→외부 입력 로딩 연결, 동일 Editor putString→apply/commit,
다중 TrustManager 배열→SSLContext.init, Android Base64 유래 암호 재료 연결,
IPv6 로컬 주소 분류, INI/dotenv/properties/conf의 같은 section AWS 키 쌍 분석.

WebView enabled/disabled/다른 객체, Editor apply, 다중 TrustManager 변경은 실제
JEB DEX fixture 시험 **1 passed / 10.77초**에서 확인했다. 그 뒤 추가된 Base64
DEX fixture는 전체 통합 실행이 중단되어 아직 실제 JEB 검증 완료로 세지 않는다.
단위 시험의 Base64 양성·음성은 통과했다. 전체 제품 완성을 뜻하지 않는다.

전체 JEB 회귀를 한 번 실행했으나 시스템 가용 메모리 **240,906,240 bytes** 관측으로
테스트를 중단했다. 명령행 hash로 확인한 이 실행의 pytest PID 60348 및 해당 자식
CoreRunner JVM PID 62584만 종료했다. 다른 프로그램/APK/보고서/사용자 설정은 건드리지
않았다. 종료 뒤 가용 메모리는 **1,153,781,760 bytes**였다. 전체 테스트와 독립 설치의
JVM 검증을 반복하지 않았다. 기존 2102 passed 결과를 이번 변경의 근거로 재사용하지 않는다.

현재 wheel SHA-256: `daf49263fb72942bb90045c6e72430f0370ad21181765e6ca8d135d5001ed5fe`.
빌드는 성공했지만 최신 전체 회귀/독립 wheel 설치 검증은 미완료다.
release-regression.xml 및 이전 validation.json은 이전 wheel용이며 출시 승인 근거가 아니다.
메모리 확보 후 새 전체 회귀, Base64 포함 JEB fixture, 독립 설치를 수행해야 한다.
원 요청의 인증·인가/IPC/규칙/함수 간 문맥 및 나머지 검증 backlog는 유지한다.


## 2026-10-11 MIT 오픈소스 배포 준비 / 사용자 지정 JEB 경로

최종 전체 회귀 **2102 passed / 159.08초**. AOSEYE_RUN_JEB=1과 사용자가 지정한
AOSEYE_JEB_PATH/aapt2 경로로 실제 JEB/Jython/GUI 통합까지 실행했다.
wheel SHA-256: `caa16f46614a964d62d18a884176428b55bed95f9c575b7ba3a2ecbf38088257`.
JUnit: `build/release-regression.xml`, suite 이름에 이 wheel hash를 결합했다.
독립 wheel 설치의 **14개 검사 모두 exit 0**:
`C:\validation-temp\aoseye-wheel-h_7q_cpu\validation.json`.

- 사용자 선택에 따라 MIT LICENSE, SPDX 패키지 메타데이터 및 고지 파일을 추가했다.
  JEB/제3자 의존성을 MIT로 재허가하거나 재배포하지 않는다.
- JEB 기본 경로는 비어 있다. 사용자 GUI/CLI/환경 변수 지정과 기존 저장 경로만 사용한다.
  미설정 시 GUI는 경로 안내를 표시하고 backend는 Java 실행 전에 명확한 오류를 반환한다.
  현재 작업 폴더나 홈 폴더를 JEB 설치로 오인하지 않는다.
- wheel 소스/리소스/라이선스와 회귀/설치 증거를 대조하는 release gate를 추가했다.
  승인은 담당자·근거·대상 hash가 필요하며 template은 미승인 그대로 보존했다.
- sdist 경계 검사와 공격적 경로/링크/비허용 파일 회귀를 추가했다. 사용자 APK, 실제 분석
  보고서, JEB/JAR/DEX 및 가상환경은 소스 배포에 포함하지 않는다. 문서 내부의 역사적
  로컬 경로/앱 이름까지 익명화한 것은 아니므로 공개 전 내용 검토는 필요하다.
- sdist에서 wheel을 다시 빌드했으며 원 wheel과 모든 ZIP 멤버의 내용이 동일했다.
  ZIP 컨테이너 hash의 동일성이나 재현 가능한 전체 배포 인증을 주장하지 않는다.
- 보안/기여/제3자 안내와 공개 패키지 소개를 추가했다. 의존성 관측은
  DEPENDENCY_VALIDATION.md에 기록했으며 취약점/법률 검토 완료가 아니다.

release gate는 자동 증거 불일치 없이 **BLOCKED**를 반환했다. 미승인 항목은 요구사항 범위,
대화형 GUI, 새 PC, 실제 APK/제한, 제3자 조건 및 배포/지원이다. MIT 선택만으로 이를
자동 승인하지 않았다. 원 요청의 8개 미완료 기능군은 COMPLETION_PLAN.md에 유지했다.
대형 APK 재실행에 부족한 가용 메모리가 관측되어 보호 기준을 낮추거나 다른 프로세스를
종료하지 않았다. 공개 저장소 생성/업로드/릴리스 태그/서명은 수행하지 않았다.


## 2026-10-10 TrustManager 배열 / 공개 인증서 자산

전체 회귀 **2070 passed / 129.85초** (`AOSEYE_RUN_JEB=1`, 실제 JEB/Jython/GUI 포함).
TrustManager 대상 18개(JEB 포함), 자산/애플리케이션/배열 회귀 69개 및 독립 설치 14개 통과.
wheel SHA-256: `f44539f0683315da581b6d77dcb9d17234bbd9131aaa4d823f4f933011b01545`.
설치 보고서: `C:\validation-temp\aoseye-wheel-l42_lb06\validation.json`.

- AOS-TLS-006: 빈 checkServerTrusted가 확인된 새 객체→단일 TrustManager 배열→SSLContext.init.
  new-array/aput-object 및 filled-new-array, 별칭/덮어쓰기/미확정 인덱스·타입·호출을 검증했다.
  실제 JEB의 installTrust 양성과 installSafeTrust 음성을 확인했다. 초기화 성공/socket 사용은 UNKNOWN.
- AOS-ASSET-006: 공개 PEM/DER 인증서의 파싱 성공을 INFORMATION으로 구분한다.
  기존 제한형 파서의 1MiB/64개 예산을 사용한다. 잘못된 입력은 진단하며 혼합 파일의 private-key
  텍스트 후보는 유지한다. 인증서 체인/유효성/신뢰 용도 또는 keystore 암호 해독은 구현하지 않았다.
- 저장 왕복, 취소, 파서 예산, 다른 인자/안전 callback 음성을 확인했다.

검증 종료 후 시스템 가용 메모리 **3,829,248,000 bytes**를 관측했다. 기존 대형 APK의
4GiB/3GiB 실행은 1GiB 가용 메모리 보호 기준으로 중단됐으므로, 이번에는 반복 실행하지 않았다.
대형 APK 재검증/사용자 인수 및 나머지 분석 backlog는 여전히 미완료다.
상세 범위는 TLS_CONTEXT.md, ASSET_CONFIG.md, COMPLETION_PLAN.md에 반영했다.

## 2026-10-10 TLS setter 연결 / 생체 인증 콜백 문맥

전체 회귀 **2046 passed / 134.40초** (`AOSEYE_RUN_JEB=1`, 실제 JEB/Jython/GUI 포함).
두 신규 탐지기 대상 31개(JEB 포함), 독립 wheel 설치 검증 14개 통과.
wheel SHA-256: `28bbb398dfa5727d6d6240b5be3d1649d007027f940a2e811a7183f96a8df499`.
설치 보고서: `C:\validation-temp\aoseye-wheel-zq3amdbd\validation.json`.

- AOS-TLS-004/005: permissive callback 본문과 새 객체/기본 생성자/플랫폼 setter 인자를 연결.
  실제 JEB에서 HttpsURLConnection instance/default 및 WebView 양성 3건을 확인했다.
  별칭, 다른 인자, 초기화 누락, 일반/넓은 레지스터 덮어쓰기, 미확정 호출·예외 등을 검증했다.
  L3/WEAKNESS/MANUAL_REVIEW이며 실제 setter 성공/유지/네트워크 사용은 미확정이다.
- AOS-AUTH-001: 플랫폼/AndroidX BiometricPrompt 실패·오류 callback에서 자신의 로컬
  success(null)를 직접 호출하는 직선 본문. 실제 JEB 플랫폼 양성 2건, 일반 클래스와 거부 음성.
  L2/REVIEW/MANUAL_REVIEW이며 UI 처리 또는 null 거부일 수 있으므로 인증 우회를 확정하지 않는다.
- 신규 결과의 DEX 위치/관련 메서드, 취소, 프로젝트 저장 왕복을 확인했다.

상세: TLS_CONTEXT.md, BIOMETRIC_CONTEXT.md. TrustManager 배열/함수 간 설치,
생체 인증 CryptoObject/보호 동작/서버 권한, 기타 미구현 항목은 COMPLETION_PLAN.md에 남아 있다.
대형 APK의 메모리 제한 재검증과 사용자 인수도 이번 fixture/설치 통과로 대체하지 않는다.

## 2026-10-10 문맥 규칙 / 다운로드 기록 URI 흐름

전체 회귀 **2016 passed / 129.70초** (`AOSEYE_RUN_JEB=1`, 실제 JEB/Jython/GUI 포함).
대상 테스트 57개(JEB 포함), 독립 wheel 설치 검증 14개 통과.
wheel SHA-256: `96fe6017576194ef198396d5aab7f85f99b8c3795d851c6900e460326fddfcad`.
설치 보고서: `C:\validation-temp\aoseye-wheel-oz9lu4qg\validation.json`.

- RuleRegistry의 root/source/transfer/sink 필드와 타입/enum/CWE/인자 검증을 강화했다.
  중복 YAML 키와 alias를 거부하고 바이트/깊이/노드 예산을 제한했다.
- required_conditions의 source_prefix/argument_constant를 추가했다. MET/NOT_MET/UNKNOWN을
  구분하고 미확정은 REVIEW/MANUAL_REVIEW로 유지한다. fingerprint와 관측 통계에 반영한다.
- DownloadManager 기록 URI→DexClassLoader/PathClassLoader code-path 인자 흐름을 별도 패스로
  추가했다. 문맥 DSL을 사용하며 기존 분석들과 전체 단계 예산을 공유한다.
- 실제 JEB에서 직접/함수 간 양성 2건과 다른 인자/덮어쓰기 음성을 검증했다.
  다운로드 성공, 파일 경로 유효성, 무결성 검증, 코드 실행은 입증하지 않는다.
- 파서 악성 입력, 취소, 예산 소진, 다른 출처, 미확정 변환, 저장 왕복을 검증했다.

상세: RULE_CONDITIONS.md, DOWNLOAD_FLOW.md. 최신 대형 APK 검증은 아래 메모리 제한 때문에
여전히 미완료다. 인증 결과/토큰 검증, 콜백 설치, 추가 IPC 및 사용자 인수 등 전체 backlog의
완료를 의미하지 않는다. 기존 APK·사용자 설정·과거 보고서를 삭제하거나 수정하지 않았다.

## 2026-10-09~10 구성 자산 분류 / TLS interface 연결

전체 회귀 **1975 passed / 134.66초** (`AOSEYE_RUN_JEB=1`, 실제 JEB/Jython/GUI 포함).
대상 테스트 88개(JEB 포함), 독립 wheel 설치 검증 14개 통과.
wheel SHA-256: `f6d9cb4ccd03f6b9a7e092ba101e45d2609d4616530ef22eeed2937711798112`.
설치 보고서: `C:\validation-temp\aoseye-wheel-cfdivrfb\validation.json`.

- Firebase 클라이언트 공개 구성과 서비스 계정 private key 후보를 구분한다.
  AWS ID/secret 쌍, RFC1918 IPv4/개발 URL 문맥, 규칙별 탐지 잘림 표시를 추가했다.
- JSON 바이트/깊이/중복 키 제한, 취소, 값 마스킹을 검증했다. 외부 인증 요청은 없다.
- JEB interface 선언을 기존 예산 안에서 수집하고 Program에 저장한다.
  TLS 검증 메서드의 실제 interface 조상 확인을 signature-only 후보와 구분한다.
  callback 설치/실행 가능성은 여전히 미확정이다. 기존 프로젝트와 저장 왕복도 검증했다.
- MyAcademy/amospro 최신 재검증과 증거 조회·저장은 완료했지만 complete=False다.
- 대형 amoremall은 힙 4GiB/3GiB 모두 시스템 가용 메모리 1GiB 보호 기준으로 취소됐다.
  최신 대형 APK 검증은 미완료이며 이전 성공 기록으로 대체하지 않는다.

상세 범위: ASSET_CONFIG.md, TLS_CONTEXT.md, REAL_APK_VALIDATION.md.
전체 기능 완료가 아니다. 콜백 설치, 추가 민감 source/저장 문맥, IPC/인증·인가,
문맥 DSL 및 인수 항목은 COMPLETION_PLAN.md에 남아 있다.

## 2026-10-09 PendingIntent 목적지 변경·복사

전체 회귀 **1921 passed / 147.82초** (`AOSEYE_RUN_JEB=1`). 대상 40개(JEB 포함) 통과.
새 wheel의 독립 설치 검증 **14개 통과**. 이전 디스크 부족으로 남은 검증 제한을 최신 빌드에서 해소했다.
작업 시작 시 C: 여유 53,317,271,552 bytes를 확인했으며 이번 작업에서 기존 파일을 삭제하지 않았다.
wheel SHA-256: `93c0eba203331fe9e3cbfb5838368a6624e88514784b28cb6f268a4239f7a9f7`.
설치 보고서: `C:\validation-temp\aoseye-wheel-uyrh3dc9\validation.json`.

- Intent 복사 생성자의 component/package 상태를 원본과 독립적으로 추적한다.
- setClass 및 setClassName 두 오버로드의 확인된 클래스/이름 인자를 지원한다.
- setComponent(null)은 component만 해제하고 package 제한은 유지한다.
- 미확정 이름/ComponentName/복사 원본을 암시적 Intent로 추정하지 않는다.
- 실제 JEB에서 명시적 대상 해제 양성, 암시적 복사 후 원본 제한의 복사본 양성,
  명시적 복사 후 원본 대상 해제의 복사본 음성을 검증했다. 저장/재열기도 통과했다.

상세 한계는 `PENDING_INTENT.md`에 기록했다. 실제 IPC 전달/권한/외부 접근이나 전체 backlog를
완료했다는 의미는 아니다. 아래 설치 실패 기록은 당시 관측으로 보존한다.

## 2026-10-09 PendingIntent 문맥

전체 회귀 **1908 passed / 138.20초** (`AOSEYE_RUN_JEB=1`). 대상 27개(JEB 포함) 통과.
mutable/unconstrained Intent 및 충돌 플래그를 REVIEW로 분류하며 explicit/package/immutable,
별칭·재대입·미확정 변경·SDK 제약을 구분한다. 상세 범위는 `PENDING_INTENT.md`.
wheel 생성 완료: SHA-256 `5e5de3b53519b7891ef548a1e750ec6e338a054c408ca974fd750895bc257d79`.

독립 설치 검증은 **미완료**: pip 설치 단계에서 `[Errno 28] No space left on device` 발생.
관측 C: 여유 236,654,592 bytes. 실패 보고서/로그는
`C:\validation-temp\aoseye-wheel-w61d5io0`에 보존했다.
해당 실행이 만든 실패한 venv만 정리하려 했으나 도구 정책으로 명령이 거부되어 삭제하지 않았다.
디스크 여유 확보 후 독립 설치 검증을 다시 수행해야 한다. 이전 14개 통과 기록을 이번 wheel의
검증 결과로 간주하지 않는다. 사용자 APK와 기존 분석 결과는 변경하지 않았다.

## 2026-10-09 고정 키·IV·salt 소비자 연결

전체 회귀 **1882 passed / 198.63초** (`AOSEYE_RUN_JEB=1`, 실제 JEB/Jython/GUI 포함).
소비자 연결 대상 19개(JEB 포함), IV CWE 매핑 조정 후 단위 18개 및 독립 설치 14개 통과.
wheel SHA-256: `2be6bed27c652b4f7f8941e174b02337a11da96ff2e4df83dba5e1fc2bfdb85a`.
설치 보고서: `C:\validation-temp\aoseye-wheel-hzmlyo_s\validation.json`.

- 고정 문자열 bytes→SecretKeySpec→Cipher.init key 인자 연결(AOS-CRYPTO-005).
- 고정 문자열 bytes→IV/GCM spec→암호화 Cipher.init parameter 인자 연결(AOS-CRYPTO-006).
- 고정 문자열 bytes→PBEKeySpec salt→SecretKeyFactory.generateSecret 연결(AOS-CRYPTO-007).
- 실제 JEB에서 키/IV/salt 양성 각 1건 및 동적 배열/미사용 객체 음성을 확인했다.
  별칭, 덮어쓰기, 복사 전후 원본 변경, 모드, 잘못된 호출 형식과 블록 경계도 회귀로 검증했다.
- 값 대신 DEX 출처/생성자/소비자 위치만 Finding에 기록한다. 원본 프로젝트 데이터 삭제는 아니다.
- REVIEW/MANUAL_REVIEW/L3이며 생성 성공/실행 가능성/알고리즘 적합성을 확정하지 않는다.
  함수 간 추적, 배열 리터럴/decoder 및 알고리즘별 IV 정책은 미지원이다(`CRYPTO_MATERIAL.md`).

이 단계는 전체 backlog의 완료가 아니다. 나머지 IPC, 인증·인가, 문맥 규칙 및 인수 항목은
`COMPLETION_PLAN.md`에 미완료 상태로 유지했다.

## 2026-10-09 암호 파라미터 문맥

전체 회귀 **1864 passed / 190.06초** (`AOSEYE_RUN_JEB=1`, 실제 JEB/Jython/GUI 포함).
대상 테스트 80개 및 독립 wheel 설치 검증 14개도 통과했다.
wheel SHA-256: `67638d16789f23b807b3fc347ff16596038f41f4587948c5c55bf6440c032ced`.
설치 보고서: `C:\validation-temp\aoseye-wheel-6vs_83xn\validation.json`.

- PBEKeySpec/PBEParameterSpec 생성자의 iterationCount=1을 검토 대상으로 표시한다.
- GCMParameterSpec의 32/64비트 인증 태그를 프로토콜 문맥 검토 대상으로 표시한다.
- 정확한 생성자/인자/호출 형식과 블록 내 상수를 사용한다. 미확정 덮어쓰기와 블록·분기 경계를 검증했다.
- 실제 JEB fixture에서 양성 5개 및 정상·미확정 인자 음성을 확인하고 프로젝트 저장/재열기를 통과했다.
- 결과는 REVIEW/MANUAL_REVIEW다. 객체 생성 성공이나 암호 연산 사용을 증명하지 않는다.
  키/IV/salt 객체 추적, SecretKeyFactory/Cipher.init 연결은 여전히 후속 구현 대상이다.

상세 범위와 공식 API 근거는 `CRYPTO_PARAMETERS.md`를 참조한다. 원 요청 전체 완료는 아니다.

## 2026-10-09 민감정보 source-to-argument 흐름

전체 회귀 **1792 passed / 207.91초** (`AOSEYE_RUN_JEB=1`, 실제 JEB/Jython/GUI 포함).
독립 wheel 설치 검증 **14개 통과**.
wheel SHA-256: `1e2c46aa55e3102b945e57475e854bcd25fc260175eaac70ffb6cd125fdcd56e`.
설치 보고서: `C:\validation-temp\aoseye-wheel-g9o1h4r7\validation.json`.

- AccountManager 인증 토큰/비밀번호 반환 3종을 기존 외부 입력 source와 분리했다.
- Log/println, Preferences value, SQLite bind value, Writer/OutputStream,
  Clipboard text 인자 흐름 6개 규칙을 추가했다. REVIEW/MANUAL_REVIEW로만 표시한다.
- 문자열 인코딩, helper 인자·반환과 기존 bounded 객체 모델을 재사용한다.
  Intent 입력, 다른 인자, 덮어쓰기와 알 수 없는 변환은 구분한다.
- 두 분석의 steps 합이 max_flow_steps 안에 있도록 민감정보 분석은 남은 예산만 사용한다.
  credential source 없는 ICC/async 루트는 추가 탐색하지 않는다.
- 실제 JEB fixture에서 8개 양성 경로(6개 규칙)와 음성, helper L4 및 저장 왕복을 확인했다.
- 이전 저장 모델 MyAcademy 11,768개/amospro 12,952개 본문에 새 분석만 재적용했다.
  해당 저장 범위에서는 credential source root 및 finding이 0이었다. APK 새 전체 분석이 아니다.
  선언 해석 진단은 각각 663/647개로 불완전한 기존 인덱스의 한계를 유지한다.

정확한 지원 범위/미지원 인자/실제 저장 여부 제한은 `SENSITIVE_FLOW.md`를 참조한다.
토큰의 실시간 유효성, commit/apply/execute, 저장 경로/암호화, cache/external storage와
SDK 고유 비동기 인증 응답 등은 미구현이다. 전체 요청 완료 선언이 아니다.

## 2026-10-08 기능군 통합 보강

전체 회귀 **1768 passed / 125.52초** (`AOSEYE_RUN_JEB=1`, 실제 JEB/Jython/GUI 포함).
TLS 위치를 실제 proceed 명령으로 연결하는 조정 후 대상 38개도 통과했다.
wheel SHA-256: `ac9356464a56baed912c40e18eb0043729512be5b4f8c8afc2059f194f18bcc1`.
독립 wheel 설치 **14개 확인 통과**. 보고서:
`C:\validation-temp\aoseye-wheel-_3vo7lb7\validation.json`.
후속 검증 도구의 evidence 실패 상태 수정 후 해당 테스트 **13개 통과**(신규 2개 포함).
도구 전용 변경 이후 전체 회귀를 다시 실행한 수치로 합산하지 않았다.
83.8MB APK는 4GiB JVM/manifest-first/선언 5,000개/본문 16MiB 한도에서
2,886개 본문과 두 메서드의 디컴파일·AST·XREF를 확인했다. 분석 22.063초/전체 30.373초.
2GiB에서는 증거 조회 중 JEB 메모리 부족이 관측되었다. 전체 코드 분석 완료는 아니다.
근거는 `build/large-apk-20261008-heap4096/amoremall/summary.json` 및 `REAL_APK_VALIDATION.md`.

남은 작업/완료 기준은 `COMPLETION_PLAN.md`에 8개 기능군으로 정리했다. 원 요청 전체는 미완료다.
세부 연산을 무한히 늘리지 않고 보안 탐지와 실제 APK 분석 범위를 우선한다.

- TLS callback DEX 패턴 3종과 안전/불완전 입력 음성 및 실제 JEB fixture를 추가했다(`TLS_CONTEXT.md`).
- 상수 문맥 분석에서 defs 없는 move/move-result가 오래된 약한 알고리즘 값을 유지하는 문제를 수정했다.
- SQLite 자산의 credential 이름 열에 대한 제한적 표본/마스킹 검사를 추가했다(`SQLITE_ASSETS.md`).
- secret regex의 전체 matches 목록 생성 대신 최대 20개만 소비하여 메모리 낭비를 줄였다.
- JEB class/field metadata는 전체 선언 byte 예산의 절반까지만 사용하게 변경했다.
  나머지는 method 선언에 사용 가능하며 전체 예산/누락 진단/partial 정책은 그대로 유지한다.
  bridge 스크립트 hash가 캐시에 포함되므로 이전 인덱스를 새 정책 결과로 재사용하지 않는다.
- 실제 amospro_dev6에서 기존 기본 8MiB 선언 예산으로 본문 0개였으나 수정 후 12,952개를 얻었다.
  수정 후 분석 15.233초, `complete=False`. 전체 앱 분석 또는 취약점 완전 탐지를 의미하지 않는다.
  근거: `build/real-apk-20261008-tls/2-amospro_dev6/summary.json` 및
  `build/real-apk-20261008-budget/2-amospro_dev6/summary.json`. 기존 결과는 보존했다.

이하 정수 곱셈 단계의 테스트 수/패키지 해시는 이전 시점 기록이다.

2026-10-08 정수 곱셈 지원 후 전체 테스트: **1725 passed** (`AOSEYE_RUN_JEB=1`, 125.42초).
일반 테스트 1706개와 실제 JEB/Jython/GUI 통합 19개를 포함한다.
mul-int 및 /2addr, /lit8, /lit16의 signed 상수 곱셈과 32비트 오버플로를 지원한다.
부호/0/경계, 오래된 목적지 제거, defs 누락, 미확정 원본 trace와 계산 후 배열 할당을 검증했다.
실제 JEB tripleSize의 mul-int/lit8(3) 결과로 배열을 할당하고 마지막 슬롯 입력 흐름을 확인했다.
나눗셈/나머지/비트 연산과 long/float/double은 미지원이다(`INTEGER_FLOW.md`).
add-int/sub-int 및 각각의 /2addr 형식에서 두 상수 연산과 32비트 오버플로를 지원한다.
목적지 중복/defs 누락, 오래된 값 제거, 미확정 원본과 대표 외부 입력 trace 보존을 검증했다.
실제 JEB query의 sub-int/2addr가 마지막 배열 인덱스를 계산하고 입력 슬롯을 읽는 흐름을 확인했다.
나눗셈 및 분기 증명은 미지원이다(`INTEGER_FLOW.md`).
add-int/lit8 및 add-int/lit16의 signed 상수 계산과 32비트 오버플로를 지원한다.
목적지 오래된 값 제거, 동일 레지스터, defs 누락, 미확정 입력 trace의 불확실성 보존을 검증했다.
실제 JEB lastIndex 보조 메서드의 array-length→add-int/lit8(-1)과 마지막 슬롯 입력 흐름을 확인했다.
덧셈·뺄셈·곱셈 외 산술과 분기 증명은 미지원이다(`INTEGER_FLOW.md`).
확인된 String[]/Object[]의 길이를 정수 상수로 전달하며 원소 입력 trace와 구분한다.
목적지 stale trace/참조/상수 제거, 동일 레지스터, defs 누락, 후속 배열 할당과 실패를 검증했다.
실제 JEB의 arraySize 보조 메서드에 array-length가 존재하고 반환 길이가 fill 종료 인자로 전달됨을 확인했다.
일반 정수 산술/분기 증명이나 외부 배열 길이 추정은 미지원이다(`ARRAY_FLOW.md`).
알려진 인덱스의 aput-object는 해당 위치의 이전 wildcard를 제거하고 다른 슬롯만 불확실하게 보존한다.
안전 값/새 입력 교체, 모든 슬롯 덮어쓰기, 후속 미확정 쓰기의 재전파, 별칭/경로 분리를 검증했다.
수정 전 8개 실패를 재현했고 수정 후 대상 49개 및 전체 회귀가 통과했다.
실제 JEB에서 미확정 쓰기 후 안전 문자열/null 단일 슬롯 덮어쓰기 음성을 확인했다(`ARRAY_FLOW.md`).
목적지 wildcard가 복사된 구간에 남던 문제를 수정했다. 구간 밖에만 불확실한 기존 trace를 보존한다.
원본 wildcard/겹치는 복사의 사전 상태, 길이 0 무변경과 길이 한도 검증을 유지·보강했다.
수정 전 새 회귀 13개 실패를 재현했고 수정 후 대상 26개 및 전체 회귀가 통과했다.
실제 JEB에서 미확정 인덱스 쓰기 후 부분/전체 안전 복사의 덮어쓴 위치 음성을 확인했다(`ARRAY_FLOW.md`).
정확한 Object[]의 4인자 fill에서 확인된 [from,to) 구간만 교체하고 바깥 슬롯을 유지한다.
빈/경계/전체/부분 구간, wildcard의 선택적 제거와 외부 슬롯 불확실성, 별칭/실패를 검증했다.
실제 JEB query에서 구간 입력 양성과 종료 위치 음성, 구간 밖/빈 구간 보존 및 null 덮어쓰기를 확인했다.
미확정/잘못된 범위는 진단한다. 저장 타입 제약 배열과 중첩 identity는 미지원이다(`ARRAY_FLOW.md`).
정확한 Object[]의 2인자 fill 정적 호출 및 /range에서 모든 슬롯 trace를 교체한다.
전체 덮어쓰기/wildcard 제거, 빈 배열, 불확실성, 별칭/경로 분리와 미확정/형식/예산 실패를 검증했다.
실제 JEB query에서 입력 fill 양성과 안전 문자열/null 덮어쓰기 후 음성을 확인했다.
String[]의 저장 타입 검사와 중첩 identity는 미지원이다(`ARRAY_FLOW.md`).
확인된 ArrayList에 String[]/Object[] 슬롯을 순서대로 추가하는 정적 호출 및 /range를 지원한다.
prefix 보존, 빈 배열 무변경/상수 반환, 원본 변경 독립성, 불확실성과 wildcard를 검증했다.
실제 JEB query에서 배열 추가 후 원본 덮어쓰기에도 입력 유지 및 안전 슬롯/prefix 음성을 확인했다.
미확정 내용/길이/형식/예산은 진단한다. 다른 Collection, 기본형/다차원 배열과 중첩 identity는 미지원이다(`LIST_FLOW.md`).
확인된 ArrayList 간 copy 정적 호출 및 /range에서 앞부분 복사와 목적지 꼬리/크기 보존을 지원한다.
빈 원본/자기 복사, 안전 슬롯 덮어쓰기, 불확실성, 별칭/경로 분리와 원본 변경 독립성을 검증했다.
실제 JEB query에서 복사 후 원본 clear에도 입력이 유지되고 안전 원본 재복사 후 제거됨을 확인했다.
크기 부족/미확정 내용/형식/예산 실패는 진단한다. 다른 List와 subList 뷰/중첩 identity는 미지원이다(`LIST_FLOW.md`).
확인된 ArrayList의 fill 정적 호출 및 /range에서 크기를 유지하며 모든 슬롯 trace를 교체한다.
빈 리스트 무삽입, 입력/안전 값 덮어쓰기, 불확실성, 별칭/경로 분리와 미확정/예산 실패를 검증했다.
실제 JEB query에서 fill 입력 흐름과 안전 문자열/null 덮어쓰기 후 음성을 확인했다.
중첩 객체 채우기는 비어 있지 않은 리스트 내용을 무효화하고 진단한다. 다른 List와 중첩 identity는 미지원이다(`LIST_FLOW.md`).
확인된 ArrayList와 상수 Java int 이동량에서 rotate 정적 호출 및 /range를 지원한다.
양수/음수/길이 초과/정수 경계 이동, 무변경, 원상 복구, 별칭/경로 분리/불확실성을 검증했다.
실제 JEB query에서 +4 이동의 입력 0→1 양성과 안전 위치 음성, -4 복구 후 Iterator 흐름을 확인했다.
미확정 내용/이동량과 잘못된 형식/예산은 진단하며 다른 List 및 subList 뷰는 미지원이다(`LIST_FLOW.md`).
확인된 ArrayList의 reverse 정적 호출 및 /range에서 위치별 trace와 불확실성을 역순으로 이동한다.
빈/단일 원소·중앙 값 보존, 두 번 뒤집기, 별칭/경로 분리와 미확정/형식/예산 실패를 검증했다.
실제 JEB query에서 입력 0→2 이동 양성과 안전 값 위치 음성, 원상 복구 후 Iterator 흐름을 확인했다.
다른 List 구현체는 지원하지 않으며 변경 전 반복자는 기존 snapshot 정책에 따라 미해결 처리한다(`LIST_FLOW.md`).
확인된 ArrayList의 두 상수 위치 교환과 trace/불확실성 이동, 별칭/경로 분리를 지원한다.
같은 유효 위치는 그대로 유지하며 미확정/잘못된 위치·내용·형식·예산 초과는 진단한다.
실제 JEB query에서 이동한 입력 양성 및 안전 값 위치 음성과 재교환 후 Iterator 흐름을 검증했다.
기존 반복자는 snapshot 정책상 보수적으로 미해결 처리한다. 일반 List/동시성 모델은 아니다(`LIST_FLOW.md`).
replace는 기존 키만 교체하고 이전 값 trace를 반환하며 없는 키에는 삽입하지 않는다.
직접/Map 및 /range 호출, trace 없는 기존 매핑, 별칭/경로 분리/불확실성과 미확정 상태를 검증했다.
실제 JEB에서 이전 값의 입력 흐름 및 교체 후 안전 값/없는 키 조회 음성을 확인했다.
putAll 덮어쓰기 회귀 입력을 분리한 최종 fixture도 별도 JEB 시험 1개를 재통과했다.
3인자 조건부 replace와 일반 객체 값 비교는 미지원이다(`MAP_FLOW.md`).
용량 지정 생성자의 빈 맵 초기화와 clone의 별도 identity/항목 사전/불확실성 복사를 지원한다.
실제 JEB에서 두 호출과 복제 후 원본 clear의 입력 흐름 유지 및 기존 음성을 확인했다.
미확정/음수 용량, 복제 예산/미확정 내용은 진단한다. 깊은 복사나 실제 메모리 할당 성공 증명은 아니다(`MAP_FLOW.md`).
putAll 및 Map 복사 생성자의 충돌 키 덮어쓰기/trace 복사/별칭/원본 수정 독립성을 지원한다.
실제 JEB에서 복사 생성자→putAll 흐름과 안전 값 덮어쓰기 음성을 확인했다.
합집합 키 한도, 미확정 내용/원본, 자기 복사 및 다른 구현체는 진단한다(`MAP_FLOW.md`).
getOrDefault/containsKey/size/isEmpty를 지원하며 없는 키와 trace 없는 기존 매핑을 구분한다.
실제 JEB에서 기본값 입력 흐름, 안전/null 매핑의 기본값 음성 및 조회 후 원본 흐름 유지를 확인했다.
미해결 키/내용은 기본값이나 false/0으로 단정하지 않는다. 정밀 분기 증명은 아니다(`MAP_FLOW.md`).
확인된 HashMap의 무인자 생성자 및 문자열 상수 키 put/get/remove/clear를 직접/Map 호출에서 지원한다.
키별 덮어쓰기/이전 값 반환/별칭/호출 불확실성 및 객체·항목 한도를 검증했다.
실제 JEB Provider update에서 최초 get 입력 흐름과 덮어쓰기/remove/clear 음성을 확인했다.
다른 구현체, null/객체 키, 중첩 객체, Map 뷰/고급 연산 및 Set은 미지원이다(`MAP_FLOW.md`).
Iterator.remove의 마지막 반환 위치/단일 삭제 권한, 원소 이동과 커서 갱신을 모델링한다.
실제 JEB에서 삭제 후 원본 get과 다음 next의 음성을 확인했다. 순서 위반/중복 삭제/다른 반복자 무효화를 DTO로 검증했다.
iterator/hasNext/next의 원소 순서와 경로별 커서를 추적하며 별칭/독립 반복자 및 종료를 검증했다.
실제 JEB에서 Iterable.iterator→Iterator.next의 입력 흐름과 안전한 둘째 원소 음성을 확인했다.
원본 변경/미해결/예산/미지원 연산은 진단한다. forEachRemaining/ListIterator 및 긴 반복문 전체 분석은 미지원이다(`LIST_FLOW.md`).
clone의 별도 identity/슬롯 trace와 size/isEmpty의 알려진 상수 반환을 지원한다.
실제 JEB에서 복제 후 원본 clear, 크기 조회 후 흐름 유지와 안전 슬롯 음성을 검증했다.
깊은 객체 복사나 분기 정밀 판정은 아니며 미해결 내용/예산 초과를 진단한다(`LIST_FLOW.md`).
ArrayList(int)의 용량과 논리적 크기를 구분하고 확인된 ArrayList에서 Collection 복사 생성자로 trace를 전달한다.
실제 JEB에서 두 생성자 호출, 원본 clear 후 복사본 입력 흐름 및 안전 슬롯/clear 음성을 검증했다.
미확정 용량/원본, 다른 구현체, 자기 복사, 예산 초과는 진단하며 실제 메모리 예약 성공을 보장하지 않는다(`LIST_FLOW.md`).
확인된 ArrayList 간 addAll(Collection)/addAll(int,Collection)의 순서별 trace 복사와 위치 이동을 지원한다.
직접/List 호출 및 Collection의 인덱스 없는 호출을 지원하며, 자기 추가/미확정 원본/예산 초과는 진단한다.
실제 JEB Provider query에서 두 연속 addAll의 입력 흐름, 원본 clear 후 독립성 및 안전 슬롯/목적지 clear 음성을 확인했다(`LIST_FLOW.md`).
toArray(T[])의 런타임 Object[] 인자에 한해 배열 재사용/별도 할당, null 종료 슬롯 및 꼬리 보존을 지원한다.
실제 JEB에서 Collection/List 호출의 재사용·할당 흐름과 null/안전 꼬리 슬롯 음성을 확인했다.
미확정 호출은 목적지 배열의 이전 내용을 무효화한다. String[] 등 타입 제약 배열은 미지원이다(`LIST_FLOW.md`).
확인된 ArrayList의 무인자 toArray()를 직접/List/Collection 호출에서 지원한다.
새 Object[] identity와 순서별 trace/불확실성을 기존 배열 모델에 연결하고 배열 예산을 공유한다.
실제 JEB에서 리스트 변경 후 배열 스냅샷 흐름 유지와 배열 변경 후 리스트 흐름 유지,
안전한 배열 원소 덮어쓰기 음성을 검증했다. IntFunction 오버로드와 중첩 객체는 미지원이다(`LIST_FLOW.md`).
add(int,Object)/remove(int)의 원소 위치 이동과 삭제 반환 trace를 추가했다.
확인된 ArrayList 객체의 직접/List 인터페이스 호출만 적용하며 미확정 변경은 내용을 무효화한다.
실제 JEB에서 삽입/삭제 이동 증거와 remove 반환값 흐름 및 set/clear 후 음성을 검증했다.
remove(Object)의 값 비교, 일반 컬렉션 및 다른 구현체는 여전히 지원하지 않는다(`LIST_FLOW.md`).
직접 생성한 ArrayList의 add/get/set/clear, 별칭 및 앱 내부 호출 전달을 모델링한다.
set 이전 값 반환과 가상 호출 불확실성을 유지하며, 미지원 연산/인덱스와 예산 초과는 진단한다.
실제 Provider openFile DEX에서 최초 get 흐름과 set/clear 후 음성을 JEB로 검증했다.
후속으로 확인된 ArrayList 객체의 List add/get/set/clear 및 Collection add/clear 인터페이스 호출을 지원한다.
실제 Provider call DEX의 invoke-interface와 입력 흐름/덮어쓰기/clear 음성을 JEB로 검증했다.
미확정 구현체, 잘못된 opcode/인자 및 미지원 메서드는 진단한다. 일반 컬렉션 모델은 아니며
범위와 한도는 `LIST_FLOW.md`에 기록했다.
참조 배열 3인자 copyOfRange의 위치 이동/잘림/null 확장과 범위 검사를 추가했다.
실제 Provider call DEX의 from=1 복사 및 추가 null 슬롯 음성을 JEB로 검증했다(`ARRAY_FLOW.md`).
참조 배열 2인자 copyOf의 새 identity, 잘림 및 null 확장 슬롯을 지원한다. wildcard가
확장 슬롯으로 전파되지 않음을 확인하고 실제 JEB의 입력 슬롯/추가 슬롯을 교차 검증했다(`ARRAY_FLOW.md`).
알려진 String[]/Object[] clone의 새 identity와 독립 슬롯을 모델링한다. 원본/복제본 덮어쓰기,
불확실성/예산과 실제 JEB clone→sink를 검증했다. 일반 객체/깊은 복사는 아니다(`ARRAY_FLOW.md`).
동일 참조 배열 타입과 확인된 범위의 System.arraycopy를 지원한다. 겹친 복사는 사전 상태로
처리하며 미해결 목적지 내용은 무효화/진단한다. 실제 JEB query 경로에서도 확인했다(`ARRAY_FLOW.md`).
filled-new-array 및 /range의 슬롯별 초기 trace와 move-result-object 배열 identity를 지원한다.
일반 및 /range 명령을 실제 Provider DEX/JEB로 검증했다(`ARRAY_FLOW.md`).
상수 길이 String[]/Object[]의 원소 저장/읽기, 별칭, 슬롯 덮어쓰기와 호출 전달을 추가했다.
미확정 인덱스는 POTENTIAL이며 지원 한도/형식 실패는 진단한다(`ARRAY_FLOW.md`).
Provider 실제 DEX fixture의 query도 배열을 거쳐 sink로 전달하도록 바꾸어 JEB로 검증했다.
JDK/D8/aapt2로 생성한 Provider APK 3종에서 실제 JEB의 연산별 권한 분리, 불확실성,
sink 오프셋, Review 데이터 및 프로젝트 왕복을 검증했다(`PROVIDER_ACCESS.md`).
최신 제품 wheel은 배열 및 제한된 ArrayList 흐름 구현을 포함한다.
Provider의 구성 불확실 사유를 entry catalog, 흐름 라벨, Reviewer 및 저장 결과에 전달했다.
합성 파이프라인에서 POTENTIAL 유지/확정 attack_path 부재와 저장 왕복을 확인했다.
Review 표시 데이터 확인을 추가한 대상 테스트 7개도 별도 통과했다(`PROVIDER_ACCESS.md`).
읽기/쓰기 권한 중 하나가 있다는 이유로 Provider 전체 진입점을 제외하던 처리를 수정했다.
경로별 권한, openFile 및 call은 불확실 진입점으로 구분한다(`PROVIDER_ACCESS.md`).
정책 식별자 갱신 후 application/Provider 대상 테스트 21개도 별도로 통과했다.
제공된 APK 3개에는 백업 XML 참조가 없어, 컴파일된 로컬 재현 APK로 전체 분석 경로,
이름/숫자 ID 결과 일치와 프로젝트 왕복을 검증했다. 잘못된 legacy/modern 섹션 혼합을
거부하도록 파서를 보강했다. 실제 OS 백업/복원 검증은 아니다(`STORAGE_CONFIGURATION.md`).
추가 수동 실제 APK 검증에서 amoremall의 FileProvider 참조 2개를 선택적 aapt2 이름→ID와
JEB 기본 XML 구성으로 해석했다. 넓은 경로 3개는 REVIEW이며 실제 노출 증명은 아니다.
이전 UNKNOWN 증거와 원본 프로젝트는 보존했다(`STORAGE_CONFIGURATION.md`).
FileProvider/백업 선언 인벤토리와 Storage Policy 화면, 손상 XML/ZIP UNKNOWN 처리 및
대용량 IR 출력의 UTF-8 바이트 누적 제한을 추가했다(`STORAGE_CONFIGURATION.md`).
amoremall 부분 결과의 4,951개 본문을 포함한 33MB IR 출력/재읽기를 확인했다.
최신 wheel의 별도 가상환경 설치·JEB 분석·보고서 출력 검증 14항목도 통과했다.
패키지 SHA-256: `61631a07cdcafe6ec791ec231d3511ad3da523b2624986c7b0c588ce383be5c9`.
설치 검증 기록: `C:/validation-temp/aoseye-wheel-6qg0gk2c/validation.json`.
unit 내부 Manifest/package 힌트 우선 수집과 정책별 캐시 격리·오류 폴백을 추가했다.
amoremall 선언 종류별 1,000개 조건에서 Manifest 일치 클래스 109개와 본문 1,000개를
부분 저장/재열기했다. 전체 분석 완료가 아니며 범위는 `INDEX_PRIORITY.md`에 있다.
후속 GUI 정책 선택 및 요청/유효 정책 표시를 구현했다(`GUI_INDEX_POLICY.md`).
후속으로 종류별 unit 간 전역 선택을 구현했다(`GLOBAL_INDEX_PRIORITY.md`).
저장된 호출 대상 본문의 누락/모호성 계측과 GUI 요약/상세 표시를 추가했다
(`CALL_TARGET_COVERAGE.md`). 누락 위치 필터/페이지/호출자 이동을 추가했다
(`CALL_TARGET_BROWSER.md`). 단일 직접 호출 대상의 읽기 전용 JEB 조회·예산 계약을 검증했다
(`CALL_TARGET_CANDIDATE.md`). GUI 독립 미리보기와 실패/취소 시 기존 근거 보존도 연결했다
(`GUI_CALL_CANDIDATE.md`). 후보 독립 내보내기/출처 보존과 전용 검증 로더도 구현했다
(`CANDIDATE_EXPORT.md`). 후보 GUI 재열기·출처 비교와 원본/JEB 재검증 후 명시적 제한 확장을
구현했다. HTML/CSV/정규화 DEX JSON 내보내기도 추가했다(`CANDIDATE_EXPANSION_AND_REPORTS.md`).
자동 재귀 확장이나 앱 전체 분석 완료를 의미하지 않는다.
설치된 JEB 5.47에서
실제 초기화·DEX·CFG·XREF·디컴파일·AST와 GUI worker 연동을 검증했다.
명명된 텍스트 XML의 cleartext 상속 분석과 미해결 리소스 진단을 추가했다.
컴파일 XML/숫자 리소스 ID의 기본 구성 해석을 실제 APK에서 검증했고
`NETWORK_SECURITY_CONFIG.md`에 범위를 기록했다. 기기별 구성 및 alias 해석은 미완료다.
호스트 최장 도메인/점 경계 매칭과 저장 프로젝트 CLI 조회를 추가했다.
Network Policy GUI 메뉴에서 오프라인 host 조회와 저장 정책/근거 파일 경로 확인을 지원한다.
trust anchors/debug overrides의 선언·상속·조건부 적용을 저장/표시한다.
pin-set의 상속·알고리즘·값·중복 및 만료일을 검사하고 저장된 기준일로 조회한다.
명명된 raw CA 경로 후보에 PEM/DER X.509 형식 검사를 추가했다. 숫자 ID는 JEB 기본 구성으로 연결하며 alias는 미완료다.
명명된 raw 이름→ID→JEB 연결을 선택적 aapt2 설정·CLI·GUI로 연결했다. 미설정 시 기존 경로 후보 검사 유지,
설정된 도구 실패 시 UNKNOWN으로 남긴다. 대용량 APK의 전체 자동 분석·성능 검증은 다음 단계다.
새 cryptography 의존성을 포함한 wheel의 독립 가상환경 설치·GUI·JEB·재열기 10개 검증을 통과했다.
CA 실제 내용·체인·핀과 인증서의 일치 및 런타임 TLS 검증을 완료한 것은 아니다.
추가 사용자 APK amoremall(약 83.8MB)의 전체 분석을 두 번 시도했지만 메모리 감시로
JEB 인덱싱 중 취소됐다. 두 JVM 모두 정리됐고 원본 SHA-256은 유지됐다. 프로젝트 저장/재열기는
미완료이며 수치와 한계는 `REAL_APK_VALIDATION.md`에 기록했다. 검증 도구에 자원 감시와 실패 보고서를 추가했다.
후속 2GiB 힙 재시험은 합산 RSS 약 2.38GiB에서 120초 시간 guard로 취소됐다.
전체 완료는 여전히 미검증이며 GUI/CLI 힙 설정과 OOM 보고/원인 불명 종료 구분을 추가했다.
600초 한도 후속 시험에서는 메서드 스트림이 약 428MB까지 증가했으나 333.860초에 시스템
여유 메모리 guard로 취소됐다. 합산 RSS 피크는 약 2.37GiB였다. 내보내기 바이트 예산이 다음 작업이다.
후속으로 기본 64MiB 내보내기 예산을 추가했다. 8MiB 실제 시험은 파일 크기를 제한했지만
JEB OOM으로 메서드 0개의 기본 APK 부분 보고서만 저장/재열기했다. 범위는 `METHOD_EXPORT_BUDGET.md`에 있다.
단계 계측으로 artifact open 직후 약 93% 힙 점유와 선언 180,000개까지의 진행을 기록했다.
인덱스 완료/직렬화 시작은 관측되지 않았다. 수치와 추론 한계는 `JEB_PHASE_PROFILING.md`에 있다.
선언 인덱스 한도를 추가한 후 종류별 1,000개 조건에서 amoremall 본문 959개를 받아
부분 분석·저장·재열기에 성공했다. 전체 앱 분석 성공이 아니며 `DECLARATION_INDEX_BUDGET.md`에 기록했다.
저장된 범위/제외 수와 검색 공백의 의미를 GUI에 표시하고 누락 본문의 자동 탐색을 하지 않음을
확인했다. 구형 결과와 실제 부분 프로젝트 검증 범위는 `GUI_PARTIAL_COVERAGE.md`에 있다.
GUI 연결 실패/수정/재연결 후 기존 근거 화면과 메모 보존은
`GUI_BACKEND_RECOVERY.md`에 검증 범위와 재현 방법을 기록했다.
원본 APK/DEX 누락·변경 및 늦은 취소 시 기존 근거 화면 복원은
`LIVE_INPUT_GUARD.md`에 기록했다. 저장된 근거 열람/저장과 원본 복구 후 재시도를 검증했다.
1MiB 단위 해싱 취소 및 128MiB 합성 파일 측정은 `HASH_CANCELLATION.md`에 기록했다.
후속으로 live 검증을 backend 공개 함수에 모아 GUI 요청당 한 번 해싱한다.
캐시 반환도 원본을 검증하며 다음 요청과 직접 backend 호출의 검사를 생략하지 않는다.

## 1. 구조 / 모델 / 실행 환경

구현: `pyproject.toml`, `src/analyzer/core/models.py`, `app/settings.py`,
`app/jobs.py`, `app/project_manager.py`, `__main__.py`.
GUI 의존성은 core 모델과 분석기에 들어가지 않는다. Finding의 severity / confidence /
verification / type을 분리하고, JSON schema_version=1과 안정적인 Finding ID를 사용한다.
저장은 임시 파일 → flush/fsync → atomic replace 순서다.

검증: Python 3.14.2에서 editable 설치, JSON round trip, 메모 보존, 미지원 schema 거부.
추가 배포 검증: 저장소 밖의 새 가상환경에 wheel을 설치해 pip check, 설치 위치/자원,
CLI 도움말, offscreen GUI, 실제 JEB probe/inspect/fixture 분석과 보고서 재열기를 확인했다.
재현 도구는 `tools/validate_wheel_install.py`, 환경과 한계는 `WHEEL_INSTALLATION.md`에 있다.
후속 검증: `tools/validate_install_failures.py`로 설치된 wheel의 설정/경로/로그/입력 오류
8개를 확인했다. 예상 가능한 CLI 오류의 exit 2 처리, Java 명시 설정 우선순위와
실행 실패 후 세션 정리를 보강했다. 전체 351개 회귀 및 새 wheel 정상 검증도 통과했다.
전체 모델 deep copy 없는 JSON 스트리밍 저장과 실패 시 기존 파일 보존도 검증했다.
추가 구현: `core/input_validation.py`의 타입/필수 필드/알 수 없는 모델 필드 검사,
Finding enum/flow 위치/메서드 키와 offset 검증, JSON 중복 키·비정상 숫자·깊이 제한.
설정 파일은 64 KiB, 프로젝트는 512 MiB까지 읽고 저장한다. 저장 제한 초과 시
기존 파일을 교체하지 않는다. 잘못된 설정은 조용히 기본값으로 덮어쓰지 않고 오류로
중단하며, GUI 설정 저장 실패 시 메모리상의 설정도 보존한다.
잘못된 프로젝트 재열기 실패 후 기존 결과·선택·메모 유지, 직렬화/교체/크기 제한
실패 시 원본 파일과 임시 파일 정리를 회귀로 검사했다. 확장 dict의 모든 도메인 의미를
검증하는 것은 아니며 파일 크기 제한은 프로세스 메모리 상한 보장이 아니다.
남은 작업: 프로젝트 데이터 migration, 확장 메타데이터의 세부 의미 검증, 증분 로딩.

## 2. JEB 연동

구현: `backends/base.py`, `backends/jeb/backend.py`, `backends/jeb/session.py`, `backends/jeb/scripts/`.
설치된 JEB의 `javap`와 동봉 API 문서로 instruction / method / CFG / register range
형식을 확인했다. Core API를 사용하는 독립 Jython 클라이언트이며, 상용 타입은 bridge에만 있다.
설치 경로를 명시해 Core와 Engines를 초기화하며, 장기 실행 JVM과 프로젝트를 재사용한다.
타임아웃, 취소, 캐시, Java AST DTO와 JEB 원본 XREF, 디컴파일 지연 실행을 제공한다.

원인 및 정정: 이전 인자 없는 `getInstance()`가 낸 `JEB is not permitted to run`을
실행 환경의 제한으로 해석했으나, `getInstance(File(jebHome))`로 정상 초기화됐다.
현재 구현은 이 경로를 사용한다. CLI 스크립트 런처의 지원 여부와 무관한 Custom Client다.

실제 검증: 생성한 fixture APK/DEX에서 Core/Engines, unit/class/method/field index,
바이트코드 def/use, 분기 CFG, invoke-range, method/field XREF와 페이지 조회,
decompiler text, Java AST source unit/호출 노드/물리 오프셋을 확인했다.
onCreate에서 Navigation.open으로 향하는 DEX 오프셋 20이 JEB XREF의 `+14h`, AST 호출
노드 offset 20과 일치한다. 원본 DEX 기반 엔진이 L5를 생성하며 safe() 경로는 배제한다.
같은 PID/프로젝트를 유지한 여러 요청, 입력 변경 시 project_generation 증가,
명시적 정상 종료, GUI 백그라운드 AST/XREF/decompile 재사용도 통합 테스트로 확인했다.
취소·타임아웃·잘못된 응답 ID에 대한 세션 폐기/재시작은 process mock 테스트로 검증했다.

추가 검증: 사용자 제공 MyAcademy(1 DEX), amospro_dev6(17 DEX)의 binary Manifest와
실제 바이트코드, CFG/AST/XREF, 프로젝트 저장을 확인했다. 메서드 NDJSON 스트리밍으로
17 DEX 앱의 JVM heap 부족을 해결했다. Jython이 표현하지 못하는 고립 surrogate는
숫자 코드포인트로 전송해 원문을 보존한다. 실제 인덱싱 취소와 재시작도 확인했다.
상세 결과와 부분 분석 범위는 `REAL_APK_VALIDATION.md`를 참고한다.
남은 작업: 더 큰 APK 성능 시험, IR export, 추가 메모리 최적화,
AST를 활용한 정밀 보안 의미 분석.

## 3. APK / 구성 / 보안 문맥

구현: `analyzers/apk.py`, `manifest.py`, `security.py`, `context.py`.
압축 파일을 디스크에 추출하지 않고 크기·압축률·총 읽기 예산을 제한한다.
외부 노출과 취약점을 구분하며, 비밀정보 후보 증거는 마스킹한다.
Manifest에서 exported 기본값·권한 상속·enabled를 고려한다.
상수 인자를 확인한 crypto/WebView 설정은 L2 근거로만 분류한다.
MD5/SHA-1의 상수 선택만 확인되고 보안 용도가 입증되지 않으면 L2 REVIEW/INFO로
유지한다. WebSettings의 일반 getter/표시 설정과 Log.isLoggable은 API 경고에서
제외하지만, 실제 로그 출력과 보안 관련 설정 호출은 REVIEW로 유지한다.

검증: ZIP 경로 탈출 비추출, 압축률 제한, 부분 실패, 권한/SDK/alias/disabled,
AES 단독 오탐 방지, ECB 문맥, 상수 덮어쓰기.
남은 작업: 전체 Android resource 해석, 리소스 참조 exported/enabled 평가, Manifest 설치
유효성 검증, network security / FileProvider / backup 구성의 의미 분석 및 추가 탐지군.

## 4. 데이터 흐름

Manifest enabled/exported/권한 리소스의 미확정 상태를 명시적 false와 구분한다.
`entry_catalog`를 흐름 분석과 후보 reviewer가 공유하고 상속 callback, 로컬 override,
본문 없는 native/abstract 선언, alias, 순환 상속을 처리한다. 미확정 진입점도 탐색하되
외부 도달성이 확정된 L5 근거로 쓰지 않는다. 후속 보강으로 `DeclarationResolver`를
lifecycle/흐름/reviewer/문맥 분석/backend/GUI가 공유한다. 본문 없는 선언은
DECLARED_NO_BODY, 구형 인덱스의 불명확한 선언은 UNKNOWN_DECLARATION으로 기록하며
두 경우 모두 상위 구현 탐색을 중단한다. 후자는 재인덱싱 진단을 남긴다. 이전 버전의
미확정 상위 lifecycle 후보 탐색도 이 정책으로 대체했다. 알려진 reference-only 항목은
상속을 계속 검사하며, 실제 indexed body가 있으면 그것을 우선한다. 생성자는 상속하지
않고 순환 상속은 중단한다. 선언 인덱스는 작업별로 한 번 구성해 전역 캐시의 오래된
상태를 피한다. 가상 dispatch/인터페이스 default method의 완전한 해석은 아니다.
리소스 실제 평가와 provider의 연산별 권한 의미 분석은 아직 남아 있다.

구현: `core/dataflow.py`, `core/rules/flows.yaml`, `core/rules/registry.py`.
CFG 경로와 호출 문맥별 레지스터 상태를 추적한다. 인자/반환/경로별 필드 전파,
덮어쓰기, 외부 lifecycle 입력, 소스·싱크 인자 위치, 경로 근거를 기록한다.
일반 branch predicate solver와 sanitizer suppression은 없다. 아래 제한적 URL guard
검토 범위 밖의 validation은 UNKNOWN으로 유지한다.
필드 alias/가상 dispatch는 신뢰도 하향, 예산 제한은 diagnostics로 공개한다.

검증: L5 긍정 사례, L4 외부 진입 미확인 사례, 레지스터 kill, 잘못된 인자,
도달 불가능 경로, 호출 문맥 분리, 반환·필드, 취소·예산.
소스 도달 가능성 기반 후보 선택과 루트별 예산을 추가했다. 오염 인자/힙이 없고
모델링된 소스에도 도달하지 않는 호출은 건너뛰어 라이브러리 탐색의 예산 독점을 줄인다.
이는 완전한 흐름 분석이 아니며 루프/호출/예산 한계는 계속 diagnostics에 기록한다.
Bundle/BaseBundle과 URI 전파는 정확한 메서드 서명 및 인자 위치를 사용한다.
조회 키만 오염된 경우 반환값을 자동 오염시키지 않는다. WebView HTML/base URL,
JavaScript 코드와 history URL/callback 인자를 구분하는 양성·음성 테스트를 추가했다.
실제 JEB fixture에서도 HTML/JavaScript 양성 경로와 history-only 음성 경로를 확인했다.
추가 구현: `core/objectflow.py`의 Intent/Runnable 객체별 식별자, 명시적 activity 전달,
키별 문자열 extra/data, 캡처 필드를 통한 제한된 Runnable 연결. JEB `const-class`와
`new-instance` 타입 참조를 정규화하며 일반 문자열을 클래스 상수로 오인하지 않는다.
대상이 확인돼도 scheduling/lifecycle 조건이 증명되지 않아 POTENTIAL로 유지한다.
객체 분리·별칭·factory 반환·extra 덮어쓰기·다른 키·미지원 변이·callback 반환 및 힙
효과 비동기 분리·분석 예산을 테스트한다. 별도의 `boundary-fixture.apk`는 실제 DEX에서
명시적 ICC와 Runnable 경로를 확인하는 분석용 ZIP이다.
남은 작업: 일반 객체/배열 모델, 가상 호출 해석, 암시적 ICC/서비스/receiver,
coroutine/Rx 및 비동기 순서, 검증 지배 관계,
분기 조건·정밀 path pruning, summaries 및 처리량 개선.

## 5. GUI / 보고서

Review 탭은 `gui/review.py`에서 현재 저장 DEX의 URL guard를 worker로 재계산하고 상태,
scheme/host 제약, 한계를 요약한다. 저장된 review 원문과 현재 재계산 결과는 구분한다.
비교·허용 분기/반환·helper 호출·try 시작·handler를 최대 300개 검증된 위치 링크로 제공한다.
handler는 선언된 위치이며 실행 증명으로 표시하지 않는다. 미인덱스/잘못된 예외 범위는
링크에서 제외하고 이유를 남긴다. 저장된 validation/offset 라벨은 링크 생성 근거로
신뢰하지 않으며 Finding 판정·메모·저장된 review를 변경하지 않는다. 취소/뒤로 가기와
프로젝트 재열기 후 근거 재생성을 검증했다. attack path가 없으면 빈 하단 패널은 숨긴다.
`build/gui-review-preview.png`는 이 화면의 synthetic fixture이며 실제 APK 화면이 아니다.

추가 구현: `analyzers/url_validation.py`는 같은 메서드의 `Uri.parse` 입력 identity와
getScheme/getHost→String.equals(비어 있지 않은 상수)→if-eqz/if-nez의 허용 successor를
추적한다. 동일한 문자열이 정확한 WebView.loadUrl sink에 전달되는 모든 열거된 정상
CFG 경로에서 제약이 유지될 때만 해당 항목을 MODELED_EXACT_MATCH로 기록한다.
successor 배열 순서가 아니라 물리적 다음 명령 위치를 fallthrough로 사용한다.
검토 결과/상수/비교·분기 오프셋은 Finding.review.url_validation과 validation에 저장되고
GUI Review/Evidence에 표시된다. 검사 후 재대입, 다른 값 검사, 접두어 비교, 우회,
루프, 미해결 CFG, 탐색 예산 초과는 근거를 인정하지 않는다. 예외 handler는 아래
후속 예외 CFG 모델의 범위 안에서만 검사한다.

상한은 메서드 2,000개 명령 / 탐색 4,000 steps / 대기·sink 경로 128개다. 이 모델은
정상 흐름의 정확한 문자열 제약이지 URL 안전성 증명이 아니다. URI/WebView 파서 차이,
redirect·런타임 동작, 완전한 예외 흐름과 일반적인 helper 호출은 미지원이다.
따라서 finding type/severity/verification은 낮추거나 삭제하지 않으며 null_check도 추론하지
않는다. M3의 자동 안전 경로 처리·sanitizer suppression은 아직 완료되지 않았다.

후속 구현: 정확한 static `(String)boolean` helper를 최대 2단계 추적한다. 실제 인자
identity를 helper parameter에 전달하고, 모든 모델링된 true 반환에 공통인 제약만
호출자의 true 허용 분기로 전달한다. recursion/깊이/공유 instruction 예산 초과,
미모델링 반환, 다른 입력, 무시된 결과·반대 분기·검사 실패 시 true 반환은 근거를
인정하지 않는다. 가상 helper와 boolean 외 반환 타입은 지원하지 않는다. 비교의
소속 메서드와 반환/분기 근거, helper 호출 검토 상태를 review에 저장한다.

JEB IDexCodeItem.getExceptionItems()로 Method.exception_status(NONE/PRESENT/UNKNOWN),
exception_regions의 바이트 단위 [start,end)와 handler 주소·타입을 기록한다. 기존 전체
successors는 보존하고 normal_successors를 별도 추출한다. `analyzers/exception_flow.py`는
각 보호 명령에서 등록된 모든 handler로 가는 보수적 예외 경로를 만든다. 타입 매칭이나
실제 throw 가능성을 추정해 경로를 제외하지 않는다. 예외 전이 시 pending 반환값과
기존 guard 사실을 지우고 handler를 탐색한다. 정상·예외 경로 모두 기존 공유 예산을 쓴다.

정규화된 정보가 충분한 fixture에서는 false 반환/조기 종료 catch와 true 반환/sink 우회
catch를 구분한다. 검증된 제약이 예외 경로까지 유지되면 EXCEPTION_FLOW_CONSTRAINED로
표시하지만 안전성 판정이나 suppression은 아니다. UNKNOWN 상태, 범위/handler/정상
successor 누락, 범위 겹침·비정렬, 순환·예산 제한은 계속 UNKNOWN이다. region 및 region별
handler 상한은 각각 64개다. 보호 구간 끝이 인덱스 명령 경계로 확인되지 않는 경우도
거부한다. legacy PRESENT 프로젝트에 상세 범위가 없으면 재분석이 필요하다.
모든 타입·finally·동기화·비정상 DEX를 완전히 해석한 모델은 아니다.

추가 구현: `analyzers/verification.py`에서 후보별 선언 호출/모델 경계 역추적과
CFG 분기 문맥을 기록한다. 경로 없음과 탐색 제한을 구분하고, dominance만으로
sanitizer를 인정하지 않는다. `Finding.review`를 프로젝트에 저장하고 GUI Review
탭으로 표시한다. 이전 프로젝트는 review 기본값으로 열린다. 원본 JEB XREF도 실제
DEX operand와 대조해 다른 선언을 가리키는 참조를 직접 호출자로 오인하지 않게 한다.

구현: `gui/controllers/workspace.py`, `gui/models/findings.py`, `gui/highlighter.py`,
`gui/qml/Main.qml`. QML shell, 가상 목록, 검색/필터, 코드 구문 강조, 증거·바이트코드·
XREF/CFG/호출 데이터, 공격 경로, 메모, 백그라운드 분석, 취소, JSON 저장/열기를 연결했다.
시작 시 Core/Engines를 백그라운드 검사하고 AST/JEB XREF 탭은 실제 브리지에서 가져온다.

검증: 실제 Qt Quick 엔진으로 빈 화면과 synthetic finding을 로드하는 offscreen smoke 테스트.
`build/gui-preview.png`는 **synthetic normalized fixture** 화면이며 실제 APK 분석 결과가 아니다.
`build/gui-jeb-preview.png`는 생성한 fixture APK를 실제 JEB로 분석한 뒤 GUI에서
디컴파일 결과를 조회한 화면이다. 상용 앱 분석 결과로 해석하면 안 된다.
추가 구현: `core/graph.py`의 공통 선언 해석을 backend callers/callees/XREF와 GUI 조회에
연결했다. 원본 DEX operand와 해석된 선언을 별도 필드로 보존하며 가상 dispatch 증명을
주장하지 않는다. GUI XREF/Call Graph는 worker에서 취소 가능하게 최대 300개 edge를
반환하고, 잘림을 표시한다. 참조 위치와 인덱스에 존재하는 선언 본문은 클릭 탐색한다.
`core/navigation.py`는 unit/메서드/정확한 명령 offset을 확인하고 잘못된 위치를 거부한다.
Finding location, flow step, attack path에서 최대 61개 명령 문맥과 `>>>` 마커를 표시한다.
이전 DEX 위치로 돌아오는 100개 한도 이력과 현재 탐색 메서드의 코드/CFG/AST 조회를
연결했다. 이력 자체는 세션 전용이며 프로젝트에는 저장하지 않는다. 프로젝트 재열기 후
같은 flow/reference 위치로 이동하는 경로는 정규화된 근거로 재현된다.
원본 JEB XREF도 `native_reference_page`에서 실제 명령 operand를 재검증한 뒤 클릭한다.
EXACT_DECLARED_TARGET / INHERITED_DECLARATION이며 unit이 일치하는 위치만 링크를
생성한다. 다른 대상/미확정/잘못된 offset/unit 누락은 원본 참조와 거부 이유를 보존하되
링크를 만들지 않는다. 외부에 저장된 validation label은 신뢰하지 않고 다시 계산한다.
중복 위치는 링크만 합치고 원본 항목은 유지한다. 페이지당 최대 300개를 조회하며
이전/다음 버튼과 범위/전체 개수를 표시한다. 전체 페이지를 누적하지 않고 현재 페이지만 유지한다.
새 페이지 검증·직렬화 완료 후 목록을 교체하며 실패/취소/늦은 취소는 기존 목록과
위치·이력·메모를 보존한다. 다른 Finding/프로젝트의 오래된 응답은 반영하지 않는다.
603개 합성 참조의 3개 페이지, 빈 페이지와 실제 JEB fixture의 왕복 조회를 검증했다.
DEX 패널은 클래스→메서드의 2단계 탐색, 대소문자 무시 검색과 300개 페이지를 제공한다.
전체 순회는 취소 가능한 worker에서 실행하고 화면에는 현재 페이지만 전달한다. 순서는
저장된 인덱스 순서이며, 참조 전용 method_index는 제외한다. 본문 없는 항목은 명시한다.
Finding 없이 정확한 Bytecode 위치와 이력, CFG/XREF/AST/디컴파일을 사용할 수 있으며
독립 탐색 시 Finding 선택/판정 표시를 해제하되 저장된 Finding과 메모는 변경하지 않는다.
80,000개 합성 메서드의 페이지 상한과 취소, 실제 JEB fixture의 독립 조회를 검증했다.
추가 구현: unit→package→class→member drill-down과 필드 inventory를 제공한다.
새 class_index/field_index는 JEB가 반환한 unit별 심볼 출처를 저장한다. 클래스/필드의
unit 출현을 선언 여부로 해석하지 않는다. 구형 프로젝트의 알 수 없는 출처는 빈 unit으로
유지하고 Unknown unit으로 표시한다. 선언이 확인된 method_index의 미저장 본문도 표시하되,
동일 서명의 다른 unit에 저장된 본문으로 대체하지 않는다. 분석 엔진의 서명 기반 단일 본문
모델은 그대로이며, 중복 본문 전체 분석/분리 저장을 구현한 것은 아니다. 캐시 키의 브리지
파일 해시가 바뀌므로 새 분석은 변경된 출처 인덱스를 생성한다.
필드 선택 시 Field XREF worker가 표준 iget/sget/iput/sput 및 7개 타입 변형을
정확한 operand로 검색한다. 선택 unit과 일치하는 저장 본문만 조회하고 페이지당 최대
300개를 표시한다. Unknown unit은 전체 저장 본문을 검색하되 링크를 생성하지 않는다.
고유한 유효 DEX 오프셋/메서드 키/동일 unit을 확인한 READ/WRITE만 위치 탐색으로 연결한다.
취소·오래된 응답은 반영하지 않는다. 상속 필드 해석, quickened opcode, 선언 여부,
실행·전체 참조 완전성은 검증하지 않는다. 실제 JEB fixture READ/WRITE와 위치 이동,
합성 오프셋/출처/타입 변형/상한 및 Finding·메모 보존을 확인했다.
필드 Previous/Next 페이지 및 ALL/READ/WRITE 필터를 추가했다. 총 개수는 해당 범위의
저장 본문을 worker에서 매번 순회해 계산하며, 현재 페이지만 GUI에 전달한다. 필터는
성공한 응답과 함께 반영하고 실패/취소/늦은 응답 시 기존 페이지·필터·위치·메모를 보존한다.
603개 합성 참조와 실제 JEB fixture 페이지 왕복·필터 전환 및 빈 결과를 검증했다.
대형 저장 프로젝트 측정을 위해 tools/benchmark_field_navigation.py를 추가했다.
실제 QML workspace의 ALL/READ/WRITE 전환과 취소를 반복하며 worker 검색 시간,
이벤트 루프 타이머 간격, 취소 전달 시점과 전달 후 종료 지연을 구분한다.
offset 인덱스는 현재 페이지에서 링크 가능한 후보가 있는 메서드에만 생성하고,
필드 JSON은 내용 손실 없이 항목당 한 줄로 배치해 화면 갱신 비용을 줄였다.
반복 횟수/입력과 출력 경로를 검사하며 입력 프로젝트는 수정하지 않는다.
tools/benchmark_project_loading.py는 입력마다 새 프로세스에서 QML 로딩, OS 피크
working set, 알려진 caller unit의 참조 링크 300개 및 마지막 행 스크롤/위치를 검증한다.
JSON 바이트 버퍼는 디코딩 직후 해제하고, 프로젝트 로더 소유 DTO는 전체 검증을 마친 뒤
메서드별로 소비한다. 기본 from_dict는 입력을 변경하지 않고, 인덱스 순서도 유지한다.
두 저장 프로젝트의 로딩 피크는 약 1,048→891MiB / 2,009→1,685MiB로 감소했다.
한 번씩의 로딩 관측이며, amospro의 최대 UI 타이머 간격 약 388ms는 미해결 한계다.
로딩 취소: 1MiB 읽기 경계, JSON object hook/깊이 순회, 스키마/의미 검증,
메서드·명령·Finding 변환에 선택적 Cancellation을 전달한다. schema validation은
owned DTO 소비보다 먼저 실행한다. 기존 호출자는 cancel/progress 인자 없이도 동작한다.
GUI는 결과 반영 직전에 취소와 원래 세션 identity를 확인한다. 취소/오류/오래된 결과는
현재 화면·위치·Finding·메모·Review 요약을 보존하고, 재시도는 새 토큰으로 실행한다.
UTF-8 decode와 JSON native decoder의 긴 문자열/primitive array 및 객체 해제는
즉시 중단할 수 없으므로 hard cancellation deadline은 제공하지 않는다.
반복 세션 검증에서 완료된 _finish_callback과 Job.work, backend.program이 이전 모델을
붙잡는 경로를 재현했다. 성공/오류/취소 시 작업 참조를 해제하고, _loaded에서 backend도
새 program에 연결한다. 다음 작업을 시작하는 완료 콜백은 새 작업 참조를 덮어쓰지 않는다.
종료 시에도 작업 참조를 정리한다. 로그 캡처 핸들러가 보관하는 traceback은 별도 소유자다.
tools/validate_reopen_stability.py는 같은 QML workspace에서 취소→재열기를 반복하며,
이전 결과/program weak reference와 콜백 해제, 메모 보존, GC 전후 RSS를 기록한다.
실제 두 저장 프로젝트 교차 2회에서 총 4회 취소/4회 성공 재열기를 통과했다.
모든 과거 result/program weak reference는 GC 후 해제됐지만 RSS 잔류와 최대 약
1.5초의 로딩 타이머 지연은 남아 있다. 이는 장시간 누수 부재나 메모리 상한 보장이 아니다.
남은 작업: 원본 코드 위치 매핑과 마커, 완전한 CFG/call graph
레이아웃, dock/undock, light 테마, 더 세밀한 데이터 증분 갱신, HTML/CSV.

검증: 상속 호출의 raw/resolved 분리 및 reviewer/backend 일치, 참조 제한·취소,
정확한 unit/offset 검증, bounded bytecode 문맥, 프로젝트 round trip, GUI 비동기 조회와
탐색 이력 회귀. QML screenshot에서 새 flow 탐색 목록의 렌더링도 확인했다.
두 실제 저장 프로젝트의 탐색 결과와 단회 Qt timer 측정은 `build/navigation-validation.json`에 있다.

## 반복 가능한 검증 명령

```powershell
python -m pytest -q
python -m analyzer gui-smoke
python tools/build_fixture.py
python -m analyzer analyze build/fixtures/flow-fixture.apk -o build/fixtures/result.json
$env:AOSEYE_RUN_JEB = '1'
python -m pytest -q
python -m analyzer inspect build/fixtures/flow-fixture.apk --method 'Ltest/Main;->onCreate(Landroid/os/Bundle;)V' -o build/fixtures/jeb-evidence.json
```

fixture 분석은 정상 완료 코드 0과 `complete=True`를 반환하며, inspect 명령은 실제
코드·AST·CFG·XREF 근거와 capability/session 상태를 저장한다.
분석용 fixture는 DEX를 포함하나 text Manifest / 미서명 ZIP이므로 설치 대상이 아니다.
