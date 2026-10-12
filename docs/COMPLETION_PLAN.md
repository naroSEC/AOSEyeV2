# AOSEye 완성 작업 계획

기준일: 2026-10-12. 원래 요청의 기능을 삭제하거나 구현 완료로 간주하지 않는다.
개발 backlog이며 검증 기록은 IMPLEMENTATION_STATUS.md를 따른다.
테스트 개수는 지원 범위의 회귀 근거이지 제품 완성률이 아니다.

## 작업 방식

- 정수/컬렉션 API의 무제한 추가를 중단하고 현재 검증된 bounded 모델을 유지한다.
- 새로운 보안 탐지의 실제 미탐 원인일 때만 해당 연산을 추가한다.
- 기능군별 구현과 양성/음성 시험을 묶고 전체 회귀·wheel 설치는 묶음 마지막에 실행한다.
- API 존재, 정적 패턴, 입력 흐름, 실행 가능성이 입증된 취약점을 구분한다.
- 검증되지 않은 기능을 완료 처리하거나 미탐을 안전 판정으로 바꾸지 않는다.

## 현재 기반

JEB 지속 세션, 정규화 DEX/CFG/XREF/AST, APK/Manifest 분석, 제한적 호출 간 입력 흐름,
GUI 증거 탐색과 검토, 프로젝트 저장/재열기, HTML/CSV/IR 내보내기 및 독립 wheel 설치가 있다.
Network Security Config/backup/FileProvider, 배열/ArrayList/HashMap 일부 연산도 구현되어 있다.
오래된 REQUIREMENTS_ACCEPTANCE.md의 미구현 표기는 이후 구현 이력과 함께 해석해야 한다.

## 남은 8개 기능군

각 기능군에는 여러 구현 항목이 포함된다. 8개는 남은 개별 기능 수가 아니다.

1. **TLS 및 WebView 문맥 — 진행 중**
   - 이번 구현: 빈 서버 인증서 검증 후보, 항상 true인 호스트 검증 후보,
     incoming SSL 오류 handler의 무조건 proceed 호출을 DEX 본문에서 탐지.
   - 후속 구현: JEB interface 선언 수집과 조상 타입 확인을 추가했다(TLS_CONTEXT.md v2).
   - 2026-10-10: 새 callback 객체→HttpsURLConnection/WebView setter 인자 연결 추가.
     실제 실행·유지·네트워크 사용을 확정하지 않는다(TLS_CONTEXT.md).
   - 후속: 단일 TrustManager 배열→SSLContext.init 인자 연결 추가(TLS_CONTEXT.md).
   - 2026-10-11: 다중 TrustManager 배열(최대 16개)→init 후보 연결, 동일 WebView의
     설정→외부 입력 로딩 문맥 추가. provider 선택/실행은 미확정이며 수동 검토로 유지.
   - 남음: 함수 간 배열·객체 설치 연결, 분기·helper·예외 경로,
     JavascriptInterface 실제 노출과 로딩 출처/설정의 객체별 연관.
   - 2026-10-12: 같은 WebView의 bridge 등록/해제→외부 입력 로딩 연결 추가.
     annotation/실행 API/iframe 및 실제 노출은 미해결(RECEIVER_CONTEXT.md).
   - 완료 조건: 설치 여부/분기별 양성·음성 DEX fixture와 근거 탐색·저장 왕복.
2. **민감 데이터 저장·유출 흐름 — 미완료**
   - 2026-10-09: AccountManager 토큰/비밀번호 반환→Log/Preferences/SQLite bind/
     Writer·OutputStream/Clipboard 값 인자 흐름 추가. 상세 범위는 SENSITIVE_FLOW.md.
   - 현재는 REVIEW 경로이며 저장 완료/외부 유출/평문 저장 확정이 아니다.
   - 2026-10-11: 같은 Editor의 putString→apply/commit 연결을 추가했다.
     실제 디스크 반영/성공 반환/보호 문맥은 UNKNOWN(RECEIVER_CONTEXT.md).
   - 2026-10-12: 같은 SQLiteStatement 슬롯의 bindString→execute 연결과
     openFileOutput 반환→민감 byte[] 쓰기의 내부 파일 요청 문맥 추가(SENSITIVE_FLOW.md).
     ContentValues/외부·캐시 경로/암호화 여부/SDK source는 아직 미완료다.
   - SharedPreferences/SQLite/file/cache/external storage/log/clipboard.
   - 외부 입력과 민감 데이터를 동일시하지 않는 source 분류, 저장 인자의 역할 및 보호 문맥 필요.
   - 완료 조건: 민감 입력 양성, 공개 데이터·덮어쓰기·다른 인자 음성, 위치와 흐름 증거.
3. **암호 사용 문맥 — 부분 구현**
   - 2026-10-09: PBE 단일 반복 인자와 GCM 32/64비트 태그의 DEX 상수 문맥 검토 추가.
     생성자와 소비자의 연결을 입증하는 기능은 아니며 CRYPTO_PARAMETERS.md에 한계를 명시.
   - 후속: 고정 문자열 bytes→key/IV spec→Cipher.init 및 salt→PBEKeySpec→generateSecret의
     기본 블록 내 연결 추가(CRYPTO_MATERIAL.md). 함수 간/배열 리터럴과 알고리즘별 판단은 남음.
   - DES/3DES/RC4/명시적 ECB 및 약한 해시 검토는 있음. AES 이름만으로 취약 판정하지 않음.
   - 2026-10-11: 상수 문자열→Android Base64.decode→key/IV/salt 생성자→소비자 연결 추가.
     함수 간/배열 리터럴과 알고리즘 판단, decoder 실행 성공은 여전히 미확정이다.
   - 남음: 키/IV/salt의 고정 값과 실제 암호 초기화 연결, KDF 파라미터, PRNG 사용 목적.
   - 완료 조건: 알고리즘 이름이 아닌 인자/객체 문맥을 입증하는 양성·음성 시험.
4. **IPC·Deep Link·권한 연결 — 부분 구현**
   - 2026-10-09: mutable PendingIntent의 대상 제한과 플래그 충돌을 기본 블록에서 검사.
     SDK별 생성 제약과 미확정을 표시한다(PENDING_INTENT.md). 실제 전달/권한 경로는 남음.
   - 후속: Intent 복사·setClass/setClassName·component null 해제의 독립 상태를 추적한다.
   - 명시적 Activity 전달과 Provider operation별 권한은 일부 지원.
   - 2026-10-12: 명시적 service/receiver 전달과 추적 객체의 참조 필드 연결 추가.
     정확한 지원 API 및 외부 호출 무효화 한계는 COMPONENT_DELIVERY.md에 명시.
   - 남음: implicit Intent, 기타 service/receiver lifecycle, PendingIntent, URI grant,
     task 설정, 앱 링크 소유권, privileged action의 권한 검사.
   - 완료 조건: exported 존재와 무권한 실행 가능성 구분, 차단 조건/미해결 조건 명시.
5. **APK 자산의 의미 분석 — 부분 구현**
   - 파일 목록, 제한적 텍스트 secret 후보와 값 마스킹은 있음.
   - 이번 구현: SQLite credential 이름 열의 제한된 행 표본 검사(모든 값 마스킹).
   - 후속 구현: Firebase 공개 구성/서비스 계정 키/AWS 키 쌍 JSON 구분, IPv4 사설망 검증,
     규칙별 20건 잘림 표시를 추가했다(ASSET_CONFIG.md).
   - 후속: 공개 PEM/DER X.509 자산 파싱을 INFORMATION으로 분리(ASSET_CONFIG.md).
   - 2026-10-11: IPv6 로컬 주소와 INI/dotenv/properties의 같은 section AWS 키 쌍 추가.
   - 남음: 암호화 DB/다양한 스키마, keystore/인증서 실제 사용 문맥, JSON 외 cloud credential 문맥,
     추가 cloud 형식·개발 설정. 파일 확장자 탐지와 내용 분석을 구분.
   - 완료 조건: ZIP/파서 예산·취소·악성 입력 회귀, 공개 설정을 secret으로 과대평가하지 않음.
6. **인증·인가 및 동적 코드 문맥 — 미완료**
   - 실행/로더 API와 일부 외부 입력 흐름은 있음.
   - 2026-10-10: 생체 인증 실패/오류→로컬 성공 콜백(null) 직접 호출을 REVIEW로 추가
     (BIOMETRIC_CONTEXT.md). 성공 핸들러의 보호 동작/서버 권한은 미확정이다.
   - 2026-10-10: DownloadManager 기록 URI→DexClassLoader/PathClassLoader 인자 추적 추가
     (DOWNLOAD_FLOW.md). 실제 다운로드/내용 무결성/실행 증명이 아닌 REVIEW다.
   - 남음: download→load 연결, biometric 결과 사용, token 검증, 클라이언트 전용 인가 패턴.
   - 2026-10-12: Signature.verify 반환값 무시→정상 경로 true 반환을 REVIEW로 추가.
     보호 동작/서버 권한은 미해결(AUTH_VERIFICATION.md).
   - 서버 정책·실제 업무 권한은 APK만으로 증명할 수 없으므로 수동 검증 조건을 출력해야 함.
   - 완료 조건: 제한된 지원 패턴을 명시하고 안전/위험 쌍으로 검증.
7. **규칙·분석 범위·표준 매핑 — 부분 구현**
   - YAML source/transfer/sink와 Python 규칙은 있음.
   - 2026-10-10: 엄격한 YAML 스키마/파서 예산 및 source-prefix/argument-constant
     required_conditions DSL 추가(RULE_CONDITIONS.md). UNKNOWN은 수동 검토로 유지한다.
   - 남음: receiver/검증기 연결 등 추가 문맥 조건, source/sanitizer 확장,
     적절한 MASVS/MASWE/MASTG 매핑 및 탐지기별 미지원 범위 표시.
   - 2026-10-12: argument_bits 조건과 signed/unsigned 32비트 입력 검증 추가.
   - 일반 heap/virtual dispatch/branch solver 및 모든 연산 지원으로 범위를 무한 확장하지 않음.
   - 완료 조건: 스키마 검증, 결정적 결과, 캐시 정책 버전, 불확실성·예산 고갈 표시.
8. **제품 인수·대형 APK·배포 — 부분 검증**
   - 2026-10-12 민감정보 저장 문맥: 전체 회귀 2,366개 및 독립 설치 14개 통과.
   - 2026-10-12: component/객체 참조/WebView bridge/인증/규칙 묶음의 최종 전체
     회귀 2,250개와 독립 설치 14개 통과. 기능군 전체 완료는 아니다.
   - 2026-10-12: WebView/Editor receiver, 다중 TrustManager, Base64/IPv6/assignment
     자산 묶음의 전체 회귀 2,161개 및 독립 설치 14개 통과. 메모리 중단 뒤 재검증 완료.
   - 2026-10-11: 오픈소스/MIT 배포 선택 반영. JEB는 사용자 지정 필수이며 기본 경로 없음.
     wheel 라이선스 메타데이터, 소스 배포 경계 검사, 출시 증거 대조 도구를 추가했다.
     저장소 공개/제3자 조건 검토/보안 신고 채널/인수는 자동 승인하지 않는다.
   - 이전 TrustManager 배열/공개 인증서 묶음: 전체 회귀 2,070개 및 독립 설치 14개 통과.
   - 이전 TLS setter/생체 인증 callback 묶음: 전체 회귀 2,046개 및 독립 설치 14개 통과.
   - 이전 문맥 규칙/다운로드 흐름 묶음: 전체 회귀 2,016개 및 독립 설치 14개 통과.
   - 2026-10-10 자산/TLS interface 묶음: 전체 회귀 1,975개/독립 설치 14개 통과. 소형 APK 두 개 재검증 완료.
     최신 대형 앱은 4GiB/3GiB 모두 시스템 가용 메모리 보호 기준으로 취소되어 재검증 필요.
   - 83.8MB 앱은 제한된 본문 추출 기록이 있으며 전체 앱 분석 완료가 아님.
   - 이번 수정: 클래스/필드 메타데이터가 선언 예산을 독점하여 메서드가 0개가 되는 문제 방지.
   - 이번 검증: 83.8MB 앱의 제한 본문 2,886개와 두 증거 조회를 4GiB JVM에서 확인.
     2GiB 증거 조회 OOM과 runner의 실패 상태 표기도 기록/보강했다.
   - 남음: 최신 탐지기로 실제 APK 재검증, 정답 있는 탐지 corpus, 반복 세션/대형 프로젝트
     시간·메모리·취소 검증, 장애 복구와 사용자 GUI 인수.
   - 완료 조건: 설정/입력 해시/분석 범위가 고정된 측정 기록, 독립 설치, 알려진 제한 문서화.
   - 사용자 인수와 JEB 라이선스/다른 PC 실행은 자동 테스트만으로 완료 처리하지 않음.

## 별도 후속 범위와 완료 선언

원 요청에서 미래 확장으로 명시한 JEB IR/deobfuscation 및 JADX/Androguard는 이번 구현의
완료를 위해 임의로 추가하지 않는다. Resilience 미탐도 보호 기능 부재의 증명이 아니다.

각 기능군의 지원 패턴·제한이 구현/시험/문서에서 일치해야 한다. 위 미완료 항목이 남은 동안
원래 요청 전체를 완료했다고 선언하지 않는다. UI 완성, 테스트 통과, wheel 생성은 각각
부분적인 완료 조건일 뿐이다.
