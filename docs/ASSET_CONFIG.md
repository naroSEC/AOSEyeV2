# APK 구성 자산 분석 v1

## 공개 인증서 자산 (2026-10-10)

.crt/.cer/.der 및 CERTIFICATE 표시가 있는 .pem을 기존 제한형 X.509 파서로 검사한다.
AOS-ASSET-006은 INFORMATION/INFO/L2이며 공개 인증서를 secret으로 분류하지 않는다.
결과에는 encoding/인증서 수만 추가하고 subject/issuer/키 값은 출력하지 않는다.
1MiB/PEM 64개 제한, 중간·뒤 추가 내용 거부, 취소를 유지한다.
파싱 실패/예산 초과는 진단에 남고 기존 텍스트 secret 검사는 계속 수행한다.
공개 인증서와 private-key 표시가 섞인 파일에서 private-key 후보를 숨기지 않는다.
만료/서명/체인/CA 적합성/실제 trust-anchor 사용을 검증하는 기능이 아니다.
PKCS12/JKS 암호 해독과 private-key 유효성 검사는 여전히 미지원이다.

## JSON 구성

선택된 assets/res/raw/res/xml의 `.json` 파일에 의미 검사를 추가한다.
모든 결과는 REVIEW/MANUAL_REVIEW이며 네트워크 인증이나 키 유효성 검사를 하지 않는다.

- AOS-ASSET-003: service_account, client_email, private_key의 PEM 시작 표시가 함께 있는
  Google 서비스 계정 키 후보. MEDIUM/L2이며 유효한 키나 활성 계정이라는 주장은 아니다.
- AOS-ASSET-004: web apiKey/projectId/appId 또는 Android project_info/client/api_key 구조의
  Firebase 클라이언트 구성 후보. INFO/L2. 일치하는 API 키의 일반 assignment 결과도 INFO로
  분류하지만 같은 파일의 password/다른 secret은 제외하지 않는다.
- AOS-ASSET-005: JSON 최상위 AWS access key ID/secret access key 쌍. MEDIUM/L2.
  ID만 있으면 탐지하지 않는다. 예제 값 여부, 권한, 사용 위치는 수동 검증 대상이다.
- 기존 AOS-SECRET-005 URL 검사는 IPv4 옥텟을 검증하고 RFC1918 세 범위 및 loopback을
  식별한다. localhost 하위 도메인과 dev/staging 레이블도 후보로 남긴다.
  device 도메인이나 URL 경로/사용자 이름의 dev만으로 분류하지 않는다.

JSON은 UTF-8, 256KiB, 중첩 32단계로 제한하고 중복 키/잘못된 구문을 거부한다.
실패/예산 초과는 진단에 표시하고 기존 텍스트 검사는 유지한다. 파서 오류 값은 출력하지 않는다.
텍스트 패턴은 파일·규칙별 20건을 유지하되 21번째 유효 일치를 찾으면 잘림을 진단한다.
공개 URL은 내부 URL 규칙의 탐지 건수 예산을 소비하지 않는다.
기존 ZIP 크기/압축률/총 읽기 예산과 취소 검사를 유지하며 파일을 추출하지 않는다.

2026-10-11: IPv6 literal의 ULA(fc00::/7), link-local(fe80::/10), loopback 및 IPv4-mapped
사설/loopback 주소를 추가했다. 불특정/멀티캐스트/문서용 IPv6를 사설망으로 일반화하지 않는다.
INI/dotenv/properties/conf/credentials는 256KiB/64 section/4096 assignment 내에서 같은
section의 AWS 키 쌍만 추가 검사한다. 중복·모호한 별칭·escape/다중행 구문은 거부하고,
환경 변수나 명령 치환은 실행하지 않는다. 서로 다른 section의 키를 합치지 않는다.
값은 모두 가리며 JSON과 마찬가지로 유효한 실제 credential이라고 확정하지 않는다.

제한: 중첩 AWS 자격 증명, JavaScript의 구성 문맥, XML Firebase 연관,
암호화/난독화 값, 인증서/keystore 암호 해독, 서버 정책은 이번 의미 검사에서 지원하지 않는다.
보고서에는 키/이메일/URL의 실제 값을 포함하지 않지만 원본 APK를 삭제·변경하지도 않는다.

근거:

- [Firebase API keys](https://firebase.google.com/docs/projects/api-keys): 클라이언트 API 키와 서비스 제한.
- [Firebase security checklist](https://firebase.google.com/support/guides/security-checklist): 서비스 계정 키 보호.

tests/test_asset_config.py가 양성/음성, 값 마스킹, 파서 제한, ZIP 통합 및 취소를 검증한다.
