# TLS callback context v2 / setter connection v1

DEX 본문 기반의 제한적 패턴 분석이다. APK를 실행하거나 TLS 연결을 시도하지 않는다.

- AOS-TLS-001: 정확한 checkServerTrusted(X509Certificate[],String)void 시그니처,
  nop 외 return-void만 있는 본문. REVIEW/INFO.
- AOS-TLS-002: 정확한 verify(String,SSLSession)boolean 시그니처,
  정수 상수와 move만으로 항상 1을 반환하는 직선 본문. REVIEW/INFO.
- AOS-TLS-003: 알려진 WebViewClient 상속 클래스의 onReceivedSslError에서
  incoming handler 또는 move-object 별칭에 무조건 proceed() 후 반환. WEAKNESS/MEDIUM.

모두 L2/HIGH confidence, MANUAL_REVIEW이며 attack_path를 만들지 않는다.
첫 두 패턴은 JEB의 getInterfaceSignatures(False) 선언과 superclass/interface 조상 연결에서
각 X509TrustManager/HostnameVerifier가 확인되면 WEAKNESS/MEDIUM으로 분류한다.
최대 256개 타입을 방문하며 순환을 차단한다. 선언 누락/불명확은 기존 REVIEW/INFO로 유지한다.
이 확인은 callback 설치 또는 실제 TLS 연결 사용의 증명이 아니다.
Program.class_interfaces는 기존 선언 바이트 예산에 포함되며 프로젝트/IR에 저장한다.
이 필드가 없는 과거 프로젝트는 빈 정보로 읽으며 interface 구현을 추정하지 않는다.
세 번째도 WebViewClient 설치와 실행 도달성은 입증하지 않는다.

## 설정 API 인자 연결

AOS-TLS-004/005는 별도 L3/WEAKNESS/MEDIUM 결과다. 전체 직선 본문에서 새로 생성한
정확한 클래스의 기본 생성자 호출, move-object 별칭, 다음 setter의 인자를 연결한다.

- HttpsURLConnection.setHostnameVerifier / setDefaultHostnameVerifier: AOS-TLS-002 본문과 연결.
- WebView.setWebViewClient: AOS-TLS-003 본문과 연결.

interface/상속과 permissive 본문이 확인된 callback만 사용한다. 같은 이름의 임의 메서드,
다른 receiver 인자, 덮어쓰기, 미초기화 객체, 미확정 외부 호출, 누락된 예외 정보는 승격하지 않는다.
객체 생성·초기화·setter의 DEX 위치와 callback 본문 finding ID를 함께 기록한다.
정적 인자 연결이지 setter 실행 성공/등록 유지/네트워크 사용 증명이 아니다.
MANUAL_REVIEW이며 attack_path는 없고 이후 교체 가능성은 UNKNOWN이다.

제한: 필드/반환값/함수 간 객체, 인자 있는 생성자,
상속받은 callback 본문, 분기·예외 경로, 제3자 클라이언트 builder는 미지원이다.
test_tls_installation.py와 실제 JEB fixture에서 설정 양성 3건 및 음성을 검증한다.
API 근거: [HttpsURLConnection](https://developer.android.com/reference/javax/net/ssl/HttpsURLConnection),
[WebView](https://developer.android.com/reference/android/webkit/WebView).

## 단일 TrustManager 배열 연결 v1

AOS-TLS-006은 확인된 빈 checkServerTrusted 본문의 새 객체가 길이 1의
TrustManager[] 원소에 저장되고 SSLContext.init의 trust-manager 인자로 전달되는 연결이다.
new-array/aput-object(확인된 인덱스 0), 원소 1개 filled-new-array, 배열/객체 별칭과
기본 생성자를 지원한다. L3/WEAKNESS/MEDIUM/MANUAL_REVIEW이며 attack_path는 없다.

미확정 길이·인덱스·배열 타입, 미초기화/덮어쓴 원소, 미확정 호출, 분기·예외는
이 모델에서 제외한다. 알 수 없는 호출 후 객체/배열 근거를 무효화한다.
SSLContext receiver의 생성·provider 선택, init 성공, socket factory/연결 사용은 UNKNOWN이다.
TLS 안전성이나 실제 공격 성공을 확정하지 않는다. 필드/함수 간 배열 전달은 미지원이다.

test_trust_array.py 및 JEB fixture의 installTrust 양성/installSafeTrust 음성으로 검증한다.
공식 근거: [SSLContext.init](https://developer.android.com/reference/javax/net/ssl/SSLContext).

2026-10-11 v2: 길이 2..16의 new-array/aput-object 및 filled-new-array를 지원한다.
다중 배열에 permissive callback이 포함된 연결은 AOS-TLS-007/L3/REVIEW/MEDIUM으로
별도 기록하며 provider가 그 원소를 선택한다는 뜻이 아니다. 길이/원소 위치와
provider_selection=UNKNOWN을 기록한다. 첫 원소가 거부 callback인 실제 DEX fixture도
포함 연결만 검증한다. 미초기화 원소나 다른 callback을 안전/위험으로 추정하지 않는다.

알려진 예외 테이블 없음(NONE), 연속 successor, 전체 본문과 진단 없음이 필요하다.
분기, helper, 예외 handler, 알 수 없는 재대입/호출, 잘못된 receiver, 상속 불명확은
이 정밀 패턴에서 제외된다. 기존 API review는 유지된다. 탐지 없음은 안전 증명이 아니다.

tests/test_tls.py는 상수·별칭·receiver·분기·불완전 메타데이터 음성과 취소를 검증한다.
tests/test_jeb_tls.py는 로컬 javac/D8/aapt2로 양성/음성 APK를 만들고 JEB로 읽어
정확히 세 후보 및 저장/재열기를 검증한다. APK 설치/실행은 하지 않는다.

의미 근거:

- [X509TrustManager](https://developer.android.com/reference/javax/net/ssl/X509TrustManager)
- [HostnameVerifier](https://developer.android.com/reference/javax/net/ssl/HostnameVerifier)
- [WebViewClient](https://developer.android.com/reference/android/webkit/WebViewClient)

Android 문서의 SSL 오류 취소 지침을 따른다. 정적 모양만으로 실제 앱 전체의 우회를 확정하지 않는다.
