# 생체 인증 콜백 문맥 v1

AOS-AUTH-001은 플랫폼/AndroidX BiometricPrompt.AuthenticationCallback 상속 클래스에서
onAuthenticationFailed 또는 onAuthenticationError가 자기 객체의 로컬
onAuthenticationSucceeded(AuthenticationResult)를 null 인자로 직접 호출하는 패턴을 기록한다.

전체 본문/예외 정보 NONE/직선 successor를 요구한다. 본문은 nop, null 상수,
move-object 별칭, 해당 성공 메서드 호출과 return-void만 허용한다.
성공 메서드 본문이 인덱스에 있어야 하며, 미확정 상속 메서드로 넘어가지 않는다.

결과는 REVIEW/MEDIUM/HIGH confidence/L2/MANUAL_REVIEW다. 성공 콜백이 UI만 처리하거나
null을 거부할 수 있으므로 권한 우회 확정이나 공격 경로를 생성하지 않는다.
콜백 등록, 대체 인증, 보호 동작 및 서버 권한은 UNKNOWN으로 남긴다.

미지원: 분기/다른 helper/예외 경로, FingerprintManager 등 다른 API, CryptoObject 사용과
Keystore 보장, JWT/서버 token 검증, 업무 권한, 실제 센서·사용자 인증. 기기나 서버에 접속하지 않는다.
test_biometric.py와 실제 JEB fixture에서 플랫폼의 실패/오류 양성 2건, 같은 이름만 있는
일반 클래스와 정상 거부 음성, AndroidX 정규화 명령 모델, 취소·저장 왕복을 검증한다.

공식 근거: [플랫폼 콜백](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.AuthenticationCallback),
[AndroidX 콜백](https://developer.android.com/reference/androidx/biometric/BiometricPrompt.AuthenticationCallback).
