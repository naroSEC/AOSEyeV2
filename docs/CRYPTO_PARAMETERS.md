# 암호 파라미터 문맥 v1

2026-10-09. 기본 블록 내 상수 전달과 정확한 생성자/인자 위치를 검사한다.

- AOS-CRYPTO-003: PBEKeySpec의 3/4인자 및 PBEParameterSpec의 2/3인자 생성자에서
  iterationCount가 정확히 1인 경우 검토 항목을 생성한다.
- AOS-CRYPTO-004: GCMParameterSpec의 두 생성자에서 tLen이 32/64비트인 경우
  프로토콜별 제약을 확인할 검토 항목을 생성한다.

둘 다 REVIEW/LOW severity/HIGH confidence/L2/MANUAL_REVIEW다. confidence는 상수 인자
관측에 대한 것이며 실제 취약성에 대한 확신이 아니다. runtime_use와 algorithm_or_protocol은 UNKNOWN.
생성 성공, 유효한 salt/IV, SecretKeyFactory/Cipher.init 연결, 실제 도달성은 증명하지 않는다.
constructor API 존재만으로 탐지하지 않고 정확한 invoke-direct 형식·레지스터 수를 확인한다.
다른 값, bool/문자열/미확정 값, 다른 블록, 분기 이후, 미확정 덮어쓰기는 이 규칙의 양성이 아니다.
탐지되지 않은 값이 안전하다는 뜻도 아니다. 임의의 범용 KDF 최소 반복 횟수를 정하지 않는다.

PBE 반복 인자의 위치는 [PBEKeySpec 문서](https://developer.android.com/reference/javax/crypto/spec/PBEKeySpec)를 따른다.
[GCMParameterSpec 문서](https://docs.oracle.com/en/java/javase/26/docs/api/java.base/javax/crypto/spec/GCMParameterSpec.html)는
32/64비트 태그를 특정 용도에서 허용하므로, 짧은 태그 자체를 확정 취약점으로 처리하지 않는다.

검증: test_crypto_parameters.py의 생성자/범위 호출/형식/덮어쓰기/블록 경계 회귀와
실제 JEB CryptoParameterFixture의 양성 5개 및 정상·미확정 인자 음성.
키/IV/salt 고정 값의 객체 추적과 실제 암호 초기화 연결은 여전히 후속 구현 대상이다.
