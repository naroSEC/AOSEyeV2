# 고정 암호 재료의 소비자 연결 v1

기본 블록 안에서 다음 연결을 DEX 레지스터/객체 별칭으로 추적한다.

- 고정 문자열 → String.getBytes() 또는 getBytes(고정 charset 이름) → SecretKeySpec(byte[],String)
  → Cipher.init의 key 인자. ENCRYPT/DECRYPT 모드만 지원한다(AOS-CRYPTO-005).
- 같은 bytes 출처 → IvParameterSpec(byte[]) 또는 GCMParameterSpec(int,byte[])
  → Cipher.init의 AlgorithmParameterSpec 인자. ENCRYPT 모드만 검사한다(AOS-CRYPTO-006).
- 같은 bytes 출처 → PBEKeySpec의 salt 인자(3/4인자 생성자)
  → SecretKeyFactory.generateSecret의 KeySpec 인자(AOS-CRYPTO-007).

객체의 할당 타입과 정확한 생성자·호출 서명 및 인자 수를 확인한다. 객체 레지스터 별칭을
따라가며 생성자가 bytes를 복사한 출처를 보존한다. 원본 배열이 나중에 미확정 호출에
전달되어도 이미 만들어진 spec의 출처와 구분한다. 생성 전 배열 전달, spec의 미확정 호출,
분기/미지원 쓰기에서는 보수적으로 상태를 제거한다. 블록 사이와 호출 간 요약은 하지 않는다.

모든 결과는 REVIEW/MANUAL_REVIEW/L3이며 공격 경로를 만들지 않는다. 키/IV는 MEDIUM,
salt는 LOW severity다. 생성 성공, 올바른 키/IV 크기, provider, 실제 암호 알고리즘,
실행 도달성과 반복 IV 사용은 증명하지 않는다. CWE는 검토 주제이며 확정 취약점 선언이 아니다.
탐지 근거에는 값·원문 bytecode 대신 출처/생성자/소비자의 DEX 위치와 비밀이 아닌 라벨만 넣는다.
원본 코드나 저장 프로젝트의 문자열까지 제거한다는 뜻은 아니다.

2026-10-11: Android Base64.decode(String,int)의 상수 문자열/플래그(0..31)를 지원한다.
디코딩이 반환했다면 상수 유래라는 연결만 모델링한다. 실제 값을 디코딩하거나 노출하지
않으며 구문 유효성·반환 성공·알고리즘 적합성은 확인하지 않는다.
미지원: byte[] 리터럴/fill-array-data, Java Base64/hex 및 기타 decoder, Charset 객체 오버로드,
구간 생성자, 키 저장소/자원/field의 정밀 추적, 분기 결합, 함수 간 material 전달,
알고리즘별 IV 요구조건 및 반복 사용 증명. 미탐은 재료가 안전하거나 랜덤하다는 증명이 아니다.

실제 JEB CryptoMaterialFixture에서 key/IV 양성 각 1개와 동적 배열 음성,
salt→generateSecret 양성 1개와 동적 salt 음성을 검증한다. 모든 fixture는 정적 분석 전용이다.

API 근거:

- [SecretKeySpec](https://developer.android.com/reference/javax/crypto/spec/SecretKeySpec)
- [Cipher](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/Cipher.html)
- [PBEKeySpec](https://developer.android.com/reference/javax/crypto/spec/PBEKeySpec)
