# 서명 검증 반환값 무시 검토

2026-10-12. AOS-AUTH-002는 완전한 선형 boolean 메서드에서 정확한 Signature.verify
호출 반환값이 move-result로 소비되지 않고 정상 경로가 상수 true를 반환하는 패턴이다.
verify([B), verify([BII)만 지원하며 메서드 최대 4,000명령, 예외 영역/불완전 CFG/정규화
진단이 없을 때 분석한다. 취소를 확인하며 지원하지 않는 쓰기는 상수 사실을 버린다.

REVIEW / MANUAL_REVIEW를 유지한다. 서명 검증 호출과 반환 명령의 원래 DEX offset을
보여주며 인증 우회로 확정하지 않는다. 검증 API가 예외를 던지면 true에 도달하지 않을 수
있고, 진단용 함수일 수도 있다. caller의 보호 동작, JWT 검증 정책, 서버 권한 및 업무
인가 연결은 아직 해결하지 않는다. CWE-252는 반환값 무시 패턴에 한정한 매핑이다.

test_auth_verification.py의 양성/음성/취소/저장 왕복과 SignatureResultFixture.java의
실제 DEX에서 ignored/used/reject를 구분한다.

API 계약: https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/Signature.html
