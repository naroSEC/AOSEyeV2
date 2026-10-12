# SQLite 자산 표본 검사

assets/res/raw/res/xml의 .db/.sqlite/.sqlite3 중 SQLite 헤더가 있는 2MiB 이하 파일을
메모리로 읽는다. 원본이나 사용자 DB를 열어 수정하지 않는다. 기존 APK ZIP 예산도 적용한다.

최대 16개 일반 테이블, 테이블당 64개 열/100개 행, SQLite VM 약 100,000 연산으로 제한한다.
17번째 테이블/101번째 행은 잘림 확인용이다. SQL 식별자는 이중 따옴표 이스케이프한다.
stored SQL, view, trigger, virtual-table 정의는 실행하지 않는다. query_only/trusted_schema 설정과
SELECT/READ만 허용하는 authorizer를 함께 적용한다. 확장 모듈을 로드하지 않는다.

password/passwd/secret/client_secret/api_key/access_token/refresh_token/private_key라는 열에서
비어 있지 않은 text/blob 표본이 있으면 AOS-ASSET-002(REVIEW/LOW/MEDIUM confidence/L2)를 만든다.
테이블/열 이름과 값은 근거에 남기지 않는다. Location.offset은 파일 바이트가 아닌
테이블 순번이다. 패키지 파일 경로 및 표본 행 수/해당 열 수만 기록한다.

값이 진짜 자격 증명인지, 해시/암호문/예제인지, 유효한지는 증명하지 않는다.
암호화 DB, 다른 열 이름, 행 한도 밖 데이터는 미탐 가능성이 있다. 형식/예산 실패는
diagnostic으로 보존하며 분석 완료 또는 안전으로 표시하지 않는다.

텍스트 secret 정규식도 전체 일치 목록을 먼저 만들지 않고 20개까지만 순회하도록 변경했다.
이 변경은 결과 개수를 바꾸지 않으면서 반복 문자열에서 불필요한 메모리 할당을 줄인다.
