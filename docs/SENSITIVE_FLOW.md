# 민감정보 흐름 및 저장 문맥 — 2026-10-12

기존 외부 입력→위험 API 분석과 별도 규칙 집합/상태로 실행한다. Intent 입력이라는 이유로
민감정보로 간주하지 않는다. source는 AccountManager.peekAuthToken, blockingGetAuthToken,
getPassword의 정확한 반환 시그니처 3종이다. 값 자체를 조회하거나 계정 API를 실행하지 않는다.

## 탐지 범위

- Log 메시지 인자(일반 및 Throwable 오버로드, println).
- SharedPreferences.Editor.putString의 value 인자.
- SQLiteProgram/SQLiteStatement.bindString의 value 인자.
- 지정된 Writer의 String write와 OutputStream/FileOutputStream의 byte[] write 인자.
- ClipboardManager.setText 또는 ClipData.newPlainText의 text→setPrimaryClip.

String.concat/getBytes의 명시적 인자 전달, 앱 내부 인자/반환/필드 및 기존 bounded
배열/컬렉션 모델을 재사용한다. 알 수 없는 변환은 안전하다고 가정하거나 투명 전파하지 않고
진단한다. API 미지원으로 경로가 끊겼다는 사실은 암호화나 유출 방지의 증명이 아니다.

모든 결과는 REVIEW/LOW severity/MEDIUM confidence/MANUAL_REVIEW, L3 또는 L4이다.
외부 공격 경로를 만들거나 실제 데이터 저장, 평문, 외부 저장소,
캐시 경로, 타 앱 접근, 토큰 유효성 또는 분기 실행 가능성을 확정하지 않는다.
후속 문맥 분석은 apply/commit 및 제한된 SQLite execute 호출을 연결하지만 실행 성공과
트랜잭션 commit을 확정하지 않는다.
stream은 메모리 기반/보호된 구현체일 수도 있고 source는 null을 반환할 수도 있다.
CWE는 검토 주제 매핑이며 해당 취약점의 확정이 아니다.

Log tag, preferences key, ClipData label은 현재 **값 흐름** 규칙 범위 밖이다.
그 인자에 민감 값이 없거나 안전하다는 뜻이 아니다. 비동기 AccountManager Bundle 결과,
앱/SDK 고유 OAuth 응답, 암호화 저장소 판별, ContentValues/실행 연결과 경로별 저장 위치는
후속 구현 대상이다. source 이름/변수 이름만의 일반적인 비밀번호 추측은 하지 않는다.

## 저장 호출 문맥 v1

기존 민감정보 finding의 validation/review에 연결 근거를 추가한다. 원래 source→sink
경로, finding ID/심각도/검증 수준을 바꾸지 않는다. 문맥을 못 찾았다는 것은 저장되지
않았거나 안전하다는 뜻이 아니다. storage_call_context=UNKNOWN으로 남긴다.

- SQLiteProgram/SQLiteStatement.bindString의 상수 슬롯(1..32766)과 같은 receiver의
  execute/executeInsert/executeUpdateDelete를 연결한다. 알려진 다른 슬롯 쓰기는 유지하고
  같은 슬롯의 bindString/bindNull/bindLong/bindDouble/bindBlob 덮어쓰기는 제거한다.
  clearBindings, 알 수 없는 슬롯/호출, 다른 symbolic receiver 변경은 보수적으로 무효화한다.
  최대 128개 슬롯을 추적하며 초과하면 기존 사실을 버린다. 실행 이후 callback 영향을
  고려해 추적 상태를 버린다. SQL 종류, DB 위치/암호화, 성공 반환과 트랜잭션은 UNKNOWN이다.
- 정확한 Context/ContextWrapper/Activity/Service/Application.openFileOutput 호출의 반환을
  FileOutputStream/OutputStream.write([B), write([BII) receiver로 연결한다. 이름은 단일
  상수 basename(1..255자, 경로 구분자/상위 경로/NUL·줄바꿈 제외)일 때만 지원하며 값은
  결과에 기록하지 않는다. 요청된 위치 APP_INTERNAL_FILES, mode 및 열기/쓰기 offset을
  남긴다. runtime 위치/암호화/실제 쓰기/외부 앱 접근은 UNKNOWN이다. 내부 파일이라는
  사실만으로 안전 또는 취약 판정하지 않으며, API override/실행 SDK 제약을 확정하지 않는다.

두 모델은 완전한 선형 CFG, 예외 영역 없음, 정규화 진단 없음, 최대 4,000명령을 요구한다.
move 별칭을 지원하며 미모델링 호출/필드·배열 접근/분기에서 사실을 제거한다. 기본/이름
인자 String.getBytes는 파일 연결을 유지하지만 사용자 Charset 객체는 보수적으로 끊는다.
모든 명령에서 취소를 확인한다. 값/파일명/SQL 문자열을 추가로 출력하지 않는다.

미완료: ContentValues→insert/update, cache/external path→File 생성자→stream, Writer wrapper,
SQLCipher/암호화 wrapper 판별, 비동기 토큰 응답/SDK source, 함수 간 저장 객체 문맥.
이번 연결은 이 항목들의 구현 완료를 대신하지 않는다.

## 예산·통합

기존 입력 분석이 먼저 소비한 뒤 max_flow_steps의 남은 한도를 사용한다. 따라서 전체
분석의 두 엔진 steps 합은 설정 한도를 넘지 않는다. 앞 단계가 예산을 소진한 경우
민감정보 경로가 있어도 생략될 수 있으며 Sensitive flow 진단과 coverage에 남긴다.
민감 source가 없는 독립적인 ICC/async 루트는 추가 탐색하지 않는다.
별도 sensitive_flow_coverage에 source 규칙 fingerprint, step_limit, steps, 한계를 저장한다.
analysis_policy에 sensitive-flows-v1을 추가한다. YAML은 wheel에 포함된다.

## 검증

tests/test_sensitive_flow.py: 값/다른 인자, source 분리, 덮어쓰기, helper 반환, 문자열 인코딩,
clipboard text/label, 불명확한 변환, 예산/취소와 결과 저장 왕복.
tests/test_jeb_tls.py와 CredentialFixture.java: 실제 JEB가 읽은 DEX에서 6개 규칙,
8개 기존 경로(helper 포함)와 SensitiveStorageFixture의 4개 민감정보 경로를 확인한다.
그중 SQL 실행/파일 열기의 연결 양성 2개와 clearBindings/다른 stream의 문맥 음성 2개를
구분한다. test_sensitive_storage.py는 덮어쓰기/별칭/다른 슬롯/예산 전제/예외/취소/저장
왕복을 검사한다. fixture는 APK에 설치하거나 실행하지 않는다.

API 의미 근거:

- [AccountManager](https://developer.android.com/reference/android/accounts/AccountManager)
- [SharedPreferences.Editor](https://developer.android.com/reference/android/content/SharedPreferences.Editor)
- [ClipData](https://developer.android.com/reference/android/content/ClipData)
- [SQLiteStatement](https://developer.android.com/reference/android/database/sqlite/SQLiteStatement)
- [Context.openFileOutput](https://developer.android.com/reference/android/content/Context#openFileOutput(java.lang.String,%20int))
