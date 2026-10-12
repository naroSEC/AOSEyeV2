# 후보 재열기·제한적 재분석·보고서 내보내기 (2026-10-05)

## 후보 재열기

상단 Candidate 버튼으로 별도 파일을 읽기 전용으로 연다. 전용 스키마/바이트/해시 검증 후
현재 프로젝트의 원본 지문, 호출자 unit/명령/대상, 대상 선언, JEB 버전을 비교한다.
SAVED_METADATA_MATCH는 저장 정보 일치이며 진위나 실제 APK 검증이 아니다. 프로젝트가
없거나 정보가 다르면 NO_PROJECT 또는 MISMATCH_OR_UNKNOWN으로 표시한다.
원래 후보의 시각/출처를 보존하며 파일을 재열었다는 이유로 새로운 조회 시각을 만들지 않는다.

## 명시적 제한 확장

후보 창의 Reverify & analyze expanded scope는 원본 파일 해시와 실제 JEB 본문을 다시
조회해 후보 해시와 일치하는 경우에만 새 Program을 만든다. 기존 분석의 methods에 바로
넣지 않는다. 같은 설정으로 APK 구성/저장 범위의 보안 규칙을 다시 실행한 새 결과가 성공한
뒤에만 화면을 교체한다. 이전 객체는 바꾸지 않고 메모를 복사한다. 자동 파일 덮어쓰기는 없다.

한 요청에 한 본문, 누적 최대 8개/추가 본문 2MiB다. 원래 선언 범위를 늘리지 않고 partial을
유지한다. 기존 제외 진단도 지우지 않는다. 원본이나 본문이 바뀌었거나 JEB가 재검증하지
못하면 거부한다. 완료 직전 취소/오래된 응답은 반영하지 않는다. 실패 시 backend의 원래
program/path/hash 연결을 복원한다. live resource 해석도 새 program에만 capability를 기록한다.

복제/재분석은 기존 저장 범위 크기에 비례하며 전체 RAM 상한은 아니다. 메모의 finding ID가
새 결과에 없을 수 있으므로 메모를 자동 삭제하지 않는다. 결과는 새 프로젝트 파일로 저장하는
것을 권장한다. 가상 dispatch, 인덱스 밖 대상, 재귀 자동 확장은 여전히 지원하지 않는다.

## 보고서

GUI Save / Export에서 HTML, CSV findings, Normalized DEX IR JSON을 선택한다.
CLI 예: `python -m analyzer export project.json --format html -o report.html`.
CLI 내보내기는 JEB나 사용자 설정 로딩 없이 저장 프로젝트를 읽는다.

HTML은 모든 증거를 escape하고 외부 스크립트/이미지를 허용하지 않는 CSP를 포함한다.
CSV는 spreadsheet 수식 접두어를 보호한다. IR JSON은 저장된 정규화 DEX DTO이며
JEB optimizer 고유 IR이나 정확한 런타임 호출 그래프를 뜻하지 않는다.
민감한 코드/증거가 포함될 수 있으므로 외부 공유 전 검토가 필요하다.

최대 128MiB, 새 파일만 원자적으로 게시하고 기존 파일을 덮어쓰지 않는다. 실패/취소 시
임시 파일을 정리한다. hard link 미지원 파일시스템은 안전하게 실패한다. 출판 직후 들어온
취소는 이미 저장된 파일을 삭제하지 않는다. 후보 형식과 마찬가지로 프로젝트/IR/보고서
파일은 서로 다른 형식이다. IR export를 프로젝트로 자동 가져오지 않는다.

## 검증

전체 736 passed (143.08초), 실제 JEB 통합 17개 포함. 신규 18개는 후보 출처/재열기,
불일치·취소·확장 한도·기존 데이터 보존, HTML escaping/CSV 수식 방지/IR 왕복/내보내기
실패를 검사한다. 기존 실제 JEB GUI 시험에서 실제 후보의 확장/재분석도 확인했다.
wheel SHA-256: `4e0a7eab234aa708ab93bc34205ae086a7332a699bd48d0cbac63261519bd56e`.

후속 검증(2026-10-05): 위 해시는 이전 후보/보고서 빌드의 기록이다.
Storage Policy와 UTF-8 바이트 누적 writer를 포함한 당시 wheel SHA-256은
`e98f0945daf0780b40bb26afa8866c8e858a6bf1d0c6ad65db894a48c486e995`이다.
별도 가상환경 설치부터 JEB 분석/재열기와 HTML/CSV/IR 출력까지 14항목을 통과했다.
설치 검증 기록: `C:/validation-temp/aoseye-wheel-krhp9rvs/validation.json`.
대용량 출력과 저장소 XML의 확인 범위는 `STORAGE_CONFIGURATION.md`에 기록했다.
이후 이름→ID XML 연결을 포함한 최신 빌드/검증은 `IMPLEMENTATION_STATUS.md`를 참조한다.
