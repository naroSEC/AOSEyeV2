# Manifest 힌트 기반 제한 인덱스 수집

`Settings.index_order`와 analyze/검증 도구의 `--index-order`에
`native`(기본값), `manifest-first`를 지원한다. 기존 사용자 설정은 바꾸지 않는다.
예: `python -m analyzer analyze sample.apk -o result.json --index-order manifest-first`.
GUI JEB settings에서도 정책을 선택할 수 있다(`GUI_INDEX_POLICY.md`).

모든 JEB unit에서 종류별로 Manifest 선언 클래스 → Manifest package의 점/슬래시 경계가
일치하는 클래스 → 나머지 순서로 클래스·필드·메서드를 선택한다. 동일 순위에서는
JEB 순서를 유지한다. 종류별 개수와 기존 합산 인덱스/본문 바이트 예산은 유지된다.
선택용 heap은 종류별 제한에 비례하지만 모든 unit의 해당 종류 시그니처는 훑는다.
JEB 내부 데이터, 단일 시그니처, 기본 artifact 처리의 메모리 상한을 보장하지 않는다.

Manifest는 안전 XML 파서로 1MiB/20,000노드/2,048개 고유 클래스 제한 하에 읽는다.
application/name·appComponentFactory, activity/service/receiver/provider/name 및
activity-alias/targetActivity를 사용한다. 상대 이름을 정규화하고 리소스 참조 등
미해결 이름은 제외한다. disabled/unexported 선언도 힌트다. 패키지명이나 Manifest
일치만으로 앱 소유 코드·실행 가능한 진입점·취약점을 확정하지 않는다.
Manifest 조회/파싱 실패는 native로 되돌리고 진단을 저장한다. 취소는 폴백하지 않는다.
요청 정책은 provenance, 유효 정책은 program capabilities에 보존한다.
정책 및 선택 코드 해시는 캐시 키에 포함하며 폴백 진단도 캐시된다.

후속으로 종류별 **unit 간 전역** 우선순위를 구현했다(`GLOBAL_INDEX_PRIORITY.md`).
구형 결과의 unit 내부 정책은 그대로 표시한다. 상속 closure·콜백 메서드 우선순위·
호출 대상 본문 확보는 구현하지 않았다. 우선 클래스의 많은 메서드가 예산을 차지할 수도 있다.
수집되지 않은 선언/본문이나 검색 결과 공백으로 위험 부재를 결론내리면 안 된다.

## 실제 APK 검증 (2026-10-04)

아래 수치는 전역 선택 변경 전 unit 내부 정책의 역사적 검증 기록이다.

사용자 제공 amoremall.apk(83,771,204바이트), JEB 5.47, 힙 2GiB,
본문 8MiB, 종류별 선언 1,000개/인덱스 계수 1MiB, 시간 180초·합산 RSS 4GiB·
시스템 여유 1GiB guard. 원본 APK와 사용자 설정은 수정하지 않았다.
결과: `build/large-apk-20261004-priority1000/amoremall/summary.json` 및 `project.json`.

분석 20.676초, 근거 조회/저장까지 88.447초, 합산 RSS 피크 2,660,274,176바이트.
guard 발동 없이 JEB가 닫혔다. 클래스·필드·메서드 선언 각각 1,000개, 본문 1,000개,
인덱스 계수 876,754바이트를 저장했다. 제외 클래스 41,032개, 필드 165,448개,
메서드 선언 285,211개이며 complete=false와 흐름 분석 제한 진단을 보존했다.
8,792,996바이트 프로젝트를 실제 로더로 재열어 정책·수집 수를 확인했다.

기존 native 1,000개 시험과 비교하면 Manifest 정확 일치 클래스가 0→109개,
package 접두어 일치 클래스가 0→934개다. 메서드 선언 1,000개 모두 Manifest
클래스 소속이고 그중 906개는 package 접두어와도 일치한다. 이 개수는 서로 겹친다.
두 실행은 수집 대상이 달라 시간이나 finding 개수를 동일 작업의 성능/정확도 비교로
해석할 수 없다. finding 76개는 확인된 취약점 76개라는 뜻이 아니다.

IntroActivity/onNewIntent 및 SchemeActivity/onCreate의 JEB 소스·AST·XREF·CFG를
조회했다. AST 호출 오프셋 각각 5개/16개가 DEX 오프셋과 일치했다. 이 두 근거 확인은
모든 finding 검증이나 앱 전체 분석 성공을 뜻하지 않는다.

## 회귀 및 다음 범위

전체 회귀 645 passed (96.25초), 실제 JEB 통합 15개 포함. 신규 12개로 안정 정렬,
경계 일치, Manifest 입력, 설정, 캐시 격리, 오류 폴백, 취소 전달 및 실제 Jython 선택을 검사했다.
wheel 재빌드와 두 신규 모듈의 패키지 포함을 확인했다. SHA-256:
`8fd831bf454addcdb55a06dd7ce8588fee7dcf494c90c1be390bddec5a3d0fbc`.
이번 단계에서는 독립 가상환경 설치 검증을 반복하지 않았다.
CLI 도움말은 UTF-8 출력에서 확인했다. 이 Windows 환경의 cp949 출력에서는 기존
도움말의 유니코드 범위 기호 때문에 인코딩 오류가 난다. PowerShell에서
`$env:PYTHONIOENCODING='utf-8'` 설정 후 조회할 수 있으며 CLI 출력 호환성 보강은 남아 있다.
후속으로 GUI 정책 선택과 요청/유효 정책 및 unit 내부 한계 표시를 구현했다.
전역 선택 후속 검증은 `GLOBAL_INDEX_PRIORITY.md`에 있다. 호출 대상 누락 계측/확장은 남아 있다.
