# GUI JEB 연결 복구 검증

2026-10-02, Windows / Python 3.14.2 / JEB 5.47에서 검증했다.

## 변경

분석 프로젝트가 열린 상태에서는 연결 확인의 실패/성공 메시지가 기존 근거 화면을
덮어쓰지 않는다. 연결 상태와 stage로 결과를 표시하고 Finding 선택, 탭, 탐색 위치·이력,
참조 목록, Review 요약 및 분석가 메모를 유지한다. 새 JEB 경로로 backend를 교체해도
기존 정규화 program을 유지한다. 취소 직후 도착한 성공 응답은 Connected로 반영하지 않는다.

**JEB settings → Save & check connection**은 기존 의미대로 설정을 먼저 저장한 후 연결을
검사한다. 연결 실패 자체가 경로 저장을 되돌리지는 않는다. 잘못된 값 또는 저장 오류는
기존 설정 객체를 유지하며, 다른 작업 중에는 설정 변경 요청을 무시한다.

경로 변경 시 기존 JVM은 종료된다. 보존하는 것은 분석 결과/GUI 세션이지 이전 JEB
프로세스가 아니다. 연결 성공만으로 DEX/AST 등 모든 capability가 검증됐다고 표시하지 않는다.

## 검증

- mock 기반 7개: 연결 실패, 취소, 늦은 취소, 성공, 설정 저장 실패, 잘못된 경로 값,
  작업 중 요청 무시. 첫 6개는 기존 세션 보존 후 정상 재시도도 확인했다.
- 기존 실제 JEB/QML 통합 검사를 확장했다. fixture 분석 → Finding 및 메모 선택 →
  없는 JEB 경로 저장/실패 → 원래 경로 저장/재연결 → AST/XREF/디컴파일·탐색을 확인했다.
- 실패 직후와 복구 후 화면/위치/이력·결과·메모 보존, 이전 JVM 종료,
  저장된 경로 및 교체 backend의 program 일치를 확인했다.
- 전체 회귀: **358 passed (53.09초)**, 실제 JEB 통합 5개 포함.

```powershell
python -m pytest tests/test_backend_recovery.py -q
$env:AOSEYE_RUN_JEB = '1'
python -m pytest tests/test_gui.py::test_live_gui_jobs_share_backend -q
```

테스트의 설정/캐시는 임시 LOCALAPPDATA에 저장한다. 사용자 설정은 수정하지 않는다.
실제 통합 검사는 offscreen QML과 GUI controller 슬롯을 사용한다. 마우스로 설정 대화상자를
조작한 수동 인수, 사용자 APK 재분석, 라이선스 만료, 장시간/대형 앱 재연결 검증은 아니다.
대형 프로젝트 로딩의 기존 UI 지연과 RSS 잔류도 이 변경으로 해결했다고 주장하지 않는다.

갱신 wheel SHA-256:
`c174532778485f34641346c04fec1f7213ca0b0b618ee2d64da13e882c62321b`.
독립 가상환경 wheel 설치/자원/CLI/GUI smoke/JEB probe·inspect/분석·재열기 10개 검사도
통과했다. 로그는 `C:\validation-temp\aoseye-wheel-lapw7lll`에 있다.
실패 직후 보존 assertion 추가 후 실제 GUI/JEB 통합 단독 재실행도 통과했다 (18.66초).
