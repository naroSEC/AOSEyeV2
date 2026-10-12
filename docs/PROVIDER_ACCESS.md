# Provider 연산별 선언과 분석 진입점

기존 코드는 readPermission 또는 writePermission 중 하나라도 있으면 Provider의
모든 콜백을 제외했다. 이제 query는 읽기, insert/update/delete는 쓰기 선언을 각각
사용한다. 연산별 속성을 우선하고, 없으면 기존 provider/application permission을 사용한다.
리소스 참조는 UNKNOWN이며 명시적인 빈 문자열과 구분한다.

Manifest component.access_policy에 읽기/쓰기 값·상태·출처, 경로별 권한 및 URI grant
선언을 보존한다. Components 화면 및 프로젝트 JSON에서 볼 수 있다. entry_catalog는
저장된 파생 정책을 맹신하지 않고 원래 속성으로 계산하며 엔진/reviewer가 같은 계약을 사용한다.
분석 provenance의 정책 식별자에 provider-operations-v1을 추가했다.

path-permission이 있으면 URI 매칭과 권한 대안이 미해석이므로 불확실 진입점으로 남긴다.
openFile은 실행 시 모드, call은 구현 내부의 권한 검사가 필요하여 불확실로 분류한다.
불확실 진입점이 확정 무권한 진입점으로 승격되지는 않는다. 권한 요구를 이유로 제외한
콜백도 안전성 증명이 아니며, 실제 권한 강도/보유 여부/런타임 검사까지 판단하지 않는다.
비노출 Provider에 대한 임시 URI grant를 통한 접근은 아직 흐름 모델 밖이다.
기존 저장 분석을 열기만 해서는 새 정책으로 재분석되지 않는다.

양방향 비대칭 권한, application 상속, 명시적 빈 권한, 미해결 참조, 경로 규칙에 대한
합성 메서드/Manifest 회귀를 추가했다. 실제 Provider 실행이나 공격 성공 시험은 아니다.

## 불확실성 근거 전달

entry_catalog의 각 구성 기록에 configuration_reasons를 추가했다. 미해결 exported/enabled,
일반 권한 및 Provider의 경로 권한/파일 모드/커스텀 call 검사를 구분한다. Reviewer의
도달 경로에 해당 진입점 구성 근거를 포함하며 메서드당 최대 20개와 잘림 표시를 제공한다.
이는 기존 Review 근거 표시와 프로젝트 JSON에 전달된다. 불확실 콜백 인자의 흐름 라벨도
확정 외부 입력과 구분한다.

실제 Application 파이프라인에 합성 DEX DTO/텍스트 Manifest를 넣어 읽기 허용/요구,
미해결 권한/경로, openFile 및 call의 sink 흐름을 검증했다. 미확정 구성은 POTENTIAL,
L3(이 단일 메서드 fixture의 경우), POSSIBLE_ENTRY_PATH_FOUND이며 확정 attack_path는 없다.
프로젝트 저장/재열기에도 사유와 판정이 보존된다. 이 테스트는 실제 JEB Provider 실행이나
런타임 권한 우회 증명이 아니다.

## 실제 DEX 통합 검증

`tests/fixtures/provider/ProviderFixture.java`는 Android SDK의 ContentProvider를 상속하고
query/update/openFile/call 인자를 테스트 sink에 전달한다. JDK로 컴파일하고 설치된
JEB의 D8로 DEX를 생성한 뒤 aapt2로 만든 binary Manifest APK에 넣는다. 기존 flow fixture나
사용자 APK를 변경하지 않으며 APK는 설치·서명·실행하지 않는다.

`tests/test_jeb_provider.py`는 같은 DEX에 세 가지 Manifest를 적용한다: 쓰기만 권한 요구,
읽기만 권한 요구, 경로별 권한 선언. 실제 JEB에서 얻은 parameter register/명령어/CFG로
Application 전체 분석을 수행한다. 연산별 제외 여부, LIKELY/POTENTIAL 및 L5/L3 구분,
불확실 경로의 확정 attack_path 부재, 구성 불확실성 근거를 검사한다. sink의 DEX 오프셋과
타깃 일치, Review 표시 데이터, 프로젝트 전체 저장/재열기 일치도 확인한다.

증거: `build/jeb-provider-validation.json`. 이는 실제 JEB 정적 분석 검증이지 Android OS의
권한 집행, 임시 URI grant, 앱 설치 유효성 또는 공격 성공 검증은 아니다.
실행은 AOSEYE_RUN_JEB=1 및 AOSEYE_TEST_AAPT2를 지정한 후
`python -m pytest tests/test_jeb_provider.py -q`를 사용한다. Android SDK android-35 jar가
기본이며 AOSEYE_TEST_ANDROID_JAR로 대체할 수 있다. javac/java 및 설치된 D8가 필요하다.

설계 근거: [Android provider 선언](https://developer.android.com/guide/topics/manifest/provider-element),
[ContentProvider API](https://developer.android.com/reference/android/content/ContentProvider).
