# PendingIntent 문맥 v2

2026-10-09. 기본 블록 내 Intent 할당/생성자, 레지스터 별칭, setAction/setPackage와
상수 flags를 함께 검사한다. getActivity(4/5인자), getBroadcast, getService,
getForegroundService의 정확한 정적 호출만 지원한다.

- AOS-IPC-005: 명시적 MUTABLE 플래그이며 component/package 제한이 없는 것으로 추적된
  Intent. IMMUTABLE 및 NO_CREATE가 있으면 이 후보를 만들지 않는다.
- AOS-IPC-006: MUTABLE과 IMMUTABLE이 동시에 설정된 구성 검토.

REVIEW/MANUAL_REVIEW/L2이며 공격 경로 또는 실제 생성/전달 성공을 주장하지 않는다.
005는 MEDIUM, 006은 INFO severity다. 미확정 flags/Intent, 알 수 없는 변경/분기,
블록 경계는 추적을 중단한다. 명시적 Context/Class 생성자와 확인된 package 제한은
005에서 제외한다. 이는 해당 PendingIntent가 전반적으로 안전하다는 뜻이 아니다.

target SDK 34 이상이고 unsafe implicit 허용 플래그가 없으면 MAY_REJECT_ON_API_34_PLUS를
표시한다. 실제 실행 OS를 모르므로 생성이 반드시 실패하거나 성공한다고 단정하지 않는다.
unsafe 허용 플래그 유무, 충돌 여부, 실행/공격자 접근 미확정을 validation에 기록한다.

v2는 Intent 복사 생성자의 독립적인 목적지 상태, setClass와 setClassName 두 오버로드의
확인된 클래스/이름 인자, setComponent(null)에 의한 component 제한 해제를 지원한다.
component를 해제해도 기존 package 제한은 유지한다. 알 수 없는 ComponentName/클래스 이름과
미확정 복사 원본은 암시적이라고 추정하지 않는다. 실제 대상 클래스 존재/권한은 검증하지 않는다.
원본 Intent 변경은 복사본의 목적지 상태를 바꾸지 않으며 레지스터 별칭 변경은 같은 객체에 반영한다.

미지원: flags 산술, flags 미지정의 SDK별 기본 mutability, getActivities 배열,
non-null ComponentName 구성, 함수/블록 간 Intent 추적, 기존 토큰 재사용,
외부 전달·권한·실제 실행 경로. 미지원 변경은 명시적/암시적으로 추정하지 않는다.

실제 JEB fixture에서 implicit mutable 및 충돌 양성, explicit/package 제한/immutable 음성을
검증한다. 단위 테스트는 별칭·fluent 결과·package null 제거·재대입·불명확한 변경·취소를 포함한다.
모든 APK는 정적 분석 전용이다.

후속 실제 JEB 검증: setClass 후 component 해제 양성, 암시적 Intent 복사 후 원본을 명시적으로
바꿔도 복사본 양성 유지, 명시적 Intent 복사 후 원본 component 해제 시 복사본 음성 유지.
setClassName의 Context/String 및 String/String 오버로드가 이 fixture에 포함된다.

[Android PendingIntent API](https://developer.android.com/reference/android/app/PendingIntent)의
mutability 및 Android 14 implicit Intent 제약을 근거로 한다.
