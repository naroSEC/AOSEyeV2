# 명시적 component 전달과 객체 필드 참조

2026-10-12. 기존 Activity ICC 및 Runnable 경계를 확장했다.

- 정확한 Context/ContextWrapper/Activity/Service startService, startForegroundService,
  sendBroadcast(Intent), sendBroadcast(Intent,String) 호출에서 명시적 Intent 대상과
  Manifest component 종류를 일치시킨다.
- service는 onStartCommand의 Intent 인자, receiver는 onReceive의 Intent 인자로
  같은 경로의 Intent extra를 전달한다. 비활성 component, 대상 미해결, 본문/인자 누락은
  연결하지 않는다. permission 인자가 있어도 런타임 전달 성공을 확정하지 않는다.
- Intent 복사 생성자와 상수 package/class setClassName을 지원한다. 복사본의 extra
  변경은 원본과 분리된다. implicit Intent, bindService, IntentService, 동적 receiver,
  ordered broadcast, PendingIntent 실행 경로는 이 모델이 해결하지 않는다.
- String/String setClassName은 Manifest와 달리 상대 클래스명을 확장하지 않는다.
  package가 분석 앱 Manifest package와 다르면 같은 클래스명이 있어도 연결하지 않는다.
- 추적 중인 Intent/Runnable/collection 객체의 iput-object→iget-object 참조를 유지한다.
  일반 Java heap 전체를 모델링하지 않으며 static object reference는 지원하지 않는다.
  필드 덮어쓰기와 알 수 없는 외부 호출은 참조 그래프를 순회해 기존 상태를 버린다.
  순환 참조는 visited 집합으로 제한하고 취소를 확인한다.

경계는 MODELED_POTENTIAL, runtime_delivery=UNKNOWN이다. lifecycle, 작업 순서,
background 실행 제한, component 권한 및 실제 실행을 입증하지 않는다. 연결된 경로와
callback 안에서 독립적으로 읽은 source 후보를 구분해야 한다. 예를 들어 Service this를
알 수 없는 생성자에 먼저 전달하면 연결된 Intent 상태도 보수적으로 무효화할 수 있다.
이 때문에 경계 inventory가 있어도 끝까지 연결된 sink 경로가 없을 수 있다.

test_component_delivery.py, test_object_field_refs.py, test_boundaries.py 및
test_jeb_tls.py의 실제 DEX fixture로 전달/복사/덮어쓰기/외부 전달/순환 참조를 검증한다.
테스트 APK는 설치하거나 실행하지 않는다.

API 구현 근거: AOSP Intent.setClassName 및 ComponentName(String,String):
https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/content/ComponentName.java
