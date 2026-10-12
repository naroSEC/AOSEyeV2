# 같은 객체의 WebView 설정 / Editor 완료 호출 문맥

2026-10-12. receiver-context-v2-bridge-registration은 새 취약점을 API 존재만으로 생성하지 않는다.
기존 AOS-WEBVIEW-004/005/006 및 AOS-SENSITIVE-003 흐름에 추가 근거를 붙인다.
분석 수준·심각도·공격 경로·안전 판정을 자동 승격하거나 억제하지 않는다.

## WebView

동일 메서드에서 WebView.getSettings 반환→설정 setter→같은 receiver의
loadUrl/loadData/loadDataWithBaseURL/evaluateJavascript를 연결한다. JavaScript,
file/content access 및 file URL 접근 설정의 명시적 true/false/UNKNOWN을 기록한다.
기본값은 추정하지 않는다. 설정 호출 위치와 로딩 위치는 review.webview_context에 남는다.
다른 매개변수 객체가 런타임에 같을 가능성은 합치지 않으며 설정 변경 시 다른 객체의
기록을 버린다. 로딩 뒤에는 callback 부작용을 고려해 설정 사실을 버린다.

같은 객체의 addJavascriptInterface→로딩 호출도 연결한다. 상수 이름(최대 256자)별
최대 32개 등록을 추적하고 같은 이름 removeJavascriptInterface는 해당 후보를 제거한다.
등록 이름/객체 값은 결과에 저장하지 않으며 등록 DEX offset만 남긴다. 다른 객체의
변경, 알 수 없는 이름/외부 호출, 로딩 이후에는 보수적으로 기존 사실을 버린다.
webview_bridge_registration=MODELED는 등록 호출 연결이며 object null 여부, 노출 메서드의
@JavascriptInterface, targetSdk/실행 API, 페이지/iframe origin, 런타임 호출은 UNKNOWN이다.
JavaScript DISABLED도 결과를 지우거나 안전으로 승격하지 않는다. 삭제 호출 역시 이미
실행 중인 페이지의 노출 해제를 증명하지 않는다.

## SharedPreferences.Editor

민감 값 putString finding에서 같은 Editor의 뒤따르는 apply/commit 호출을 연결한다.
move 별칭과 putString의 fluent 반환은 지원한다. 그 사이의 다른 put/remove/clear나
미모델링 호출은 이전 기록을 버린다. 마지막 쓰기만 인정하는 보수적 모델이다.
editor_flush_call=MODELED는 호출 연결이지 commit=true, 디스크 기록 성공, 암호화 부재,
외부 앱 접근 가능성의 증명이 아니다. persistence_or_exposure=UNKNOWN을 유지한다.

## 제한과 검증

완전한 선형 CFG, 예외 없음, 메서드 정규화 진단 없음, 최대 4,000명령만 지원한다.
분기/예외, 함수 간 객체 전달, 필드/배열을 통한 객체 회수, 사용자 override와 비동기
실행은 미지원이다. 미모델링 호출/메모리 쓰기는 연결 사실을 제거한다. 취소를 확인한다.
이는 해당 미지원 항목의 완성을 대신하지 않는다.

단위 시험은 같은/다른 객체, 별칭, true→false, 알 수 없는 값, overwrite, wide write,
임의 호출, 필드 쓰기, 불완전 CFG, 잘못된 인자 수, Editor 후속 변경과 저장 왕복을 다룬다.
실제 JEB 시험은 Java fixture를 DEX로 변환해 설정 enabled/disabled/다른 WebView와
AccountManager 반환→putString→apply를 검사한다. APK를 설치하거나 실행하지 않는다.

API 계약 참고:
- https://developer.android.com/reference/android/content/SharedPreferences.Editor
- https://developer.android.com/reference/android/webkit/WebSettings
- https://developer.android.com/reference/android/webkit/WebView
