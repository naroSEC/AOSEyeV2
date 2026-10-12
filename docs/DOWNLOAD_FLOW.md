# 다운로드 기록 URI → 코드 로더 인자 v1

AOS-DYNAMIC-003: DownloadManager.getUriForDownloadedFile(long) 반환값을 시작으로
Uri.getPath()/toString(), String.concat, 기존의 제한적 함수 간 전파를 거쳐
DexClassLoader/PathClassLoader 생성자의 code-path 인자로 전달되는 경로를 기록한다.
별도 source 집합을 사용하므로 일반 Intent 입력을 다운로드 출처로 바꾸지 않는다.

항상 REVIEW/MEDIUM/MANUAL_REVIEW이며 attack_path를 만들지 않는다. URI 조회가 null인지,
URI의 path가 파일 경로인지, 원격 출처/무결성 검사/로더 생성/클래스 실행 여부는 UNKNOWN이다.
DownloadManager 기록 자체가 네트워크 다운로드를 증명하지는 않는다.
읽기/쓰기/다운로드/앱 설치/실행 또는 서버 접속을 수행하지 않는다.

untrusted flow → sensitive flow → download flow 순서로 남은 max_flow_steps를 공유한다.
새 패스도 취소/호출 깊이/루트별 예산을 따르고 별도 coverage/rule fingerprint를 저장한다.
예산 부족과 알 수 없는 변환은 진단이며 탐지 없음은 안전 증명이 아니다.

미지원: enqueue부터 ID 연결, 파일 내용/스트림 쓰기, OkHttp 등 다운로드 SDK,
ContentResolver의 실제 파일 경로 복원, 서명/해시 검증의 유효성, InMemoryDexClassLoader,
원격 바이트 실행 증명. Android API 제한이나 저장 정책은 수동 확인이 필요하다.

tests/test_download_flow.py 및 실제 JEB DownloadFixture.java로 양성, 다른 인자,
덮어쓰기, 다른 출처, 미확정 변환, 함수 간 연결, 취소·예산·저장 왕복을 검증한다.

공식 API 근거:

- [DownloadManager](https://developer.android.com/reference/android/app/DownloadManager#getUriForDownloadedFile(long))
- [DexClassLoader](https://developer.android.com/reference/dalvik/system/DexClassLoader)
