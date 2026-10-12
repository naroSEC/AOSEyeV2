# FileProvider 및 백업 선언 검사

Manifest의 provider meta-data, path-permission, grant-uri-permission을 보존한다.
`android.support.FILE_PROVIDER_PATHS` 참조와 application의 `fullBackupContent`,
`dataExtractionRules` 참조를 제한된 XML 파서로 검사한다. GUI Storage Policy에서
저장된 선언 인벤토리를 확인할 수 있다.

FileProvider의 root-path, 넓은 경로 및 external-path는 REVIEW 후보로 표시한다.
메타데이터만으로 실제 provider 구현, URI grant 또는 민감 파일 노출을 증명하지 않는다.
백업 include/exclude와 전송 종류별 속성은 선언 그대로 보존하며 실제 파일 집합,
기기/OS별 적용, 암호화 지원 및 실행 중 데이터 이동은 판단하지 않는다.

명명된 단일 무조건 리소스는 직접 읽는다. 컴파일 XML 또는 숫자 ID는 기존 JEB
리소스 디코더를 사용하며 기본 구성만 확인했음을 진단에 남긴다. 중복·구성별 XML,
손상 ZIP, 미지원 루트/노드, DTD entity 및 해석 실패는 UNKNOWN이며 안전 판정하지 않는다.
최대 32개 참조, XML당 1MiB/2,000노드, 합계 4MiB, ZIP 100,000항목 제한을 둔다.
취소는 전파하며 기존 결과를 변경하지 않는다.

현재 테스트는 합성 XML/ZIP 및 디코더 대역으로 선언 해석을 검증한다. 실제 JEB
컴파일 XML 기반 경로는 기존 network XML 통합 시험으로 검증되어 있지만,
컴파일된 백업 XML의 로컬 재현 APK 종단 검증도 추가했다. 사용자 APK와 재현 APK의
검증 범위를 아래에서 구분한다. FileProvider의 후속 검증은 아래와 같다.

## 컴파일된 백업 XML 검증

제공된 MyAcademy, amospro_dev6, amoremall의 Manifest를 로컬 aapt2로 검사했다.
모두 allowBackup=false/fullBackupContent=false이고 dataExtractionRules 선언이 없으므로,
이 세 APK로 백업 XML의 성공적인 해석을 검증했다고 주장하지 않는다.

`tests/fixtures/backup`의 Manifest와 XML을 aapt2로 컴파일/링크한 뒤 기존 테스트 DEX를
넣은 미서명 APK로 JEB 및 AnalysisApplication 전체 경로를 검증한다. 설치·서명·실행하지 않는다.
fullBackupContent의 include/exclude/requireFlags, dataExtractionRules의 cloud-backup과
device-transfer 구분 및 disableIfNoEncryptionCapabilities 속성 보존을 확인했다.
이름 참조와 숫자 ID 참조의 결과가 일치하며 프로젝트 저장/재열기 후 인벤토리도 일치했다.
모든 결과에는 기본 구성만 확인했다는 진단을 유지한다. 실제 OS 백업/복원이나 민감 데이터
전송은 검증하지 않았다. 증거는 `build/compiled-backup-validation.json`이다.

구조 오류 검증 중 data-extraction-rules 안에 legacy full-backup-content를 허용하던
문제를 수정했다. 잘못된 전송 섹션, 중복 섹션, 미지원 domain 및 누락 path는 거부한다.
실행: AOSEYE_RUN_JEB=1 및 AOSEYE_TEST_AAPT2 설정 후
`python -m pytest tests/test_compiled_backup_config.py -q`.
기본 플랫폼은 aapt2가 속한 SDK의 android-35이며 AOSEYE_TEST_ANDROID_JAR로 명시할 수 있다.
기존 `tools/build_fixture.py`의 DEX 출력이 필요하다. 이 통합 시험은 필수 로컬 의존성이
없으면 skip하며, 이번 로컬 실행에서는 skip 없이 6개 시험이 통과했다.

## 파일명이 변경된 XML 연결 (2026-10-05)

amoremall의 첫 검사에서는 이름과 일치하는 ZIP 경로가 없어 2개 참조가 UNKNOWN이었다.
원본 기록 `build/large-apk-20261005-global5000/amoremall/storage-validation.json`은 보존했다.
실제 리소스 테이블 확인 결과 `@xml/provider_paths`는 ID `0x7f150003`/`res/zz.xml`,
`@xml/file_paths`는 ID `0x7f150000`/`res/8K.xml`이었다.

이제 **기존 aapt2 설정이 있는 경우에만**, 명명된 파일이 없는 참조에 이름→ID 조회를
적용한다. 단일 패키지/고유 이름을 확인하고 JEB 기본 구성 XML 조회의 ID와 구성도
검사한다. 별칭/중복 ID/잘못된 경로/크기 초과는 기존 JEB 검사에서 거부된다.
원래 이름의 중복 ZIP 항목이나 구성별 XML이 있으면 이름 매핑으로 우회하지 않는다.
설정이 없거나 조회에 실패하면 UNKNOWN을 유지한다. 사용자 설정은 자동 변경하지 않는다.
CLI에서는 `aoseye analyze <apk> -o <new-project.json> --aapt2-path <absolute-aapt2.exe>`로
이번 분석에만 지정할 수 있다. GUI의 기존 선택적 aapt2 설정도 저장소 이름 조회에 적용된다.
저장된 프로젝트를 여는 것만으로 과거 UNKNOWN 결과를 자동 재분석하지는 않는다.
리소스 ID, 이름 조회 출처, 패키지, 실제 경로를 저장하고 기본 구성만 확인했음을 명시한다.

원본 APK 해시를 검증한 뒤 저장 Manifest를 재파싱하여 실제 aapt2/JEB로 두 참조 모두
해석했다. 넓은 선언 3개는 REVIEW, `qgsdkres/` 제한 경로는 해당 경고 없음으로 기록했다.
결과: `build/large-apk-20261005-global5000/amoremall/storage-mapped-validation.json`.
이 검증은 저장소 설정만 재검사하며 원래 project.json이나 코드 분석 결과를 변경하지 않았다.
전체 기기 구성, 실제 grant 및 민감 파일 노출 검증은 아니다.

설계 근거:
- [Android FileProvider 위험 안내](https://developer.android.com/privacy-and-security/risks/file-providers?hl=en)
- [Android Auto Backup](https://developer.android.com/identity/data/autobackup?hl=en)

## 대용량 보고서 확인 (2026-10-05)

`build/large-apk-20261005-global5000/amoremall/project.json`은 83,771,204바이트 APK의
부분 분석 결과다. 실제 5개 DEX가 JEB의 1개 unit으로 병합되었으며, 종류별 선언
5,000개 한도에서 본문 4,951개를 보존했다. 실제 다중 unit 검증과는 구분한다.
HTML 309,626바이트, CSV 72,461바이트, 정규화 DEX JSON 33,096,442바이트를 출력했다.
JSON 재읽기에서 입력 SHA-256과 본문 개수가 일치했다. JSON 출력과 재읽기는 7.705초였다.
보고서 writer는 UTF-8 바이트를 누적 계산하므로 JSON 토큰마다 파일 위치 조회로
버퍼를 flush하지 않는다. 128MiB 상한, 취소 및 기존 파일 보존 계약은 유지한다.
