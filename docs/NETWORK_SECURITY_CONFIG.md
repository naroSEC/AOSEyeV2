# Network Security Config: 초기 cleartext 분석

2026-10-03 추가. 이번 구현은 **텍스트 XML의 cleartext 정책 목록**이다.
일반적인 컴파일된 APK 리소스 해석이나 전체 TLS 정책 분석이 완료된 것은 아니다.

지원하는 입력은 Manifest의 `@xml/name`과 APK 내 유일한 `res/xml/name.xml` 텍스트 XML이다.
base-config 및 중첩 domain-config의 cleartext 값 상속, 도메인과 includeSubdomains,
target SDK별 기본값을 기록한다. 도메인별 최종 호스트 매칭 함수는 아직 제공하지 않는다.
target SDK가 미확정이면 기본 허용 여부는 null이며 안전 판정으로 바꾸지 않는다.

정책 결과는 `manifest.network_security_config`에 저장돼 Manifest 화면 및 JSON 프로젝트로
확인할 수 있다. 허용 설정은 REVIEW 후보이며 실제 민감정보 전송 또는 취약점 확정이 아니다.
NSC가 선언된 앱의 Manifest cleartext=true는 독립 WEAKNESS 대신 OS/설정 검토 대상으로
분류한다. Android API 24 미만의 동작까지 이 결과로 단정하지 않는다.

숫자 리소스 ID, 리소스 alias, xml-v* 등 구성별 후보, 중복/누락 파일, 컴파일된 XML,
리소스를 참조하는 boolean, 잘못된 XML은 UNKNOWN과 진단으로 남겨 부분 분석을 표시한다.
리소스를 파일로 추출하지 않는다. 읽기 1MiB, ZIP 항목 100,000개, 압축률 1,000배,
XML 노드 2,000개와 domain-config 깊이 32 제한 및 취소 확인을 적용했다.
XML entity 확장은 거부한다. Android 전체 스키마/설치 유효성 검증은 아니다.

## 근거와 검증

정책의 상속/default 및 NSC와 Manifest 플래그 관계는 Android 공식 문서를 확인했다:
[Network security configuration](https://developer.android.com/privacy-and-security/security-config),
[application element](https://developer.android.com/guide/topics/manifest/application-element.html).

17개 회귀: 정책 상속/override, SDK 기본값, 이름 참조, binary/누락/변형/숫자 참조,
malformed XML/boolean 참조/중복 domain/entity, 취소, Manifest 경고 문맥,
전체 application pipeline 및 JSON 저장/재열기. 임시 ZIP과 mock DEX backend 기반이며
실제 사용자 APK의 보안 재분석을 수행한 것은 아니다.

다음 우선 작업은 JEB를 통한 컴파일 XML 및 resources.arsc의 숫자 ID/이름 연결이다.
그 뒤 기기 구성별 선택, 호스트별 가장 구체적인 정책 선택, trust anchors/debug overrides,
pinning 등 별도 TLS 정책 모델을 단계적으로 추가한다. 이번 변경으로 HTTPS 안전성을
확정하거나 라이브 네트워크 요청을 수행하지 않는다.

wheel SHA-256:
`d27763d6a3395073d9e4ece5ca4fec6fd9e90f9b09566c76f697b7d0235742df`.
최종 전체 회귀: 실제 JEB 통합 5개 포함 **402 passed (47.62초)**.
wheel 빌드를 확인했고 이번 변경의 별도 가상환경 설치 검증은 반복하지 않았다.

## 후속: 실제 컴파일 XML 및 숫자 ID (2026-10-03)

JEB 5.47의 설치된 JAR (`javap`) 및 동봉 `doc/apidoc.zip`을 확인해
IApkResourcesInfo/IApkResEntry/IApkResValue와 IUnitProcessor API를 사용했다.
`getResourcesByType(packageId, "xml", "")`의 기본 구성 XML 목록에서 숫자 ID를 찾고,
string 타입의 실제 ZIP 경로를 얻는다. `@0x7f…` 및 8자리 `@7f…` 참조를 지원한다.
alias/복합 값/모호한 매칭은 추정하지 않는다.

리소스 ZIP 항목은 크기/압축률/중복 경로를 검사하고 메모리에서 읽는다. JEB BytesInput으로
처리하며 디스크에 추출하지 않는다. JEB는 검증한 APK에서 `arsc` unit의 text presentation으로
XML을 제공했다. IXmlUnit이 있으면 해당 문서를 사용하며, 조회 후 임시 unit을 제거한다.
임의 JEB 표시 문자열은 정책으로 신뢰하지 않고 기존 defusedxml 파서/루트 검사/예산을 거친다.

결과는 **PARSED_DEFAULT_CONFIG**로 구분하고 기본 구성만 해석했다는 진단을 항상 남긴다.
이에 따라 전체 분석은 부분 분석으로 유지된다. 기기별 구성, trust anchors, pinning의
완료나 안전성을 의미하지 않는다. 원본 파일 해시를 검증하고 worker 취소/시간 제한을 사용한다.
이름으로 직접 찾는 compiled XML도 지원하지만, 이름과 실제 난독화 ZIP 경로가 다르면서
숫자 ID를 알 수 없는 경우의 이름→ID 해석은 아직 지원하지 않는다.

### 실제 검증

- MyAcademy의 `0x7f130001` → `res/oS.xml` → `<paths>` 디코딩을 확인했다.
  이것은 FileProvider XML의 디코딩 확인이며 NSC 정책이나 provider 취약점 판정이 아니다.
- amospro_dev6의 `@xml/network_security_config`와 해당 숫자 ID가 동일한 XML을 반환했다.
  기본 구성에서 base cleartext=false와 2개 도메인의 true 예외를 읽었다.
  앱 실행·네트워크 접속·사용자 APK 변경은 하지 않았다.
- 실제 JEB를 포함한 선택 검사 26개가 통과했다. 숫자/이름 조회, 기본 구성 표시,
  디코더 실패·잘못된 루트/경로·취소 및 qualifier 거부가 포함된다.
- 기록: `build/compiled-network-validation.json`. 리소스 해석만 새로 검증했으며,
  두 앱의 전체 DEX/보안 분석을 새로 실행한 결과는 아니다.

재현 도구:
`python tools/inspect_apk_resources.py <apk> [--reference @0x7f120006] [-o <new-report.json>]`.
output은 기존 파일을 덮어쓰지 않는다.
이 도구는 리소스 목록 및 NSC 정책을 조회하며 APK를 설치/실행하지 않는다.

갱신 wheel SHA-256:
`85d1bf975ed91cb4eef4e87dedd8358b0d5d3da9bd2e8ae3498e9e79bf124efc`.
최종 전체 회귀는 실제 JEB 통합 6개 포함 **411 passed (66.06초)**였다.
wheel 빌드를 확인했으며 새 가상환경 설치 검증은 이번에 반복하지 않았다.

## 후속: 호스트별 cleartext 정책 선택 (2026-10-03)

`select_cleartext_policy`는 이미 해석된 NSC 정책에서 호스트의 정확 일치 또는
includeSubdomains의 점 경계 suffix 일치를 찾고, 가장 긴 도메인을 선택한다.
일치 규칙이 없으면 base 값을 사용한다. 이 우선순위는 위 Android 공식 문서를 확인했다.
내부 domain-config의 상속 값은 앞 단계 파서의 결과를 사용한다.

결과는 PERMITTED / NOT_PERMITTED / UNKNOWN과 선택된 domain, EXACT/SUBDOMAIN/BASE,
구성 범위를 제공한다. NOT_PERMITTED는 제공된 구성에서의 값이지 통신 차단이나 HTTPS
안전성 증명이 아니다. PARSED_DEFAULT_CONFIG 입력의 기기별 구성 미해석 한계를 유지한다.
DNS 조회나 네트워크 연결은 하지 않고 Finding의 심각도/검증 등급을 바꾸지 않는다.

bare ASCII DNS host만 지원한다. URL, 포트, wildcard, IP, Unicode/IDN, trailing dot,
잘못된 label 및 미해결/중복/잘못된 정책은 UNKNOWN으로 남긴다. 대소문자는 무시한다.
고급 URL canonicalization이나 Android 네트워크 스택의 모든 입력 해석을 모사하지 않는다.

```powershell
# 원본 APK/JEB 없이 저장 프로젝트 조회
python tools/query_network_policy.py C:\reports\project.json --host example.com --host api.example.com
# JEB 리소스 확인과 함께 조회 (결과 파일은 새 경로 지정)
python tools/inspect_apk_resources.py C:\samples\app.apk --host example.com -o C:\reports\resources.json
```

28개 회귀는 최장 일치, 상속 예외, 정확 일치만 허용하는 규칙, suffix 공격형 문자열,
대소문자, 지원하지 않는 host, 미해결/중복 정책 및 원본 정책 불변을 확인한다.
GUI 입력창은 아직 추가하지 않았다.

새 사용자 제공 `amoremall.apk`(83,771,204 bytes, 약 83.8MB)의 JEB 리소스 조회도 수행했다.
이번에 읽은 Manifest에는 networkSecurityConfig 참조가 없어 정책을 추정하지 않았고,
임의 검사 호스트 example.com의 결과는 UNKNOWN이다. 이것은 해당 앱의 cleartext가
허용되거나 차단된다는 뜻이 아니다. 기록은 `build/amoremall-resources-20261003.json`이다.
앱 설치/실행/외부 서버 접속 및 전체 DEX/보안 재분석은 하지 않았다. 100MB 이상 시험도 아니다.

wheel SHA-256:
`7cf0e4e94fb66ed2bf19a54c82c9255980c6ebfcc13976fb817d32410a054d5d`.
전체 회귀는 실제 JEB 6개 포함 **439 passed (48.59초)**, wheel 빌드 성공이다.
이번 wheel의 새 가상환경 설치 검증은 반복하지 않았다.

## GUI 저장 정책 조회 (2026-10-03)

왼쪽 **Network Policy** 메뉴에서 bare DNS host를 입력하고 **Check host** 또는 Enter를
사용한다. 결과에 선택한 domain/매칭 방식/허용 여부, Manifest 참조와 리소스 파일 경로,
기본 구성 제한을 표시한다. **Saved policy**는 저장된 정규화 정책 목록으로 돌아간다.
원본 XML을 여는 기능이나 정확한 XML 줄 번호 연결은 아니며, 화면에서도 이를 명시한다.

조회는 저장된 프로젝트만 사용하며 APK/JEB/DNS/네트워크 접근이 없다. 기존 Finding,
메모, 원본 정책은 바꾸지 않는다. 없는 정책과 지원하지 않는 입력은 UNKNOWN으로 표시하고
다른 작업이 진행 중이면 조회를 무시한다. 정책 화면에서는 선택된 Finding의 심각도 배지와
공격 경로를 숨겨 호스트 정책의 판정으로 오인하지 않도록 했다. Finding 선택 자체는 보존한다.

추가 회귀 6개: 허용/불허/접미사 경계/잘못된 입력, 기존 분석·메모 불변, 프로젝트 저장·재열기,
없는 정책/작업 중 요청/다른 섹션 요청 무시, QML 입력과 버튼 신호 및 offscreen 렌더링.
스크린샷: `build/gui-network-policy.png`. 테스트가 실제 실행과 동일한 폰트 초기화를 적용하도록
보강한 뒤 이미지를 확인했다. 수동 사용자 클릭 인수를 대체하지 않는다.

전체 회귀 **445 passed (45.86초)**, 최종 표시 조정 후 GUI 선택 검사 **13 passed, 1 skipped**.
skip은 선택 실행에서 AOSEYE_RUN_JEB를 설정하지 않은 실제 JEB 테스트이며 전체 실행에서는
실제 JEB 통합 6개가 통과했다. wheel 빌드 SHA-256:
`daad0b3177353bbf0eb13d5c7916ee7fdff3ca4a1a80009ad8cc52f12c78f974`.
별도 가상환경 설치 검증이나 사용자 APK 추가 재분석은 이번에 반복하지 않았다.

## Trust anchors / debug overrides (2026-10-03)

`network_trust.py`에 신뢰 소스 목록 분석을 추가했다. 기본 및 domain-config의
trust-anchors는 상속하되 명시된 자식 목록으로 재정의한다. system/user/리소스 참조/UNKNOWN을
구분한다. target SDK의 일반 기본값을 모델링하되 privileged 앱과 플랫폼 차이는 미검증이다.
리소스 참조는 인증서 파일의 존재·내용·유효성을 증명하지 않으며 NOT_INSPECTED로 표시한다.

debug-overrides는 별도 선언 목록과 적용 여부를 유지한다. debuggable=true일 때 추가하고,
false이면 합산하지 않으며 미해결 참조이면 적용 여부와 합산 결과를 unknown으로 남긴다.
overridePins의 명시 값과 일반/debug 영역 기본값을 구분한다. 이것은 설정상의 조건부
pin override이며 실제 pin-set 존재·인증서 체인·런타임 우회 가능성을 확인한 것이 아니다.
공식 기준: [Android Network security configuration](https://developer.android.com/privacy-and-security/security-config).

저장 정책의 `trust`와 host 조회의 `selection.trust`에서 선언/상속된 목록, 디버그 조건,
합산 목록 및 한계를 볼 수 있다. 따라서 기존 GUI Saved policy/Check host와 CLI에도 표시된다.
명시적 사용자/사용자 지정 CA 또는 pin override 검토 항목은 REVIEW로만 생성한다.
비활성 debug 소스만을 이유로 검토 finding을 만들지 않는다. 미해결 값/CA 미검증은 진단으로
남기며 전체 TLS 안전성이나 실제 취약점으로 승격하지 않는다.

15개 신규 회귀: SDK 기본값, 디버그 적용/비적용/미확정, 목록 재정의/상속/빈 목록,
리소스 참조와 overridePins 불확실성, pipeline·host 조회·REVIEW 문맥, 구조 오류 및 취소.
구조 오류 시 PARSED 표시가 남지 않도록 결과 반영 순서도 보강했다.
기존 저장 프로젝트에는 trust 정보가 없을 수 있으며 원본 없이 새 정보를 만들어내지 않는다.
새 정보가 필요하면 다시 분석해야 한다.

갱신 wheel SHA-256:
`3386c444cc49af8f06f3bf33a73e40efc08bb5340bc5e6cc9c2020e17f03cd15`.
최종 전체 회귀는 실제 JEB 6개 포함 **460 passed (47.37초)**였다.
wheel 빌드를 확인했으며 별도 가상환경 설치나 사용자 APK 전체 재분석은 반복하지 않았다.

## pin-set 목록·형식·만료일 검토 (2026-10-03)

`network_pins.py`는 domain-config의 pin-set 선언과 중첩 상속/재정의를 기록한다.
SHA-256, 엄격한 Base64 형식 및 디코딩 결과 32바이트를 검사하며, 동일 값의 중복을
제거한 개수를 별도로 제공한다. 핀 64개/선언, XML 2,000 노드/깊이 32 예산과 취소 검사를
적용한다. 값이 너무 길면 표시를 256자로 제한하고 truncated/UNKNOWN으로 기록한다.
지원하지 않는 알고리즘·리소스 참조·형식 오류는 올바른 핀으로 간주하지 않는다.

expiration의 날짜 형식을 검사하고 분석 당시 UTC 기준일을 `as_of_date`에 저장한다.
날짜 이전/이후/만료일 당일/만료일 없음/미해결을 구분한다. 당일은 기기 시간대 및 시각의
경계를 확정하지 않고 EXPIRATION_DAY_UNCERTAIN으로 남긴다. GUI·CLI host 조회는 저장된
기준일을 보여주며 현재 시각으로 자동 재판정하지 않는다. 최신 판단은 재분석이 필요하다.

기준은 [Android 공식 NSC 문서](https://developer.android.com/privacy-and-security/security-config)를
확인했다. 핀 부재는 취약점이나 코드 수준 pinning 부재의 증명이 아니며, 서로 다른 값이
여럿 있어도 사용 가능한 backup pin을 증명하지 않는다. 실제 인증서 SPKI 일치와 TLS 적용,
trust override에 따른 조건부 적용 여부는 확인하지 않는다. 기존 trust 정보를 함께 제공한다.

만료일 경과/당일, 빈·중복·미해결 선언은 REVIEW로만 기록한다. 설정 문법 오류가 곧
런타임 pinning 우회라는 뜻도 아니다. host 선택 결과에 `pinning`이 추가돼 기존 GUI/CLI에서
볼 수 있으며, 과거 저장 프로젝트에 pinning이 없으면 없는 정보를 만들어내지 않는다.

신규 18개 회귀: 날짜 경계/잘못된 날짜, 알고리즘·Base64·길이, 상속·빈 override·중복,
host 조회·프로젝트 저장/재열기의 기준일 보존, 취소 및 허용되지 않는 구조.
기존 trust 검사와 합친 33개 선택 테스트가 통과했다.

최종 전체 회귀는 실제 JEB 6개 포함 **478 passed (47.13초)**였다.
갱신 wheel SHA-256:
`79e7c74d6d427580ca91560d8e117f17aa846219917d419d67c33368c4fc9e10`.
wheel 빌드를 확인했으며 별도 가상환경 설치나 사용자 APK 전체 재분석은 반복하지 않았다.
다음 작업은 CA 리소스 참조의 파일 연결·형식 확인이다.

## CA 리소스 경로 후보·X.509 형식 검사 (2026-10-03)

`network_certificates.py`는 명명된 `@raw/name`에 대해 `res/raw/name` 또는 단일 확장자
파일 후보를 확인한다. 리소스 테이블에 의한 연결 증명은 아니므로 `NAMED_PATH_CANDIDATE`로
표시한다. 숫자 ID·alias·난독화 경로는 미해결이며 qualifier, 중복 ZIP entry,
동일 이름의 여러 확장자 후보가 있으면 UNKNOWN이다. ZIP을 디스크에 추출하지 않는다.

후보 바이트는 cryptography X.509 파서로 검사한다. PEM 인증서 묶음 및 단일 DER를
지원하고 인증서 수·중복을 제외한 수·SHA-256 지문, 파일 SHA-256을 기록한다.
PEM의 부가 텍스트/비인증서 블록, DER 뒤의 데이터는 보수적으로 거부한다.
X509_PARSED는 CA 적합성, 유효기간, 서명, 체인, pin 일치 또는 Android 수용의 증명이 아니다.
만료된 인증서도 형식 검사에서는 정상 파싱될 수 있다. 외부 TLS 연결은 수행하지 않는다.

ZIP entry 100,000개, 고유 참조 32개, 파일당 1MiB, 전체 읽기 4MiB,
압축률 1,000배, 파일당 PEM 인증서 64개로 제한한다. 파일별 실패는 해당 참조에 남기며
cleartext/pin 정책을 지우지 않는다. 순회·읽기 후·인증서 사이 취소를 확인한다.
debug-overrides의 비활성 선언도 목록 검사는 하되 활성 trust로 승격하지 않는다.

결과는 anchor의 `resource_inspection`에 저장되고 GUI·CLI host 조회 및 프로젝트 재열기에
그대로 제공된다. 과거 프로젝트에는 정보를 소급 생성하지 않는다. 원문 인증서는 저장하지 않는다.
새 런타임 의존성은 `cryptography>=48,<49`이며 wheel 설치 검증에도 포함했다.

근거: [Android NSC 문서](https://developer.android.com/privacy-and-security/security-config),
[cryptography X.509 API](https://cryptography.io/en/latest/x509/reference/).
신규 26개 테스트는 PEM/DER, 잘못된 입력, 중복·대체 경로, 개수·개별/합계 읽기 예산,
취소, 저장/재열기 및 호스트 조회를 다룬다. trust/pin 기존 회귀와 합쳐 59개가 통과했다.
다음 단계는 JEB 리소스 테이블 기반 숫자 raw ID·실제 파일 경로 연결이다.

최종 전체 회귀: 실제 JEB 6개 포함 **504 passed (47.15초)**.
wheel SHA-256: `2068b91fcf703dc4573d79844bbe52c8ea18082365d1f2290d230d1ef7bc854e`.
새 외부 가상환경에 설치하여 의존성·설치 파일·CLI·GUI·JEB probe/inspect/분석·재열기
총 10개 검증이 통과했다. 보고서:
`C:\validation-temp\aoseye-wheel-q2n9i4p0\validation.json`.
사용자 APK 전체 재분석이나 앱 실행은 하지 않았다.

## 숫자 raw ID의 JEB 기본 구성 연결 (2026-10-03)

JEB `getResourcesByType(packageId, 'raw', '')`로 기본 구성 raw 목록을 얻고,
`resolve_ca_resource`가 숫자 ID를 단일 단순 문자열 경로에 연결한다. XML 목록과 raw
목록은 분리한다. alias, complex 값, 중복 ID, 누락은 UNKNOWN으로 남긴다.
목록은 4,096개까지이며 호출 시 기존 APK 해시 검증과 취소 경로를 사용한다.

APK의 해당 경로가 정확히 하나 존재하는지 확인한 다음 기존 CA 바이트 검사로 넘긴다.
경로 탈출·절대 경로·역슬래시·빈 경로 요소·NUL을 거부하며, 기존 1MiB/파일,
4MiB/분석, 32개 참조, 압축률 제한을 유지한다. 동일 참조는 분석 내 한 번만 해석한다.
CA 연결 실패가 cleartext/pin 분석 결과를 지우지 않으며 취소는 전파한다.

`RESOURCE_TABLE_DEFAULT`, `default-only`, 원본 resource ID·경로를 저장한다.
정상 X.509 파싱은 `DEFAULT_RESOURCE_X509_PARSED`로 표시하지만 기기별 선택이나
체인/TLS 검증을 의미하지 않는다. 명명된 `@raw/name`은 여전히 경로 후보 검사이며
숫자 ID 연결과 구분한다. 저장 프로젝트의 GUI/CLI 호스트 조회에도 이 정보가 유지된다.

amospro 사용자 APK의 raw 항목 하나에 대해 실제 JEB 숫자 ID 연결과 ZIP 경로의 단일
존재를 확인했다. 이 임의 raw 항목을 CA라고 분류하거나 전체 앱 보안을 재분석한 것은 아니다.
합성 DER 인증서로 숫자 참조→파싱→저장→호스트 조회를 별도 검증했다.
다음 단계는 명명된 raw 참조의 리소스 테이블 이름 기반 연결이다. alias와 기기별 구성,
인증서 체인 및 런타임 TLS 검증은 계속 미완료다.

숫자 ID 단계 전체 회귀: **532 passed (55.41초)**, 실제 JEB 7개 포함.
wheel SHA-256: `d4043cd4f6b306d0a0a42bc6e603686667847f33efcd12fa79da34873c7ba7b3`.
이 wheel은 빌드만 확인했으며 독립 가상환경 설치는 앞선 CA 형식 검사 단계의 기록이다.

## 명명된 raw 참조 교차 확인 진단 (2026-10-03)

설치된 JEB 5.47의 `IApkResourcesInfo`, `IApkResEntry`, `IApkResPackage` 공개 시그니처를
javap로 확인했다. entry 이름 getter가 없으므로 이름 기반 API를 가정하지 않았다.
`tools/inspect_raw_name.py`는 명시한 로컬 Android SDK aapt2로 이름→ID를 얻은 뒤,
JEB로 동일 ID의 기본 파일 경로를 연결한다. APK 해시를 전후 확인한다.

예: `python tools/inspect_raw_name.py <apk> --aapt2 <trusted-aapt2.exe> --reference @raw/name -o <new-report.json>`.
단일 패키지·정확한 이름 하나만 수용하며 중복 이름, 다중 패키지, 미지원 출력 형식은
실패 처리한다. aapt2 실행은 shell 없이 수행하고 30초/출력 16MiB 제한을 적용한다.
임시 파일 출력을 주기적으로 검사하므로 디스크 사용의 엄격한 순간 상한을 보장하지는 않는다.
취소/실패 시 프로세스를 정리하며 APK를 설치하거나 실행하지 않는다.

실제 amospro 샘플과 SDK build-tools 35.0.0에서 `@raw/zxing_beep` → `0x7f0d0002`
→ `res/raw/zxing_beep.ogg`를 확인했다. 형식 검사는 이 비인증서 입력을 UNKNOWN으로
남겼다. 이는 앱이 이 파일을 CA로 선언한다는 뜻이 아니다. 결과 파일은
`build/raw-name-zxing-validation.json`이다.

이 경로는 **명시 실행 진단 도구**이며 아직 자동 분석/GUI에는 통합하지 않았다.
사용자별 SDK 경로를 하드코딩하거나 aapt2를 배포물에 번들하지 않는다.
다음 단계는 선택적 aapt2 설정과 자동 분석 연결, 설치 환경 오류 처리 검증이다.

진단 도구 신규 13개 회귀(이름/패키지 모호성·출력 예산·프로세스 실패·취소 정리) 포함
전체 **545 passed (69.94초)**. 실제 JEB 통합은 7개이며 이름 기반 실제 APK 진단은
위 보고서의 별도 수동 CLI 실행으로 확인했다. 진단 도구는 저장소 도구이므로 wheel에는
포함되지 않는다. wheel은 앞선 숫자 ID 단계의 빌드 그대로이며 이 단계에서 재설치하지 않았다.

## 선택적 aapt2 자동 분석·GUI 연결 (2026-10-03)

`Settings.aapt2_path`는 기본값이 빈 문자열인 선택 설정이다. 기존 설정 JSON은 그대로
읽히며, 지정한다면 절대 파일 경로만 허용한다. GUI Backend settings에서 별도 저장하거나
`aoseye analyze <apk> -o <project.json> --aapt2-path <absolute-executable>`로 이번 분석에만
지정할 수 있다. CLI의 빈 문자열 값은 저장 설정을 이번 실행에서 비활성화한다.
사용자의 SDK 실행 파일을 명시적으로 선택하며 다운로드/자동 검색/번들하지 않는다.
GUI 저장은 실행 파일 존재를 확인하지만 버전/신뢰성/실행 성공을 인증하는 절차는 아니다.

자동 분석은 활성화된 경우 `@raw/name` → aapt2 ID → JEB 기본 raw 경로 → 제한된
인증서 형식 검사로 이어진다. 비활성화 시 기존 명명된 경로 후보 검사로 돌아간다.
활성화된 도구가 없거나 실행/이름 조회가 실패하면 해당 source는 UNKNOWN이며 경로 추정으로
조용히 대체하지 않는다. cleartext/pin 결과는 유지한다. aapt2 전후 APK 해시를 재검사한다.
이름 도구를 패키지의 `analyzer.backends.raw_names`로 옮겨 wheel에도 포함했으며 기존
`tools/inspect_raw_name.py` 진입점은 호환 래퍼로 남겼다. 실행은 `python -m analyzer.backends.raw_names`도 가능하다.

GUI 설정 저장 실패/작업 중 변경은 기존 설정과 분석 결과·메모·근거를 보존한다.
성공한 변경은 새 분석에만 적용하며 저장된 정책을 다시 계산하지 않는다. 화면 검증:
`build/gui-aapt2-settings.png`. 설정 도구 자체는 Qt 없이도 사용할 수 있다.

검증: 신규 21개를 포함해 **566 passed (80.46초)**, 실제 JEB 통합 8개 포함.
QML 설정 입력/저장 버튼·오류 표시를 포함한 GUI 선택 테스트 6개도 별도 통과했다.
실제 amospro의 raw 이름/숫자 ID 경로 일치는 기존 로컬 aapt2 35.0.0으로 확인했다.
테스트에서 `AOSEYE_TEST_AAPT2`를 명시했으며 사용자의 실제 settings.json은 변경하지 않았다.
동일 참조는 분석 내 재사용하지만 서로 다른 이름에는 aapt2 dump를 각각 실행한다.
대용량 APK에서 이름별 반복 실행 비용과 전체 분석 성능은 별도 검증이 필요하다.

wheel SHA-256: `8622e54e826768f7c6925d714481370ad23f1bfe0fe9b2b62df1b6e0663a6052`.
다음 단계는 제공된 대용량 APK의 자동 분석 경로와 자원 사용 검증이다.

최종 wheel 독립 가상환경 설치 검증 10개도 통과했다. 보고서:
`C:\validation-temp\aoseye-wheel-nhe0n10y\validation.json`.
설치된 패키지의 `python -I -m analyzer.backends.raw_names`로 실제 aapt2/JEB 이름 연결을
추가 실행해 성공했다. 결과는 같은 디렉터리의 `raw-name-installed.json`이다.
이는 임의 raw 파일 연결 검증이며 사용자 APK의 전체 보안 분석은 아니다.

## JEB JVM 힙 예산 설정 (2026-10-03)

`Settings.jvm_heap_mib`는 512~16,384MiB 정수이며 기본값은 기존과 같은 4,096MiB다.
GUI Backend settings의 JEB heap 입력 또는 `aoseye analyze ... --jvm-heap-mib 2048`로
지정한다. CLI 옵션은 해당 실행에만 적용한다. 힙은 Java 객체 메모리 한도이며 네이티브
메모리·코드 캐시·Python을 포함한 전체 RSS 제한이 아니다.

GUI 저장은 기존 근거/메모를 보존하며 다음 실제 JEB 요청에서 설정이 달라졌으면 JVM을
재시작한다. 저장된 결과 조회만으로 JEB를 시작하지 않는다. 분석 provenance에는
`jvm_heap_limit_mib`가 기록된다. 입력/예산 변경은 결과의 완전성을 보장하지 않는다.

오류 메시지는 최근 6,000자의 로그/응답 근거와 함께 명시적 OutOfMemoryError 보고,
JVM 시작 메모리/구성 실패, 원인 불명 종료/작업 실패를 구분한다. 종료 코드 -9 등만으로
OOM을 추정하지 않는다. OOM 응답·비정상 종료·끊긴 요청 채널은 세션을 정리하며,
일반 작업 오류는 기존 세션 재사용 동작을 유지한다. 기존 취소와 타임아웃 처리는 유지한다.
로그 뒷부분에 메시지가 없거나 JVM이 응답하지 않으면 OOM 여부를 확정할 수 없다.

실제 JEB에서 소형 fixture의 1,024MiB 인덱싱과 768MiB로 바꾼 다음 요청의 JVM 재시작을
검증했다. 실제 메모리 고갈을 유발한 시험은 아니며 OOM 분류/정리는 합성 응답으로 검증했다.

전체 회귀 **594 passed (81.93초)**, 실제 JEB 9개 포함. 신규 19개는 설정 범위·구형 설정,
명령 인자·재시작·OOM 응답·원인 불명 종료·끊긴 채널·GUI 저장 보존 및 실제 저힙 fixture를 다룬다.
wheel 빌드 SHA-256: `bd5d42b7d0a77bc4240e32cb2f3711e5ac4b7990c4c00767460148ef726bd9af`.
이번 단계에서는 독립 가상환경 설치를 반복하지 않았다. 기본값 및 사용자 실제 설정은 변경하지 않았다.
