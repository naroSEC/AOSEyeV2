# 사용자 제공 APK 검증 기록

## 2026-10-12 component / WebView bridge / 인증 / 규칙 재검증

최종 wheel과 일치하는 소스로 사용자 APK 두 개를 다시 정적 분석하고 프로젝트를 저장했다.
현재 메모리 여유에 맞춰 JVM 최대 힙 1536MiB를 사용했다. 본문 64MiB, 선언 종류별
20,000개/8MiB, native 순서, 300초, 합산 RSS 3072MiB, 가용 메모리 1024MiB 하한을
적용했다. 메모리 보호 하한은 낮추지 않았다. 이전 4GiB 시험과 설정이 다르므로 속도를
직접 비교한 성능 개선 주장으로 사용하지 않는다.

- `build/real-apk-20261012-components/1-MyAcademy`: 본문 14,536개, 분석 21.809초,
  저장/증거 조회 포함 31.810초, 최대 합산 RSS 1,565,851,648 bytes.
- `build/real-apk-20261012-components/2-amospro_dev6`: 본문 12,952개, 분석 20.731초,
  저장/증거 조회 포함 29.352초, 최대 합산 RSS 1,996,963,840 bytes.

둘 다 FINISHED, 증거 조회 오류 0, bridge_closed=True이나 **complete=False**다.
이것은 범위 제한을 포함한 실행 완료이지 전체 앱 분석/탐지 정확도/안전의 증명이 아니다.
원본 APK와 이전 보고서는 보존했다. APK 설치·실행이나 앱 서버 요청은 하지 않았다.
83.8MB 앱은 작업 후 가용 메모리가 약 3.1GiB로 기존 4GiB 분석과 보호 여유를 충족하지
못해 이번에 재실행하지 않았다. 최신 대형 APK 검증은 여전히 미완료다.

## 2026-10-09~10 구성 자산 / TLS interface 재검증

최신 구현으로 두 소형 입력을 정적 분석했다. JVM 4GiB, 선언 종류별 20,000개/8MiB,
본문 64MiB, native 순서, 300초 제한, 합산 RSS 4,608MiB, 시스템 가용 메모리 1,024MiB 하한.

- `build/real-apk-20261009-config/1-MyAcademy`: 14,536개 본문, 분석 16.617초,
  저장/증거 조회 포함 23.504초. 증거 조회 오류 0개, FINISHED, complete=False.
- `build/real-apk-20261009-config/2-amospro_dev6`: 12,952개 본문, 분석 15.988초,
  저장/증거 조회 포함 21.904초. 증거 조회 오류 0개, FINISHED, complete=False.

두 결과 모두 프로젝트를 저장했으며 범위 제한 진단을 유지한다. 전체 앱 분석 또는 안전 판정이 아니다.

83.8MB amoremall의 최신 검증은 **미완료**다. manifest-first, 종류별 5,000개/8MiB,
본문 16MiB 및 같은 보호 기준을 사용했지만 시스템 가용 메모리가 하한보다 낮아 취소됐다.

- `build/large-apk-20261010-config/amoremall`: 힙 4GiB, 17.537초에 취소.
  관측 가용 메모리 1,007,722,496 bytes.
- `build/large-apk-20261010-config-heap3072/amoremall`: 힙 3GiB 재시도, 17.920초에 취소.
  관측 가용 메모리 1,067,708,416 bytes.

두 경우 모두 본문/증거 검증에 도달하지 못했고 bridge_closed=True다. 다른 프로그램을 종료하거나
보호 기준을 낮추지 않았다. 이전 4GiB 성공 기록을 최신 코드의 성공으로 간주하지 않는다.
메모리 여유가 확보된 환경에서 재검증해야 한다. 원본 APK/과거 결과는 보존했다.

## 2026-10-08 TLS / 선언 예산 재검증

원본 파일과 이전 결과를 보존하고 별도 출력 폴더를 사용했다. APK 설치/실행이나 서버 요청은 없다.

- `build/real-apk-20261008-tls/1-MyAcademy`: 11,768개 본문, 분석 13.962초,
  `complete=False`. TLS 패턴 도입 후/메타데이터 예산 수정 전 기록.
- `build/real-apk-20261008-tls/2-amospro_dev6`: 기본 8MiB 선언 예산을 클래스/필드가
  먼저 소진하여 본문 0개. 이를 성공적인 코드 분석으로 취급하지 않았다.
- `build/real-apk-20261008-budget/2-amospro_dev6`: 클래스/필드 합산 예산을 절반으로
  제한한 후 20,000개 메서드 선언, 12,952개 본문, 151,148개 명령, 분석 15.233초.
  메서드 예산을 확보하는 대신 저장 필드가 18,127개에서 1,111개로 줄었다.
  누락 진단과 `complete=False`를 유지한다. 이 결과도 전체 앱 분석은 아니다.

각 폴더의 `summary.json`에 설정, 입력 해시, 단계별 시간과 메모리 관측치가 있다.
저장한 프로젝트에 원본 코드/문자열이 포함될 수 있으므로 보고서 마스킹과 혼동하지 않는다.

### 83.8MB amoremall 제한 분석

`manifest-first`, 선언 종류별 5,000개/총 8MiB, 본문 16MiB, 최대 300초를 사용했다.

- `build/large-apk-20261008-batch/amoremall`: JVM 2GiB. 본문 2,886개 분석은
  23.382초에 끝났지만 두 후속 증거 조회가 JEB OutOfMemory로 실패했다. 총 122.437초.
  당시 runner의 FINISHED는 오류 없는 검증을 의미하지 않는다. evidence_checks에 오류가 보존됐다.
- `build/large-apk-20261008-heap4096/amoremall`: JVM 4GiB/RSS guard 4,608MiB/
  시스템 여유 1,024MiB 하한. 동일 본문 2,886개/선언 5,000개/명령 53,189개,
  분석 22.063초, 전체 30.373초. 두 메서드의 decompile/AST/XREF가 오류 없이 반환됐다.
  AST 노드 각각 70/36개, XREF 각각 44개. Guard 발동 없음, `complete=False`.

2GiB와 4GiB 차이는 이 입력/설정에서 관측한 결과이며 모든 APK의 필요 메모리를 뜻하지 않는다.
전체 APK의 보안성을 검증하지 않았고, 고정한 분석 예산 밖의 미탐 가능성이 남는다.
검증 중 발견한 runner 상태 문제는 수정했다. 이후 evidence_checks 오류가 있으면
EVIDENCE_FAILED를 출력한다. 이 수정은 저장된 과거 summary를 덮어쓰지 않는다.

2026-10-01, Windows / Python 3.14.2 / Java 21.0.10 / JEB 5.47.0.202609202129.
사용자가 제공한 두 APK만 정적 분석했다. 외부 APK 다운로드, 앱 설치·실행,
앱 서버 요청, 외부 서비스 업로드는 하지 않았다. 아래는 도구 통합 검증이며
앱 전체의 보안 감사 완료나 취약점 부재를 의미하지 않는다.

## 최종 관측 결과

`build/real-apk-tests-final/1-MyAcademy/summary.json`:

- 입력 6,370,338 bytes, DEX 1개, binary Manifest 해석 성공.
- 클래스 6,273개, 선언 42,196개, 본문 34,352개, 명령어 563,771개.
- 분석 21.252초, 표본 근거 조회·저장 포함 35.200초.
- Python peak RSS 572,833,792 bytes, Java peak RSS 2,095,837,184 bytes.
- 저장 프로젝트 145,772,605 bytes. GUI worker 재열기 약 2.176초.
- 흐름 후보 103개 모두 탐색 시작, 56,064 steps. 일부 경로는 제한에 도달했다.
- WEAKNESS 5 / EXPOSURE 4 / REVIEW 1,434. L3 이상 탐지 결과는 없다.

`build/real-apk-tests-final/2-amospro_dev6/summary.json`:

- 입력 11,160,904 bytes, DEX 17개. JEB는 이를 1개 Bytecode unit으로 합쳤으며
  `getCountOfDexEntries()`는 17이다. binary Manifest 해석 성공.
- 클래스 13,589개, 선언 98,894개, 본문 79,800개, 명령어 1,086,577개.
- 분석 36.458초, 표본 근거 조회·저장 포함 61.157초.
- Python peak RSS 1,099,706,368 bytes, Java peak RSS 2,531,131,392 bytes.
- 저장 프로젝트 303,451,849 bytes. GUI worker 재열기 약 3.996초.
- 흐름 후보 203개 모두 탐색 시작, 60,339 steps. 일부 경로는 제한에 도달했다.
- WEAKNESS 5 / EXPOSURE 12 / REVIEW 1,888. L3 이상 탐지 결과는 없다.

최종 두 결과 모두 메서드 추출 실패 0건, 표본 근거 조회 실패 0건이다.
각 앱 2개 메서드에서 decompile/AST/native XREF/CFG를 조회했다. 모든 메서드의
AST를 검사한 것은 아니다. amospro MainActivity의 AST 호출 오프셋 33개와
SplashActivity의 5개는 모두 해당 DEX 명령어 오프셋에 존재했다.
GUI는 offscreen QML 창으로 검증했고 재열기 중 이벤트 루프 동작, Finding 표시,
창 렌더링을 확인했다. 사람이 화면을 조작하는 전체 UX 검증은 아니다.

시간은 단일 로컬 실행 관측값이며 성능 보장이나 반복 벤치마크 평균이 아니다.
일부 회귀 테스트와 실행 시간이 겹쳤다. RSS는 0.25초 간격 표본의 최대값이며,
Python/Java 각각의 peak가 같은 시점에 발생했다는 의미는 아니다.

## 발견하고 수정한 문제

1. 기존 Jython 브리지는 모든 본문과 전체 JSON 문자열을 중복 보유해 17 DEX 앱에서
   4GB JVM heap을 소진했다. 본문별 NDJSON 전송과 한 줄씩 정규화하는 수신기로 수정했다.
   JVM heap 상향 없이 재검증을 통과했다.
2. 프로젝트 저장의 재귀적 dataclass deep copy를 제거했다. MyAcademy Python peak는
   최초 약 1.016GB에서 최종 약 573MB로 줄었다. 저장 파일은 약 327MB에서 146MB로
   줄었다. 최초 Java 측정은 PATH의 실행 shim 때문에 유효하지 않아 비교하지 않았다.
3. 소스 도달 가능성 기반 후보 선택과 루트별 탐색 예산을 도입했다. 라이브러리 한 경로가
   전역 예산을 독점하는 문제를 줄였으나, 모든 경로를 끝까지 분석한다는 뜻은 아니다.
4. Guava `CharMatcher$Invisible` 생성자에 고립 UTF-16 surrogate가 있어 Jython의
   자동 Java String 변환이 실패했다. Java MethodHandle로 코드포인트 배열을 반환하고
   Python에서 원문을 복원한다. 저장 후 재열기에서도 U+D800 보존을 확인했다.
5. 기본 Java 선택에서 유효한 JAVA_HOME을 사용하도록 해 실제 JVM PID를 추적한다.
   amospro 인덱싱 중 취소 실험에서 약 0.559초 후 취소가 반환되고 원래 PID가 종료됐다.
   이후 새 JEB Core probe가 정상 연결됐다. 임의의 사용자 지정 Java 실행 래퍼까지
   프로세스 트리 정리를 보장하는 것은 아니다.

## 해석상의 제한

두 결과 모두 `complete=false`이다. 루프·호출 깊이·루트별 예산, 모델링되지 않은
호출 등의 한계를 Diagnostics에 남긴다. REVIEW 숫자는 취약점 개수가 아니며,
노출된 컴포넌트도 자동으로 취약점으로 간주하지 않는다. L3 이상 결과가 없다는 사실로
앱의 안전성을 결론 내릴 수 없다. ICC, 비동기 콜백, 가상 dispatch, 객체/배열 및
sanitizer 의미 모델은 여전히 후속 작업이다. 100MB 이상 대용량 APK는 미검증이다.

## 재실행

```powershell
$env:AOSEYE_RUN_JEB = '1'
python -m pytest -q
python tools/validate_apks.py 'path/to/first.apk' 'path/to/second.apk' --save-project --output build/real-apk-tests
```

최종 회귀 결과: 47 passed. 일반 테스트 43개와 JEB/Jython/GUI 통합 4개다.
wheel 빌드도 성공했다. `psutil`은 `pip install -e ".[test]"`에 포함된다.
정규화된 전체 인덱스는 여전히 메모리에 보유한다. 프로젝트 파일에는 원본 코드와
민감한 상수가 포함될 수 있으므로 로컬 기밀 자료로 취급해야 한다.

## 후속 정밀도 개선 재검증 (같은 날짜)

결과는 이전 기록을 덮어쓰지 않고 `build/real-apk-tests-precision/`에 저장했다.
이전 단락의 47개 테스트 및 L3 이상 결과 없음은 개선 전 실행에 해당한다.
개선 후 회귀 테스트는 **71 passed**이며, 실제 앱의 추출 본문 수는 동일하다.

- MyAcademy: REVIEW 1,434 → 1,268, WEAKNESS 5 → 1, EXPOSURE 4 유지.
  `VULNERABILITY` 타입의 L4/POTENTIAL/MEDIUM 후보 1개가 추가됐다.
- amospro_dev6: REVIEW 1,888 → 1,748, WEAKNESS 5 → 2, EXPOSURE 12 유지.
  L3 이상 후보는 여전히 없다.
- MD5/SHA-1 사용은 보안 용도를 확인하기 전에는 WEAKNESS가 아닌 L2 REVIEW/INFO다.
  라이브러리 패키지라는 이유로 제외하거나 모든 해시 사용을 안전하다고 판정하지 않았다.
- 단순 Log.isLoggable 및 WebSettings getter/표시 설정 호출을 API 경고에서 제외했다.
  로그 출력은 데이터 유출을 확정하지 않는 REVIEW로 유지했다.
- Bundle/BaseBundle 반환값은 receiver/default 값에서만 전파한다. 조회 키만 오염된
  경우를 음성 테스트로 확인했다. URI 추출과 WebView 콘텐츠 인자도 명시적으로 모델링했다.

새 MyAcademy 후보를 JEB decompiler와 Java AST로 별도 확인했다.
`BMCWebActivity.onCreate`에서 DEX offset 142의 `Intent.getExtras`, 150의
`BaseBundle.getString`, 158의 `a2.b.c` 호출을 거쳐 170의 `WebView.loadUrl`로 이어진다.
helper에는 조건에 따라 원래 문자열을 반환하는 경로가 있다. 해당 클래스는 Manifest의
직접 컴포넌트 목록에 없었고, 등록된 컴포넌트의 추출된 상속 체인에서도 확인되지 않았다.
외부 앱에서 도달 가능한지, 허용되는 URL 조건이 무엇인지 입증되지 않았으므로 L5나
CONFIRMED로 승격하지 않았다. 데드 코드 여부 및 모든 호출자는 아직 검증하지 않았다.

실제 앱 재분석은 두 앱 모두 메서드 추출 및 표본 evidence 조회 오류 없이 저장됐다.
흐름 모델의 예산·분기 조건·ICC·비동기 콜백 한계로 `complete=false`는 유지된다.
이번 단계는 정밀한 인자 모델과 검토 분류 개선이며, 컴포넌트 간 전달이나 Runnable 실행
순서까지 자동으로 연결하는 ICC/비동기 분석을 구현했다고 주장하지 않는다.

API 의미 확인 근거:
[WebView](https://developer.android.com/reference/android/webkit/WebView)의
`loadDataWithBaseURL` 콘텐츠/원점 구분과 `evaluateJavascript` 코드 인자,
[Bundle](https://developer.android.com/reference/android/os/Bundle)의 문자열 조회와 기본값,
[Log](https://developer.android.com/reference/android/util/Log)의 `isLoggable` 역할을 참고했다.

## 제한된 ICC / 비동기 연결 추가 검증

최종 결과는 `build/real-apk-tests-boundaries-final/`에 저장했다. 직전 절의
ICC/비동기 미구현 설명은 당시 실행에 해당하며, 이번에는 아래 제한된 패턴을 추가했다.

- 명시적 Intent 생성자 또는 setClass의 `const-class` 대상, 상수 키의 문자열 extra,
  data setter/getter, 같은 앱의 enabled activity/alias에 대한 startActivity→onCreate.
- 생성 클래스와 run() 본문이 확인된 Runnable 객체, 객체별 scalar 캡처 필드,
  Handler/View post·지원되는 postDelayed overload·Executor.execute·runOnUiThread.
- 인자/반환 객체 식별자와 별칭을 보존하고, 같은 factory를 두 번 호출해 생성한 객체는
  분리한다. 키 불일치·안전한 값 덮어쓰기·일반 문자열을 클래스처럼 사용하는 경우를
  연결하지 않는다. 미지원 Intent 변이는 기존 대상/전달 상태를 무효화한다.
- 비동기 경계는 snapshot으로 탐색하며 callback 결과나 힙 쓰기를 동기 호출자의 효과로
  합치지 않는다. 경계를 지나는 증거는 scheduling/lifecycle 불확실성을 명시한다.

첫 실제 앱 실행에서는 boundary 후보가 기존 소스 루트의 예산을 줄이는 회귀를 발견했다.
소스 루트의 기존 예산과 탐색 우선순위를 복구하고 boundary-only 루트를 뒤에 배치했다.
최종 실행의 MyAcademy는 소스 루트 103/103개, 전체 후보 389/389개를 탐색 시작했으며
87,971 steps를 사용했다. amospro는 소스 루트 203/203개, 전체 후보 521/521개를
탐색 시작했으며 83,004 steps를 사용했다. 모든 경로의 완전 탐색을 의미하지는 않는다.

탐색된 경계 인벤토리:

- MyAcademy: ASYNC MODELED_POTENTIAL 218 / UNRESOLVED 46,
  ICC MODELED_POTENTIAL 4 / UNRESOLVED 19.
- amospro_dev6: ASYNC MODELED_POTENTIAL 214 / UNRESOLVED 76,
  ICC MODELED_POTENTIAL 1 / UNRESOLVED 35.

위 숫자는 연결 후보와 미해결 호출의 수이지 취약점 개수나 런타임 실행 횟수가 아니다.
이 두 APK에서는 경계 모델 추가로 새로운 source-to-sink 후보가 늘지는 않았다.
MyAcademy의 기존 WebView L4/POTENTIAL 1개는 유지됐다. 메서드 본문 수는 각각
34,352 / 79,800으로 동일하고, 두 앱 모두 export/evidence 조회 실패 0건이었다.
두 프로젝트를 QML GUI에서 다시 열어 Boundaries JSON 표시와 렌더링을 확인했다.
재열기·표시 관측값은 약 2.172초 / 4.424초이며 offscreen 검증이다.

회귀 테스트 **98 passed** (일반 93 + JEB/Jython/GUI 5), wheel 빌드 성공.
새 `boundary-fixture.apk`는 실제 JEB DEX 추출 후 ICC와 Runnable 양성 경로가
L5/POTENTIAL로 나타나는지 검사한다. 분석용 text Manifest ZIP이며 설치 대상이 아니다.
기존 GUI/AST/XREF fixture 테스트도 유지했다.

지원하지 않는 범위: 암시적 Intent 해석, 서비스/receiver ICC, setComponent/setClassName,
복합 Bundle/Parcelable 전달, 중첩 객체 캡처, coroutine/Rx, 작업 취소·거부·순서,
Activity launch flags/onNewIntent 선택, 전체 객체/가상 dispatch 및 분기 조건 증명.
진단과 `complete=false`를 유지하며 CONFIRMED로 자동 승격하지 않는다.

모델의 API 근거는 [Intent](https://developer.android.com/reference/android/content/Intent),
[Handler](https://developer.android.com/reference/android/os/Handler),
[Executor](https://developer.android.com/reference/java/util/concurrent/Executor.html)다.
특히 post 성공 여부나 Executor 실행 스레드/순서를 정적 호출 존재만으로 단정하지 않는다.

## MyAcademy L4 후보의 호출자 / URL 검사 검토

재분석 프로젝트: `build/real-apk-tests-review/1-MyAcademy/project.json`.
해당 `BMCWebActivity.onCreate`는 Manifest 직접 등록, 등록 컴포넌트의 상속 체인,
정규화된 DEX 선언 호출에서 진입 경로를 찾지 못했다. 추출된 클래스/문자열 상수의
해당 클래스 참조도 확인되지 않았다. 역추적 결과는 탐색 제한 없이
`NO_MODELED_PATH_FOUND`다. 리플렉션·네이티브·동적 등록/로딩까지 배제한 결과는 아니며,
사용되지 않는 코드로 단정하거나 후보를 삭제하지 않았다.

JEB `getCrossReferences`는 해당 메서드 요청에 INVOKE 참조 15건을 반환했다.
각 주소의 실제 DEX invoke operand를 확인한 결과 15건 모두 다른 선언 대상이었다.
원본 참조를 삭제하지 않고 `DIFFERENT_DECLARED_TARGET`으로 표시한다. 이러한 원본
참조 목록만으로 이 후보 메서드의 직접 호출자가 존재한다고 결론 내리지 않았다.

URL helper `a2.b.c`의 DEX offsets 20/36은 Kotlin 접두어 비교 helper 호출이다.
JEB에서 wrapper F→D를 확인했으며, 해당 인자 조합은 대소문자를 구분하는
String.startsWith 비교로 이어진다. http:// 또는 https://로 시작하는 입력을 그대로
반환하는 경로가 있다. 다른 입력은 별도 변환을 거치므로 모든 입력이 안전하거나
모든 입력이 위험하다고 일반화하지 않았다. 해당 두 분기의 양쪽 successor는
반환 offset 102에 구조적으로 도달한다. 첫 분기가 반환을 지배한다는 사실만으로
허용 목록 검증이 증명되지는 않는다.

호출자의 offset 138 분기는 loadUrl(offset 170)을 지배하지만 predicate는
Intent.hasExtra다. extra 존재 확인을 URL scheme/host 검증으로 인정하지 않는다.
WebViewClient 및 다른 런타임 동작까지 증명한 결과도 아니다.

결론: 후보는 **L4 / POTENTIAL / MEDIUM confidence** 유지. 외부 도달성과 안전한
허용 목록 검증은 입증되지 않았다. scheme_allowlist/host_allowlist/null_check는
계속 UNKNOWN이다. 자동 안전 판정·취약점 확정·dead-code 삭제를 하지 않았다.

일반화한 후보 검토 기능은 `Finding.review`로 저장되며 GUI Review 탭에서 보인다.
실제 MyAcademy 결과를 다시 열어 분기 문맥/도달성 표시와 QML 렌더링을 검증했다.
전체 회귀 **111 passed**, wheel 빌드 성공. 이번 실제 APK 재실행은 검토 대상인
MyAcademy에 한정했으며, amospro의 새 실측 실행을 주장하지 않는다.

## Manifest 미확정 값 / 상속 callback 보강 후 재검증

두 APK를 `build/real-apk-tests-entrypoints`에 다시 분석하고 프로젝트를 저장했다.
MyAcademy는 설정 기준 확정 callback 2개(상속 1개), amospro는 중복 제거 후 11개다.
amospro의 컴포넌트별 매핑 13개 중 상속 매핑은 5개다. 여기서 설정 확정은 실제 실행이나
악용 가능성의 증명을 뜻하지 않는다. 두 앱의 미확정 외부 callback 후보는 0개였다.

MyAcademy는 VULNERABILITY 1 / WEAKNESS 1 / EXPOSURE 4 / REVIEW 1268로 유지됐다.
기존 WebView 후보도 L4/POTENTIAL 유지다. amospro는 WEAKNESS 2 / EXPOSURE 12 /
REVIEW 1752이며 L3 이상은 없다. 이전 1748개 대비 추가된 4개는 WorkManager 컴포넌트의
미해결 enabled 리소스 검토 항목이며 취약점이 아니다. 미확정 값의 L5 승격 방지는
별도 synthetic 회귀로 확인했다. 두 분석 모두 기존 분석 범위 한계로 complete=False다.

enabled는 application과 component를 함께 평가하며, alias 권한 기본값은 일반 activity와
구분한다. 플랫폼 근거: [Activity](https://developer.android.com/guide/topics/manifest/activity-element),
[Activity alias](https://developer.android.com/guide/topics/manifest/activity-alias-element).
권한 이름 존재를 보안성 증명으로 쓰지 않는다. 현재 무권한 진입점 모델은 provider의
읽기/쓰기별 접근 제어와 권한 protectionLevel을 완전히 평가하지 않는다.

## 외부 JSON 입력 검증 후 프로젝트 호환성

위 두 프로젝트를 새 크기/깊이/스키마 검증 경로로 재열기했다. MyAcademy 프로젝트는
147,243,122 bytes, Finding 1,274개 / 메서드 34,352개였고, amospro 프로젝트는
307,290,242 bytes, Finding 1,766개 / 메서드 79,800개였다. 모두 검증과 모델 복원에
성공했다. 로컬 단회 재열기 시간은 각각 10.94초 / 25.56초이며 성능 SLA가 아니다.
APK 분석을 재실행하거나 기존 프로젝트 파일을 덮어쓰지는 않았다.
전체 173개 테스트(JEB 연동 포함)와 wheel 빌드도 통과했다.

## DEX 위치 / 호출 참조 탐색 검증

`tools/validate_navigation.py`로 두 저장 프로젝트에서 Finding location→호출 참조 위치→
Back 왕복 및 잘못된 unit 이동 거부를 확인했다. APK 재분석이나 JEB 실행은 하지 않았다.
별도 전체 회귀 182개에는 실제 JEB 연동 5개가 포함되며 wheel 빌드도 통과했다.

MyAcademy의 BMCWebActivity.onCreate offset 170에서 조회한 탐색 링크는 47개,
amospro의 WebViewManager.enableWebViewRemoteDebugging offset 18에서는 5개였다.
이는 조회 근거의 링크 개수이며 취약점 개수나 실행 가능성의 증명이 아니다.
백그라운드 DEX 조회 단회 시간은 각각 0.163초/0.342초였다. 10ms Qt timer의 관측 최대
간격은 각각 24.37ms/24.19ms(표본 13/27개)였다. 로더·전체 QML 렌더링을 포함한 종합
성능 SLA가 아니며 이번 환경의 작은 표본이다. 원본 결과는 `build/navigation-validation.json`.

재현 명령:

```powershell
python tools/validate_navigation.py build/real-apk-tests-entrypoints/1-MyAcademy/project.json build/real-apk-tests-entrypoints/2-amospro_dev6/project.json -o build/navigation-validation.json
```

## 공통 선언 해석기 v2 재분석

두 APK를 실제 JEB로 재분석해 `build/real-apk-tests-declarations`에 별도로 저장했다.
이전 프로젝트는 보존했다. provenance의 analysis_policy에 `declaration-resolution-v2`를
추가해 이전 결과와 구분한다. 전체 191개 테스트(JEB 연동 포함)와 wheel 빌드도 통과했다.

MyAcademy의 유형별 결과는 VULNERABILITY 1 / WEAKNESS 1 / EXPOSURE 4 / REVIEW 1268,
amospro는 WEAKNESS 2 / EXPOSURE 12 / REVIEW 1752로 이전 실행과 동일했다.
분석 수준별 개수도 같았으며 MyAcademy L4 후보는 유지되고 amospro에는 L3 이상이 없다.
이는 개수 비교이며 모든 내부 경로가 동일하다는 의미는 아니다.

본문이 인덱스에 없는 선언의 진단은 각각 1,935개 / 4,026개였다. native/abstract 또는
본문 미수집 선언 등의 분석 한계를 뜻하며 새 취약점 개수가 아니다. 이러한 선언을
넘어 상위 구현으로 잘못 연결하지 않는다. 새 JEB 인덱스에서 UNKNOWN_DECLARATION에
따른 재인덱싱 경고는 두 앱 모두 0개였다. 두 실행의 complete=False는 유지된다.

구형 선언 메타데이터, native/abstract 및 본문 미수집 override, reference-only 상속,
indexed body 우선순위, 순환 상속, 생성자 비상속은 synthetic 회귀로 별도 검증했다.
구형 프로젝트의 모호한 상위 callback을 미확정 후보로 탐색하던 이전 정책은 중단/진단
정책으로 대체했으며, 전체 가상 dispatch나 인터페이스 default method를 해결한 것은 아니다.

## 원본 JEB XREF의 검증된 위치 탐색

전체 203개 회귀와 wheel 빌드를 통과했다. 실제 JEB fixture의 Navigation.open 참조
2건은 DEX target/unit/offset 검증 후 링크가 생성됐고, GUI에서 클릭 후 Back 왕복도
확인했다. 잘못된 주소/offset/unit, 누락된 unit, 다른 target, 위조된 validation label,
구형 선언 메타데이터, 중복 링크 및 취소는 synthetic 회귀로 검사했다.

MyAcademy 저장 프로젝트를 읽고 원본 APK 해시를 확인한 뒤 BMCWebActivity.onCreate의
JEB XREF를 실제로 다시 조회했다. 15개 모두 DIFFERENT_DECLARED_TARGET이고 링크는
0개였다. 원본 참조와 거부 이유는 유지한다. 이번 검증은 XREF 조회이며 APK 보안 분석
전체 재실행이나 취약점 판정 변경이 아니다. 결과는 `build/native-navigation-myacademy.json`.

```powershell
python tools/validate_native_navigation.py build/real-apk-tests-declarations/1-MyAcademy/project.json --method 'Lcom/mcnc/bizmob/core/view/activity/BMCWebActivity;->onCreate(Landroid/os/Bundle;)V' -o build/native-navigation-myacademy.json
```

## 정상 흐름 URL guard의 제한적 의미 검토

전체 216개 테스트(JEB 연동 포함)를 통과했다. `test/UrlGuards.java`를 D8로 변환한
실제 DEX에서 exact의 scheme/host는 MODELED_EXACT_MATCH, prefix/replaced는 UNKNOWN을
확인했다. Android Uri compile stub은 DEX에서 제외된다. fixture는 설치용 앱이 아니다.
synthetic 회귀에는 거꾸로 된 조건, 다른 값 검사, 우회 branch, 재대입, 루프·예외 handler,
CFG 누락·예산 제한 및 successor 순서 반전이 포함된다.

MyAcademy 저장 프로젝트의 BMCWebActivity.onCreate offset 170을 새 검토기로 읽었으며
scheme_allowlist/host_allowlist 모두 UNKNOWN이었다. `build/url-validation-myacademy.json`에
결과를 저장했다. APK 분석 전체를 다시 실행하거나 기존 프로젝트를 변경하지 않았다.
검토기는 Finding의 severity/type/verification을 바꾸거나 후보를 삭제하지 않는다.

모델의 플랫폼 근거는 [Android Uri](https://developer.android.com/reference/android/net/Uri)와
[Dalvik 조건 분기](https://source.android.com/docs/core/runtime/dalvik-bytecode)다.
정확한 component 문자열 비교와 branch polarity를 모델링할 뿐, Uri와 WebView의 URL
해석 일치·redirect·예외 흐름 완전성까지 입증한 결과가 아니다.

## static boolean helper와 예외 테이블

전체 230개 회귀(JEB 연동 포함) 및 wheel 빌드를 통과했다. 실제 DEX fixture에서
`helper`는 scheme/host 모두 MODELED_EXACT_MATCH, `helperOther`, `helperCatchOpen`,
`helperCatchClosed`, `callerCatch`는 UNKNOWN이었다. JEB에서 failOpen/failClosed/callerCatch의
exception_status=PRESENT를 확인했다. 보수적 거부를 검증한 것이며 fail-closed 안전성을
증명한 결과가 아니다. synthetic 회귀는 true-return bypass, 반대 조건, 결과 무시,
가상 호출, recursion, 공유 예산, 구형 메타데이터 및 프로젝트 round trip을 포함한다.

MyAcademy를 실제 JEB로 재분석하고 `build/real-apk-tests-url-helpers/1-MyAcademy`에
별도 저장했다. 인덱스 메서드 34,352개 중 예외 테이블 NONE 31,735개 / PRESENT 2,617개,
UNKNOWN 0개였다. VULNERABILITY 1 / WEAKNESS 1 / EXPOSURE 4 / REVIEW 1268로 유지됐고,
기존 BMCWebActivity 후보도 L4/POTENTIAL 및 scheme/host UNKNOWN이었다. 이 단계에서
amospro를 다시 실행하지는 않았다. 기존 프로젝트 파일은 변경하지 않았다.

## 제한적 예외 CFG 검증 (2026-10-02 확인)

전체 241개 테스트(JEB 연동 포함)와 wheel 빌드가 통과했다. JEB fixture에서
helperCatchClosed는 MODELED_EXACT_MATCH로 확장됐고 helperCatchOpen/callerCatch는
UNKNOWN을 유지했다. synthetic 회귀에서 caller 조기 종료/우회, 복수 handler 중 하나의
우회, handler 주소 누락, 범위 끝 불일치·겹침, 정상 successor 누락, handler 순환 및
새 메타데이터의 프로젝트 round trip을 확인했다. 안전 판정이나 Finding suppression은 없다.

두 사용자 APK를 실제 JEB로 재분석하고 `build/real-apk-tests-exception-flow`에 별도 저장한
뒤 새 로더로 재열기했다. MyAcademy는 메서드 34,352개 중 NONE 31,735 / PRESENT 2,617,
try 구간 4,799개였다. amospro는 메서드 79,800개 중 NONE 75,749 / PRESENT 4,051,
try 구간 7,234개였다. 두 앱 모두 exception_status UNKNOWN과 normal_successors 누락은 0개였다.
이는 메타데이터 추출 검증이며 모든 예외 경로를 증명했다는 뜻은 아니다.

MyAcademy 유형별 결과는 VULNERABILITY 1 / WEAKNESS 1 / EXPOSURE 4 / REVIEW 1268,
amospro는 WEAKNESS 2 / EXPOSURE 12 / REVIEW 1752로 유지됐다. MyAcademy의 기존 후보는
L4/POTENTIAL 및 URL guard UNKNOWN이다. 두 분석 모두 모델링 한계로 complete=False다.
원본 APK와 이전 프로젝트는 변경하지 않았다.

주소 단위와 handler 타입 정의는 설치된 JEB API와 공식
[IDexExceptionItem](https://www.pnfsoftware.com/jeb/apidoc/com/pnfsoftware/jeb/core/units/code/android/dex/IDexExceptionItem.html),
[IDexExceptionHandler](https://www.pnfsoftware.com/jeb/apidoc/com/pnfsoftware/jeb/core/units/code/android/dex/IDexExceptionHandler.html)를 확인했다.
try [start,end)와 handler 주소는 바이트 단위로 기록하며 타입 정보는 보존하지만
예외 경로 제거에 사용하지 않는다. 보수적 과대 탐색 때문에 UNKNOWN이 늘어날 수 있다.

## GUI 검토 근거 탐색

전체 248개 회귀(JEB 연동 포함)와 wheel 빌드를 통과했다. synthetic fixture에서
프로젝트 저장/재열기 후 비교·분기·허용 successor·helper·handler 링크를 생성하고 실제
명령 오프셋으로 이동하는지 검증했다. GUI worker 처리, Back 왕복, 메모 보존,
위조된 저장 review 오프셋의 무시, 잘못된 예외 범위 거부, 링크 상한·취소도 검사했다.
`build/gui-review-preview.png`에서 QML 요약과 링크 목록을 시각적으로 확인했다.

MyAcademy의 `build/real-apk-tests-exception-flow/1-MyAcademy/project.json`을 다시 열어
기존 L4 후보를 새 Review 경로로 검토했다. URL guard/scheme/host는 UNKNOWN이고 검증
링크는 0개였다. L4/POTENTIAL은 그대로이며 결과를 `build/review-navigation-myacademy.json`에
저장했다. 이번 단계는 저장 DEX 재검토이며 APK 전체 분석을 새로 실행한 것은 아니다.

## GUI JEB XREF 페이지 이동

전체 259개 회귀(JEB 연동 포함)를 통과했다. 603개 합성 원본 참조로 300/300/3개
페이지, 이전/다음 경계, 중복 링크 병합, 빈 페이지를 확인했다. 오류·불완전 응답·취소·
GUI 반영 직전 취소 시 이전 페이지/위치/이력/메모를 보존하고 오래된 응답을 거부한다.
다른 화면이나 Finding으로 이동하면 페이지 상태를 초기화한다.

실제 설치 JEB에서 flow-fixture.apk의 Navigation.open 참조 2개를 페이지 크기 1로
조회하여 첫 페이지→다음→이전과 정확한 DEX 위치 이동을 확인했다. 기본 페이지 크기는
300이다. `build/gui-xref-pagination.png`의 페이지 버튼과 범위 표시를 시각적으로 확인했다.
사용자 APK 2개의 전체 보안 분석을 다시 실행한 것은 아니며 기존 보고서는 수정하지 않았다.

## Finding 비의존 DEX 탐색

전체 265개 회귀(JEB 연동 포함)를 통과했다. 실제 flow-fixture.apk에서 클래스→메서드
패널로 Navigation.open을 열고 Finding 선택 없이 AST/JEB XREF/디컴파일을 조회했다.
`build/gui-dex-browser.png`에서 메서드 목록, 현재 코드 위치 및 코드 표시를 확인했다.
합성 80,000개 메서드에 대해 300개 페이지와 마지막 200개, 취소를 검증했다.
일반적인 UI 지연 시간이나 전체 대용량 APK 처리 성능을 보장하는 측정은 아니다.

`build/real-apk-tests-exception-flow`의 두 저장 프로젝트를 다시 읽었다. MyAcademy는
34,352개 메서드/6,273개 클래스, amospro는 79,800개 메서드/13,589개 클래스였다.
양쪽 클래스 첫 페이지는 300개이며 첫 클래스의 메서드 조회는 각각 4개/3개였다.
저장 DEX를 읽어 탐색 쿼리만 검증했으며 APK 전체 재분석이나 기존 보고서 수정은 하지 않았다.

## Unit/package/field 출처 탐색

전체 269개 회귀(JEB 연동 포함)를 통과했다. 실제 JEB fixture에서 class_index와
field_index의 unit 출처 및 필드 서명 보존을 검증했다. GUI의 unit/package/class/member
표시를 `build/gui-dex-browser.png`로 확인했다. 복수 unit 동일 서명은 합성 fixture로
검증했으며, 선택 unit에 본문이 없으면 다른 unit의 저장 본문을 열지 않는다.

이전 두 사용자 프로젝트는 새 인덱스가 없는 상태로 정상 재열기했다. MyAcademy의
24,576개 및 amospro의 53,142개 필드 항목은 unit을 추정하지 않고 Unknown으로 유지한다.
양쪽 unit 목록은 기존 JEB unit과 Unknown 항목을 합쳐 2개였다. 여기서 JEB unit은
개별 classesN.dex 파일과 일대일 관계가 아니다. package 목록은 unit을 구분하므로
동일 package가 여러 번 나올 수 있다. 기존 파일은 변경하지 않았고 APK 전체 재분석도 하지 않았다.

## 필드 읽기/쓰기 위치 연결

전체 306개 회귀(JEB 연동 포함)와 wheel 빌드를 통과했다. 실제 fixture에 Navigation.peek을
추가해 기존 last 쓰기와 읽기를 생성하고, JEB의 sput-object/sget-object 정규화 결과를
Field XREF에서 조회했다. 두 위치 링크와 클릭 후 DEX 오프셋을 검증했다.
`build/gui-field-xref.png`에서 READ/WRITE 목록과 선택 필드·unit 표시를 확인했다.
합성 테스트는 28개 표준 opcode, 다른 unit/operand, unknown 출처, 잘못되거나 중복된
오프셋, 300개 잘림, 취소/오래된 응답 거부, 이력/Finding/메모 보존을 포함한다.

두 이전 저장 프로젝트에서도 필드 operand를 조회했다. MyAcademy의
`La/a;->context:Landroid/content/Context;`와 amospro의
`L_COROUTINE/CoroutineDebuggingKt;->ARTIFICIAL_FRAME_PACKAGE_NAME:Ljava/lang/String;`는
각각 3개 일치 항목을 반환했다. 선택 필드의 unit이 없는 구형 데이터이므로 링크는 양쪽
모두 0개였다. 기존 결과 파일 수정이나 사용자 APK 전체 재분석은 수행하지 않았다.

## 필드 참조 페이지와 READ/WRITE 필터

전체 316개 회귀(JEB 연동 포함)를 통과했다. 603개 합성 참조를 300/300/3개로 조회하고
READ 302개, WRITE 301개 및 마지막 페이지를 확인했다. 필터 변경 시 첫 페이지로 이동하고
오류/취소/늦은 취소/오래된 응답은 기존 페이지와 필터·위치·메모를 변경하지 않는다.
실제 JEB fixture의 last 필드 참조 2개를 테스트용 페이지 크기 1로 왕복 조회하고
READ/WRITE 각각 1개 결과를 확인했다. 기본 페이지 크기는 300이다.
`build/gui-field-xref.png`에서 필터·범위·페이지 버튼 렌더링을 확인했다. 이번 단계는
페이지/필터 회귀이며 사용자 APK 전체 보안 분석을 새로 실행하지 않았다.

## 필드 검색 응답·취소 지연 측정 및 개선

`tools/benchmark_field_navigation.py`로 두 저장 프로젝트의 최다 참조 필드를 각각 3회
ALL/READ/WRITE 조회했다. 실제 QML과 10ms QTimer를 사용하되 offscreen 환경이며
프로젝트 로딩 시간은 측정에서 제외한다. 구형 필드 unit은 Unknown으로 유지하므로
이번 workload에는 클릭 가능한 참조 300개 렌더링이 포함되지 않는다.

기준 결과는 `build/field-navigation-baseline.json`, 최종 결과는
`build/field-navigation-optimized-isolated.json`이다. 중간
`build/field-navigation-optimized.json`은 테스트 실행과 겹쳤으므로 최종 비교에서 제외한다.
최종 측정에는 다른 테스트/빌드 작업을 병행하지 않았다. 실행 환경은 JSON에 기록했다.

MyAcademy(563,771명령)의 ALL 처리 중앙값은 244.058→118.553ms,
amospro(1,086,577명령)는 361.899→178.018ms였다. 각 3회, 초기 화면 갱신 포함이다.
최대 타이머 간격은 각각 134.435→79.647ms, 205.356→93.320ms였다.
최종 worker 검색 자체는 완료된 조회 기준 약 39–43ms / 80–94ms였으며
나머지는 작업 전달·직렬화·QML 갱신 등을 포함하므로 순수 렌더링 시간으로 해석하지 않는다.
조회 개수는 전후 동일했다: MyAcademy ALL/READ/WRITE=303/303/0,
amospro=1234/1233/1. 빈 결과와 큰 페이지 모두 포함하나 전체 필드 분포를 대표하지는 않는다.

취소는 시작 10ms 후 타이머로 예약했다. 최종 실제 전달은 시작 후 18.304–40.617ms,
전달 후 GUI idle까지는 2.676–4.250ms였다. 따라서 사용자 요청부터 종료까지를
단순히 4ms로 주장하지 않는다. 모든 취소 회차에서 이전 페이지/필터/메모 보존을 검증했다.
이벤트 루프 관측치이지 실제 화면 입력 지연 SLA나 대형 APK 전체 처리 성능 보장은 아니다.

개선은 링크 가능한 현재 페이지 후보가 있는 메서드만 offset 인덱스를 만드는 것과,
내용을 보존한 JSON 항목별 한 줄 배치다. 7개 회귀를 추가하여 순회 횟수와 빈/300개 결과,
Unicode 포함 JSON round trip을 검증했다. 전체 323개 회귀(JEB 포함)를 통과했다.
원본 프로젝트 파일은 읽기만 했으며 APK 전체 분석을 다시 실행하지 않았다.

## 프로젝트 로딩 메모리와 검증 링크 300개

`tools/benchmark_project_loading.py`는 프로젝트별 새 프로세스에서 실제 QML workspace의
reopen을 호출한다. Qt 초기 상태 약 83MiB를 포함한 OS 프로세스 수명 누적 peak working set과
작업 전후 RSS를 기록한다. offscreen/로컬 관측이며 프레임 시간·실제 입력 지연 SLA가 아니다.
기준은 `build/project-loading-baseline.json`, 개선 후는 `build/project-loading-optimized.json`이다.
각 파일 옆의 `-1.json` / `-2.json`은 개별 프로세스 결과다. 로딩은 전후 각 1회이므로
속도 차이를 통계적인 성능 향상으로 주장하지 않는다. 다른 테스트/빌드는 측정 중 실행하지 않았다.

MyAcademy 로딩은 13.106→12.673초, 피크 1047.70→891.16MiB,
직후 RSS 834.46→734.93MiB였다. amospro는 25.347→24.840초,
피크 2009.30→1684.69MiB, 직후 RSS 1551.32→1396.81MiB였다.
로딩 중 최대 10ms 타이머 간격은 각각 209.126→174.018ms, 380.923→387.859ms였다.
피크 메모리는 약 15–16% 감소했지만 긴 로딩과 UI 지연을 해결한 것은 아니다.

저장 DEX의 실제 caller unit/필드 operand로 가장 빈번한 참조를 골랐다. 이 unit은
선언 필드 출처라고 추정한 값이 아니다. 양쪽 모두 링크 300개를 생성하고 모든 위치를
bytecode_location으로 재검증했다. 첫 표시 후 동일 조회를 두 번 반복했으며 동일 텍스트의
반복은 전체 화면 재렌더링 측정과 같지 않다. 개선 후 첫 조회는 약 133ms / 202ms,
반복 조회는 55–57ms / 106ms였다. 마지막 행으로 스크롤한 contentY를 확인하고 마지막
링크의 정확한 메서드/unit/offset 이동도 통과했다. 모든 참조를 동시에 delegate로 그리는
시험이 아니라 가상화된 ListView에 300개 모델 항목을 공급한 시험이다.

개선은 JSON 디코딩 후 바이트 버퍼 조기 해제와, 검증 완료된 로더 소유 메서드 DTO를
변환하면서 해제하는 것이다. 일반 from_dict 호출은 기존처럼 입력을 보존한다.
전체 327개 회귀(JEB 포함)를 통과했다. 원본 프로젝트 수정이나 사용자 APK 재분석은 하지 않았다.

## 프로젝트 로딩 취소와 늦은 결과 방지

전체 339개 회귀(JEB 포함)를 통과했다. 로딩 시작 전, 읽기 chunk, JSON object hook과
깊이 순회, 스키마 검증, 모델 변환 및 GUI 반영 직전 취소를 검증한다. 오류와 오래된
결과도 현재 프로젝트·선택 Finding·위치·메모·Review 요약을 바꾸지 않는다.
취소 후 재열기는 새 토큰을 사용한다. 기존 strict JSON/스키마 거부 테스트도 유지했다.

`tools/validate_project_cancellation.py`로 두 실제 저장 프로젝트의 읽기/검증/모델 변환
progress가 GUI에 전달될 때 취소했다. 결과는 `build/project-cancellation-validation.json`이다.
MyAcademy의 요청 전달→관측 종료는 각 2.523 / 147.865 / 156.455ms,
amospro는 2.218 / 293.355 / 287.583ms였다. 각 단계 1회이며 기존 세션 identity와
내용/메모 보존을 모두 확인했다. 여기서 단계 progress 전달은 worker보다 늦을 수 있어
정확한 CPU 명령 위치에서 취소한 시험은 아니다. 누적 로딩 시간과 요청 후 지연은 JSON에서 구분한다.

이 측정은 QML 렌더링 없는 Qt controller/event-loop 관측이다. native UTF-8/JSON 연산과
생성된 큰 객체를 해제하는 동안 즉시 중단은 보장하지 않는다. amospro 모델 변환 단계에
도달하기까지 최대 타이머 간격 868ms도 관측했으므로 로딩 UI 지연을 해결했다고 주장하지 않는다.
메모리/로딩 성능의 이전 독립 프로세스 측정과 조건이 다르다. 원본 결과 파일은 수정하지 않았다.

## 반복 취소/재열기와 이전 모델 해제

완료 콜백, Job.work, backend.program이 이전 결과/정규화 모델을 붙잡는 경로를
weak-reference 회귀로 재현하고 수정했다. 성공/실패/취소/종료 시 작업 참조를 정리하고
완료 콜백에서 새 작업을 시작하는 경우에도 새 콜백을 잘못 지우지 않는다.
pytest 로그 수집기의 traceback 보관은 별도 소유이므로 객체 수명 테스트에서는 분리했다.

`tools/validate_reopen_stability.py`로 같은 offscreen QML workspace에서 MyAcademy→amospro를
2회 반복했다. 각 성공 재열기 전에 같은 대상의 스키마 검증 단계에서 취소하여 총 4회
취소와 4회 성공 재열기를 실행했다. 결과는 `build/reopen-stability-validation.json`이다.
취소마다 기존 화면/탐색 위치/메모와 result identity를 보존했고, 성공 교체 후 명시적 GC를
수행했을 때 모든 과거 result/program weak reference는 사라졌다. 현재 세션은 유지한다.

GC 후 RSS는 1회차 MyAcademy 734.59MiB, amospro 1980.11MiB,
2회차 MyAcademy 1848.59MiB, amospro 2010.08MiB였다. GC 전후 값도 보고서에 보존한다.
프로세스 수명 누적 피크는 2512.75MiB였다. 과거 객체가 해제되어도 RSS가 초기 수준으로
돌아가지 않았으며 allocator/fragmentation 등의 보유량을 실제 객체 누수와 구분한다.
두 반복만으로 누수 부재/메모리 상한/장시간 안정성을 증명하지 않는다. 실제 JEB JVM은
시작하지 않았으므로 네이티브 JEB 세션 누적 메모리를 검증한 시험도 아니다.

성공 재열기는 20.8/38.9/22.7/42.5초였고 최대 Qt 타이머 간격은 1495.127ms였다.
기존 세션과 새 로딩을 동시에 보유하는 조건이어서 독립 프로세스 단일 로딩 측정과 다르다.
취소/객체 수명은 검증했지만 대형 로딩 UI 지연은 남아 있다. 원본 프로젝트는 읽기만 했고
benchmark용 메모는 메모리 안에서만 변경했다.
전체 345개 회귀(JEB 포함)를 마지막 재실행에서 통과했다. 앞선 전체 실행에서는 JEB
probe JSON 응답 오류가 1회 있었고 단독 재검사와 마지막 전체 실행에서는 재현되지 않았다.
이 비결정적 오류의 원인을 이번 메모리 참조 수정으로 해결했다고 주장하지 않는다.

## amoremall 대용량 전체 분석 시도 (2026-10-03)

사용자 제공 `amoremall.apk`는 83,771,204바이트(약 83.8MB), DEX 5개(압축 해제 합계
43,626,076바이트), ZIP entry 3,144개다. SHA-256:
`4017ba8f01b5299b50f412b5b615004e995235a858b444770b8685bb36ccb47d`.
원본을 설치/실행하거나 수정하지 않았다. 테스트는 기존 프로젝트를 덮어쓰지 않는 별도 경로에서 실행했다.

검증 도구 `tools/validate_apks.py`에 선택적 aapt2 경로, 경과 시간·Python/JEB 합산 RSS·
시스템 여유 메모리 감시 및 취소/실패 보고서 보존을 추가했다. 250ms 표본에 기반한
협력적 취소이며 OS의 강제 메모리 상한이나 즉시 취소 보장이 아니다. RSS 합계에는
공유 페이지 중복이 있을 수 있고 샘플 사이의 최고점은 누락될 수 있다.
기존 출력 디렉터리는 거부하며 최종 도구는 취소/실패/부분 분석 시 exit 2를 반환한다.

첫 실행은 캐시 off, 기본 메서드 예산 100,000, 최대 300초, RSS 4,096MiB,
시스템 여유 768MiB 기준이었다. 23.293초에 합산 RSS 한도로 취소됐다.
표본 피크: Python 36,134,912바이트, JEB 4,321,906,688바이트,
동시 합산 4,357,996,544바이트. 보고서: `build/large-apk-20261003-run1/amoremall/summary.json`.

두 번째 실행은 RSS 5,120MiB, 시스템 여유 1,024MiB로 조정했다. 29.004초에
시스템 여유 메모리 기준으로 취소됐다. 표본 피크: Python 36,962,304바이트,
JEB 4,596,191,232바이트, 동시 합산 4,633,137,152바이트(약 4.31GiB).
보고서: `build/large-apk-20261003-run2/amoremall/summary.json`.
두 실행 모두 JEB DEX/CFG 인덱싱 단계에서 멈췄으며 bridge_closed=true였다.
이 두 실행은 CLI 종료 코드 보강 전이므로 프로세스 exit 0을 성공으로 해석하면 안 된다.
summary의 validation_status=CANCELLED와 complete=false가 결과다.

**전체 분석·결과 저장·재열기는 완료하지 못했다.** Finding 수나 데이터 흐름 커버리지,
런타임 안전성에 관한 결론을 내리지 않는다. aapt2는 설정했지만 이 APK는 기존 리소스
검사에서 NSC 참조가 없었고 이번에도 그 분석 단계에 도달하지 못했으므로 CA 경로를
검증했다고 주장하지 않는다. JVM은 현재 -Xmx4G지만 heap 한도와 RSS 한도는 다르다.
시스템 메모리 압박과 JVM 인덱싱 비용을 관측했으며, 누수나 특정 JEB 내부 단계가
원인이라고 단정하지 않는다. 추가 한도 상향 재시도는 하지 않았다.

다음 작업은 JEB JVM 메모리 예산의 선택 설정과 저메모리 조건에서의 실패/취소 진단을
보강한 후 재검증하는 것이다. 작은 heap만으로 대용량 분석 완료가 보장되지는 않는다.

검증 도구 신규 9개 회귀(실패/취소 보고서, 시간·RSS·시스템 여유 guard, 기존 출력 보존,
잘못된 한도 거부)가 통과했고 최종 전체 회귀는 **575 passed (77.11초)**였다.
이 테스트 통과를 amoremall 전체 분석 성공으로 해석하면 안 된다. 변경은 저장소 검증
도구와 문서에 한정되어 wheel 재빌드/독립 설치 검증은 반복하지 않았다.

## 2GiB JVM 힙 재시험 (2026-10-03)

선택적 JVM 힙 설정 추가 후 `--jvm-heap-mib 2048 --max-seconds 120
--max-rss-mib 4096 --min-available-mib 1024`로 같은 amoremall을 시험했다.
aapt2 옵션은 이번 시험에서 미설정이며 JEB 인덱싱 비용 확인에 초점을 뒀다.
120.396초에 시간 guard로 취소됐고 bridge_closed=true였다. 합산 RSS 피크는
2,551,390,208바이트(약 2.38GiB), Python 38,121,472바이트,
JEB 2,515,169,280바이트였다. 표본 피크 합계와 동시 합산 피크는 다를 수 있다.
보고서: `build/large-apk-20261003-heap2048/amoremall/summary.json`.

이 실행은 이전의 메모리 guard에 걸리지 않았지만 JEB DEX/CFG 인덱싱 단계에서
전체 분석이 미완료로 종료됐다. OOM 응답을 관측한 실행은 아니며 단순히 시간이 더
필요한지, GC 압박이나 다른 내부 처리가 원인인지는 현재 자료로 판별하지 못한다.
기본 JEB 요청 타임아웃(900초)과 별개로 검증 도구의 120초 guard를 사용했다.
다음 단계는 힙 2GiB와 메모리 guard를 유지한 더 긴 제한시간 시험 및 인덱싱 진행 진단이다.

## 2GiB 힙 장시간 인덱싱 검증 (결과 확인: 2026-10-04)

같은 원본에 600초 시간 제한, 합산 RSS 4,096MiB, 시스템 여유 1,024MiB guard를
적용했다. 보고서는 `build/large-apk-20261003-heap2048-long/amoremall/summary.json`이다.
실행은 **333.860초에 시스템 여유 메모리 guard로 취소**됐다. 600초 시간 제한이나
합산 RSS 한도에 도달한 것은 아니다. bridge_closed=true이며 프로젝트는 생성되지 않았다.
원본 SHA-256은 앞서 기록한 값과 다시 일치했다.

합산 RSS 표본 피크 2,539,896,832바이트(약 2.37GiB), Python 37,650,432바이트,
JEB 2,504,003,584바이트였다. 약 30초마다 JVM 누적 CPU 시간과 메서드 JSONL 파일
크기를 계측했다. 파일은 30.458초의 22,140,267바이트에서 121.020초의
187,430,031바이트, 332.631초의 427,780,393바이트까지 증가했다.
이 파일은 최종 프로젝트가 아닌 임시 내보내기 스트림이며 세션 정리 때 제거됐다.
증가를 통해 적어도 메서드 내보내기가 진행 중임을 확인했다. 완료율/남은 시간은 모른다.

마지막 JVM 누적 CPU 시간은 2,867.40625초다. 병렬 작업의 CPU 시간 합계라 벽시계
경과 시간보다 클 수 있으며, 이 수치만으로 GC 과부하/누수/교착을 단정하지 않는다.
시스템 여유 메모리는 다른 프로세스·캐시 등의 영향도 받으므로 guard 발동 전체를
AOSEye의 메모리 증가 탓으로 해석하지 않는다. 기존 보고서에는 중단 순간의 여유
메모리 숫자가 없고 guard 원인만 있다. 후속 계측 변경으로 새 실행부터 순간값과
주기별 여유 메모리를 저장한다. 과거 기록에 숫자를 소급해 채우지 않았다.

계측은 최대 1,200개 표본으로 제한하고, JVM CPU 접근 실패는 null로 남겨 메모리
감시를 중단하지 않는다. 신규 두 테스트로 스트림 크기/CPU 계측 및 CPU 접근 거부 시
취소·보고서 보존을 확인했다. 기본 애플리케이션의 시간/메모리 설정은 바꾸지 않았다.

**전체 분석, 최종 Python 모델 구성, 결과 저장/재열기는 여전히 미완료**다.
현재 메서드 수 예산 외에 내보내기 바이트 예산이 없고, 최종 모델을 구성하면 Python
메모리가 추가로 필요하다. 다음 작업은 메서드 내보내기 바이트 예산과 제한 도달 시
부분 결과/누락 진단을 구현·검증하는 것이다. 시스템 여유 guard를 낮춘 재시도는 하지 않았다.

최종 회귀 **596 passed (80.39초)**, 실제 JEB 9개 포함. 검증 도구와 문서만 수정했으며
wheel은 이전 JVM 힙 설정 단계 빌드를 유지했다. APK 전체 분석 성공을 뜻하지 않는다.
