# 제한된 참조 배열 흐름

지원 범위는 길이가 상수인 String[]/Object[]의 new-array, aput-object, aget-object다.
filled-new-array 및 filled-new-array/range도 지원하며 원소별 초기 trace와
직후 move-result-object로 전달되는 배열 identity를 보존한다.
배열당 최대 64개 원소, 경로 메모리당 최대 128개 배열을 모델링한다. 기존 CFG/호출 예산도
그대로 적용된다. 할당별 identity와 경로별 copy-on-write 원소 상태를 사용한다.
move 별칭, 직접 호출의 배열 인자·반환 및 알려진 인덱스의 강한 덮어쓰기를 지원한다.

알 수 없는 인덱스 쓰기는 wildcard로, 읽기는 가능한 저장값 중 대표 trace로 처리한다.
이 경우 POTENTIAL과 진단을 남긴다. 알려진 원소에 덮어쓰면 해당 위치의 이전 wildcard를
제거하고 다른 위치에만 불확실한 trace로 보존한다. 여러 source를 완전 열거하지 않으며 대표 외부 입력 trace를 우선한다.
가상 호출과 비동기 경계를 통과하는 배열의 trace에는 불확실성을 유지한다.

미지원: 원시형/다차원 배열, 배열 내부 객체 identity, 외부에서 들어온 배열 원소,
fill-array-data, 일반 객체 clone 및 컬렉션 의미 분석.
크기·타입·identity·예산을 확인하지 못하면 진단을 남긴다. 외부 미지원 호출에 넘긴
배열 내용은 기존 tracked object 무효화 정책을 적용한다. 예외 발생이나 인덱스 범위에
따른 전체 경로 차단을 증명하지 않는다. 진단 없는 다른 부분도 실행 가능성 증명은 아니다.

테스트는 정확한 슬롯, 다른 슬롯/배열 음성, 덮어쓰기, 별칭, 미확정 인덱스, 크기 제한,
직접/가상 호출을 다룬다. 기존 Provider Java fixture의 query도 배열 저장→읽기→sink로
변경해 실제 JDK/D8/JEB의 배열 명령과 데이터 흐름 근거를 함께 검사한다.
분석 정책 식별자는 bounded-reference-arrays-v11-length이다. 과거 프로젝트는 자동 재분석하지 않는다.

초기화 배열 검증에는 슬롯 구분/덮어쓰기, 원소 수 초과, 미지원 원시형, 잘못된 결과 전달
시퀀스의 오래된 identity 차단을 포함한다. Provider fixture의 openFile은 일반 초기화 배열,
call은 6개 원소 초기화 배열을 사용해 실제 DEX의 일반 및 /range 명령을 검사한다.
범위 형식의 레지스터 확장은 기존 JEB 정규화 계층에서 수행한다. 중첩 객체 identity와
전체 source 열거는 여전히 지원하지 않으며, 개별 슬롯의 대표 trace만 보존한다.

## 제한된 System.arraycopy

같은 지원 배열 타입의 source/destination identity와 세 정수 인자가 확인되고 양쪽
범위 안에 있을 때만 슬롯을 복사한다. 복사 전 상태를 읽어 동일 배열의 겹친 구간도
처리한다. 안전 슬롯 복사는 목적지의 기존 슬롯 trace를 지우며 원본 배열과 다른 CFG
경로의 메모리를 변경하지 않는다. 목적지 기존 wildcard는 복사 구간 밖에 보존하며 복사된 wildcard
trace는 불확실성을 유지한다.

identity/타입/범위를 확인하지 못하면 목적지 내용을 무효화하고 진단을 남긴다. 이는
복사가 성공하지 않았다는 판정이 아니라 미지원 범위 공개다. 타입 간 대입 호환성,
부분 ArrayStoreException, 실제 예외에 따른 전체 CFG 차단은 모델링하지 않는다.

원본/별도 경로 보존, 겹침, 안전 값 덮어쓰기, 0개 복사, 미해결 인자/타입/범위와 wildcard를
단위 검증한다. Provider query fixture의 실제 DEX에도 System.arraycopy 호출을 추가하여
JEB에서 배열 저장→복사→읽기→sink 증거를 확인한다.
겹침 의미의 근거: [Java System.arraycopy API](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/lang/System.html).

## 제한된 배열 clone

정확한 String[]/Object[] clone 호출과 같은 타입의 알려진 배열 identity만 처리한다.
새 배열 identity를 만들고 슬롯별 대표 trace 및 기존 불확실성을 보존한다. 원본과 복제본의
슬롯은 독립적으로 갱신된다. 복제도 경로당 128개 배열 예산을 사용한다. 타입/identity/예산이
불확실하면 결과 identity를 만들지 않고 진단한다. 일반 객체의 사용자 정의 clone을
배열 복제로 가정하지 않는다. 다차원 배열이나 배열 안 객체의 깊은 복사 모델은 아니다.

단위 시험은 원본/복제본 덮어쓰기, 원본 별칭 보존, 새 identity, 미확정 수신자, 예산,
기존 불확실성 보존을 다룬다. 실제 Provider update DEX에서는 clone 후 원본을 안전 값으로
덮어써도 복제본→sink 흐름이 남는지 JEB로 검증한다. 컴파일러의 초기화 명령 선택은
바뀔 수 있어 해당 시험은 new-array/aput와 filled-new-array를 모두 허용하되, openFile과
call 시험에서 일반 및 /range 초기화 명령을 별도로 검증한다.
의미 참고: [Java 배열 명세](https://docs.oracle.com/javase/specs/jls/se21/html/jls-10.html).

## 제한된 Arrays.copyOf

참조 배열의 2인자 copyOf(Object[], int)만 모델링한다. 알려진 String[]/Object[]의
원래 타입을 유지한 새 identity를 만들며, 복사 길이는 상수 0~64로 제한한다.
짧아진 부분의 trace는 버리고 늘어난 꼬리는 null 슬롯으로 취급한다. 원본의 미확정
인덱스 wildcard도 원본 범위 안의 슬롯에만 불확실 trace로 옮겨 꼬리에 전파하지 않는다.
복제와 같은 128개 배열 예산을 사용하며 실패 시 원본은 유지하고 결과를 미해결로 남긴다.

길이 축소/확장/0, 원본 보존, 음수/미해결/초과 길이, wildcard의 padding 비전파 및 예산을
검증했다. 실제 Provider update DEX는 clone 결과를 copyOf로 늘린 후 원래 슬롯과 추가된
슬롯을 각각 sink에 넘긴다. 원래 슬롯의 흐름만 발견되고 저장/Review 근거에도 복사 단계를
보존한다. null 접근의 실행 결과나 예외 경로를 검증한 것은 아니다.
원시형 및 타입 지정 3인자 copyOf 오버로드는 아직 미지원이다.
의미 참고: [Java Arrays API](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Arrays.html).

## 제한된 Arrays.copyOfRange

참조 배열용 3인자 copyOfRange(Object[], from, to)를 지원한다. 알려진 String[]/Object[]와
상수 from/to가 필요하며 0 <= from <= 원본 길이, from <= to 및 결과 길이 <= 64를 검사한다.
원본 from+i를 새 배열 i로 옮기고 원본 끝을 넘는 꼬리는 null 슬롯으로 유지한다.
from이 원본 길이와 같으면 빈 복사 구간과 null 확장을 허용한다. 원본 wildcard는
실제 복사 구간에만 불확실 trace로 옮겨 padding 오탐을 피한다. 기존 배열 수 예산도 적용한다.

음수/역전/미해결/초과 범위는 결과를 미해결로 남기고 진단한다. 실제 예외에 의한 CFG
차단, 원시형 배열 및 결과 타입을 지정하는 4인자 오버로드는 지원하지 않는다.
copyOf와 공통 구현을 사용하므로 기존 copyOf 회귀도 함께 실행한다.

실제 Provider call DEX에서 from=1의 위치 이동과 원본 끝 이후의 null 확장을 검사한다.
유효 슬롯은 POTENTIAL로 유지되고 추가된 null 슬롯에는 입력 흐름이 생기지 않는다.
이는 정적 모델 검증이며 실제 API 호출을 Android에서 실행한 시험은 아니다.

## Arrays.fill 전체 배열

2인자 Arrays.fill(Object[],Object)의 정적 호출 및 /range를 지원한다. 런타임 타입이 정확히
Object[]이고 길이가 알려진 0~64 범위일 때 모든 슬롯 trace를 교체한다. 입력 불확실성을 유지하고
안전 값/null 쓰기는 기존 슬롯과 미확정 위치 쓰기(wildcard)의 trace도 제거한다.
빈 배열은 무변경이며 별칭은 같은 결과를 보고 형제 경로는 독립적이다. 새 배열을 할당하지 않는다.
미확정/잘못된 길이·호출·예산 또는 비어 있지 않은 배열의 중첩 객체 참조는 진단하고 배열 내용을
무효화한다. String[] 등 저장 타입 제약 배열과 기본형/다차원 배열은 미지원이다.
배열 저장 타입 검사와 예외에 의한 CFG 차단은 증명하지 않는다. trace 부재는 안전성 보장이 아니다.
DTO는 빈/단일/복수/최대 길이, 전체 덮어쓰기와 wildcard 제거, 불확실성, 별칭/경로 분리 및 실패를
검증한다. 실제 JEB Provider query는 입력 fill 양성과 안전 문자열/null 덮어쓰기 음성을 검사한다.
기존 Review와 저장/재열기를 유지한다. APK 설치/실행 시험은 아니다.
계약 참고: [Java Arrays](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Arrays.html).

## Arrays.fill 범위 지정

4인자 fill(Object[],from,to,value)의 정적 호출 및 /range를 지원한다. 정확한 Object[]와
알려진 정수 범위 0 <= from <= to <= length에서 [from,to)만 교체하고 구간 밖 trace는 유지한다.
유효한 빈 구간은 무변경이다. 전체/부분 덮어쓰기, 별칭/경로 분리와 입력 불확실성을 유지한다.
이전 wildcard는 덮어쓴 구간에서 제거하며 구간 밖 슬롯에 불확실한 trace로 반영한다.
역전/음수/길이 초과/미확정 범위와 잘못된 호출·타입·예산, 중첩 객체 값은 진단하고 내용을
무효화한다. 실제 예외 경로 차단이나 저장 타입 검사를 증명하지 않는다.
DTO는 경계/빈 구간/전체/부분 쓰기, wildcard의 선택적 제거, 불확실성, 별칭과 실패를 검증한다.
실제 JEB query에서 입력 구간 양성, 제외된 종료 위치 음성, 구간 밖/빈 구간 보존 및 null
덮어쓰기 후 음성을 확인한다. 후속 정수 연산 검증을 포함한 query 총 흐름은 12개다. 기존 2인자 fill 회귀도 함께 검증한다.

## System.arraycopy 덮어쓰기 보정

목적지에 과거 미확정 위치 쓰기(wildcard)가 있으면 복사 구간에서도 그 trace가 남던 문제를 수정했다.
복사된 구간은 원본 슬롯으로 교체하고 목적지의 기존 wildcard는 구간 밖 슬롯에만 불확실한 trace로
보존한다. 원본의 wildcard는 계속 전달하며 겹치는 복사도 호출 이전 상태에서 읽는다.
길이 0 복사는 상태를 그대로 유지한다. 슬롯별 보존 처리 전에 양쪽 길이의 0~64 한도와 참조 배열
타입을 검사한다. 잘못된 범위/길이/타입은 목적지를 무효화하고 진단한다.
수정 전 새 회귀 시험 13개 실패를 확인했고 수정 후 추가 길이 검증까지 포함해 통과했다.
실제 JEB fixture는 미확정 인덱스 쓰기 후 부분/전체 안전 복사에서 덮어쓴 위치의 음성을 확인한다.
이는 오탐 감소 보정이며 미해결이나 검출 부재가 안전성 증명은 아니다.

## 단일 슬롯 덮어쓰기 보정

aput-object의 알려진 인덱스 쓰기에서도 해당 위치의 이전 wildcard를 제거하도록 보정했다.
다른 슬롯은 기존 외부 trace를 우선하며 wildcard에서 온 값은 불확실성을 유지한다.
안전한 문자열/null은 해당 위치의 입력 흐름을 지우고 새 입력은 자신의 trace로 교체한다.
후속 미확정 쓰기는 이미 덮어쓴 위치에 다시 영향을 줄 수 있다. 모든 슬롯을 안전 값으로
차례로 덮어쓰면 이전 wildcard 흐름이 남지 않는다. 별칭/형제 경로 분리와 64개 길이 한도를 유지한다.
수정 전 8개 실패를 재현했고 직접 상태 검사와 파이프라인 회귀, 실제 JEB의 안전 문자열/null
단일 슬롯 덮어쓰기 음성을 검증했다. 구간 밖 입력은 POTENTIAL이며 안전성 증명으로 취급하지 않는다.

## array-length

확인된 String[]/Object[]의 0~64 길이를 array-length 목적지 레지스터의 정수 상수로 전달한다.
목적지의 오래된 trace/참조/상수는 제거하며 원소의 입력 trace를 길이에 복사하지 않는다.
같은 레지스터가 원본/목적지인 경우 호출 이전 상태로 읽는다. 배열 객체와 별칭 내용은 변경하지 않는다.
미확정 수신자/길이, 미지원 타입, 형식 및 길이 한도 실패는 진단하고 오래된 목적지 값을 남기지 않는다.
DTO는 0/1/64 길이, 원본/목적지 중복, defs 없는 입력, 상수를 이용한 후속 new-array와 실패를 검증한다.
실제 JEB에서는 직접 호출되는 arraySize 보조 메서드에 array-length가 존재함을 확인하고 반환 길이를
Arrays.fill의 종료 인자로 전달한다. D8의 직접 길이 상수 최적화를 피한 fixture다.
일반 정수 산술/분기 증명이나 외부 배열의 길이 추정은 추가하지 않았다.
명령 의미: [AOSP Dalvik bytecode](https://source.android.com/docs/core/runtime/dalvik-bytecode).
