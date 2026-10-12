# 제한된 ArrayList 데이터 흐름

직접 new-instance로 생성된 java.util.ArrayList의 무인자/용량 지정/컬렉션 복사 생성자, add(Object), get(int),
set(int,Object), add(int,Object), remove(int), addAll(Collection), addAll(int,Collection), clear(), toArray(),
clone(), size(), isEmpty(), iterator()를 모델링한다. 객체별 identity와 경로별 불변 tuple 슬롯을 사용한다.
별칭과 앱 내부 메서드 인자 전달을 지원하고, 미해결 가상 dispatch 및 비동기 경계를 통과하는
원소 trace에는 불확실성을 유지한다. set의 반환값은 교체 이전 원소로 추적한다.

ArrayList(int)는 알려진 0 이상 Java int 용량에서 빈 리스트로 초기화한다. 용량은 원소 수가
아니므로 64개 원소 한도와 별개이며 실제 메모리 예약/OOM 성공을 보장하지 않는다.
ArrayList(Collection)는 내용이 확인된 별도 ArrayList의 순서와 trace/불확실성을 복사한다.
원본 수정은 복사본 슬롯에 영향을 주지 않으며 중첩 객체를 깊게 복사하지 않는다.
알 수 없는/음수 용량, 미확정 원본, 다른 구현체, 자기 복사, 원소 예산 초과는 진단하고
목적지 내용을 미해결로 둔다. 생성자는 ArrayList 소유자의 invoke-direct 및 /range만 지원한다.

clone()은 ArrayList 소유자의 정확한 호출만 지원하며 별도 identity에 원소 trace와 불확실성을 복사한다.
원본/복제본 슬롯은 독립적이지만 원소 객체의 깊은 복사는 아니다. 원소 64개/리스트 객체 128개 예산을
공유하고 미해결 내용/예산 초과 시 결과를 생성하지 않고 진단한다.
size()/isEmpty()는 ArrayList/List/Collection 호출에서 알려진 슬롯 개수/빈 상태를 상수로 반환한다.
원소 trace를 반환값으로 옮기거나 기존 리스트 내용을 지우지 않는다. 미해결 내용은 진단하며 반환값도
미해결로 둔다. 기존 엔진의 조건 분기 정밀 판정이나 실행 가능성 증명을 추가한 것은 아니다.

iterator()는 알려진 ArrayList에서 별도 반복자 identity를 만들고, Iterator.hasNext()/next()의
순서/커서를 추적한다. ArrayList/List/Collection/Iterable 소유자의 생성 호출과 Iterator 인터페이스
호출(/range 포함)을 지원한다. 별칭은 커서를 공유하고 각각 생성한 반복자는 독립적이다.
경로당 반복자 객체 128개 한도를 적용하며 원소 trace의 불확실성을 유지한다.
생성 이후 원본 ObjectValue가 변경되면 set처럼 실제로 허용될 수 있는 변경도 보수적으로 미해결
처리한다. 가상 호출/비동기 경계의 불확실성 재표시로 원본 상태가 바뀐 경우도 마찬가지다.
next 범위 초과, 미확정 수신자/원본, 예산 초과는 진단한다. forEachRemaining 등 미지원
반복자 연산은 반복자와 원본 내용을 무효화한다. fail-fast 예외와 동시성의 정밀 모델은 아니다.
Iterator.remove()는 성공한 next의 마지막 위치를 한 번만 삭제한다. 이후 원소의 trace 위치를
왼쪽으로 이동시키고 해당 반복자의 커서/원본 스냅샷을 갱신한다. 리스트 및 반복자 별칭에 반영하되
같은 리스트의 다른 반복자는 기존 스냅샷과 달라져 미해결이 된다. hasNext는 삭제 권한을 소비하지 않는다.
next 이전 삭제, 중복 삭제, 외부 변경 후 삭제는 진단하며 원본을 추가로 수정하지 않고 반복자를
미해결로 둔다. 예외 발생 후 제어 흐름이나 실제 ConcurrentModificationException의 정밀 증명은 아니다.
기존 CFG 방문 한도(명령당 2회)는 그대로이므로 긴 반복문의 모든 원소 분석을 보장하지 않는다.

get/set/remove의 인덱스는 알려진 유효 정수여야 한다. 위치 지정 add는 0부터 현재 크기까지 허용한다.
삽입은 이후 원소를 오른쪽으로, 삭제는 왼쪽으로 이동시키고 trace에 위치 이동을 기록한다.
remove의 반환값에는 삭제된 원소 trace를 전달한다. 미확정 인덱스는 진단하며 get은 결과를
미해결로, set/위치 지정 add/remove는 리스트 내용을 미해결로 만든다. 이는 안전성 판정이 아니다. 미지원 연산과
외부 호출도 기존 슬롯을 조용히 재사용하지 않도록 무효화/진단한다. clear는 빈 상태로 갱신한다.
최대 원소 64개와 경로당 리스트 객체 128개 제한 및 기존 CFG/호출 예산을 적용한다.

addAll은 원본과 목적지 모두 확인된 ArrayList이며 슬롯 내용이 알려진 경우에만 지원한다.
원본 순서대로 trace/불확실성을 복사하고 위치 지정 삽입의 기존 원소 이동을 기록한다.
원본 리스트의 이후 수정은 목적지 슬롯을 변경하지 않는다. 빈 원본은 변경 없이 false를 반환한다.
합산 64개 한도, 미확정 원본/인덱스, 다른 구현체 및 자기 자신 추가(빈 리스트 포함)는
목적지 내용을 무효화하고 진단한다. 자기 자신 추가를 런타임 결과로 단정하지 않는다.
Collection 소유자는 인덱스 없는 addAll만, List/ArrayList 소유자는 두 형태를 지원한다.

인자 없는 toArray()는 순서를 유지한 별도 Object[] identity를 생성하고 각 슬롯의 trace와
불확실성을 복사한다. 이후 리스트 set/clear와 배열 원소 덮어쓰기는 서로 영향을 주지 않는다.
이는 원소 객체를 깊게 복사하는 모델이 아니다. 기존 배열 한도(길이 64, 객체 128개)를 공유하며
내용 미해결/예산 초과 시 결과 배열을 만들지 않고 진단한다. 빈 리스트는 길이 0 배열을 만든다.

toArray(T[])는 인자 배열의 런타임 타입이 정확히 Object[]이고 길이/내용이 확인된 범위에서 지원한다.
인자 배열이 작으면 별도 배열을 할당하고, 충분히 크면 같은 identity를 반환하며 별칭에도 변경을 반영한다.
큰 배열의 복사 직후 한 슬롯은 null로 지우고 그 뒤 슬롯은 유지한다. 이전 미확정 인덱스 쓰기의
대표 trace는 미수정 꼬리 슬롯에만 불확실한 상태로 남긴다. 배열 재사용은 새 객체 예산을 소비하지 않는다.
미확정 수신 객체/리스트 내용/배열 길이, 미지원 배열 타입, 한도 초과는 진단하며 추적 중인 목적지 배열
내용을 무효화한다. 이는 예외 경로를 정밀하게 모델링하거나 변환 성공을 증명하는 처리가 아니다.

ArrayList로 직접 생성되었다는 identity가 확인되면 List의 add/get/set/remove(int)/clear/toArray() 및 Collection의
add/clear/toArray() 인터페이스 호출도 지원한다. invoke-interface와 /range를 모두 처리하며 원래 trace의
불확실성은 유지한다. 인터페이스 타입 선언만으로 실제 객체를 ArrayList라고 추정하지 않는다.
미확정/다른 구현체는 진단하고, 잘못된 opcode/인자 수/소유자 메서드는 슬롯을 무효화한다.
서브클래스 dispatch, remove(Object)/ListIterator/stream, String[] 등 타입 제약이 있는
toArray 인자 배열, IntFunction 오버로드, 중첩 객체 identity,
일반 Map/Set 및 동시성은 미지원이다. 제한된 HashMap은 `MAP_FLOW.md`에 별도로 기록했다.
모든 컬렉션의 의미 분석이나 실제 런타임 접근 증명이 아니다.
분석 정책 식별자는 bounded-arraylist-v16-array-addall이며 과거 프로젝트를 자동 재분석하지 않는다.

검증: 별칭/다른 리스트 음성, set/clear 이후 오탐 차단, set 이전 값 반환, 원소 예산,
미지원 연산, 미해결 인덱스, 경로 분리 및 직접/가상 호출 전달을 합성 DEX DTO로 확인한다.
Provider query의 실제 JEB 시험은 배열→List.addAll(index,source)→Collection.addAll(source)
흐름을 검증한다. 두 원본의 clear 후에도 복사한 입력 흐름만 유지되고 안전 슬롯/목적지 clear 후
흐름은 검출되지 않는다. DTO에서는 직접/인터페이스/range, 인덱스 경계, 빈 원본 반환값,
별칭/경로 분리, 불확실성 및 자기 추가/미확정 입력/예산 초과를 검사한다.
query는 용량 지정 생성자와 컬렉션 복사 생성자의 실제 DEX 호출도 검사하며 복사 직후 원본을
clear해도 입력 흐름이 유지되는지 확인한다. DTO는 용량 경계, 빈 복사, 불확실성/경로 분리,
미확정/다른 구현체/자기 복사/예산 및 잘못된 소유자·명령·인자 수를 검사한다.
query에 clone 후 원본 clear와 size/isEmpty 조회를 추가했다. 기존 입력 흐름과 안전 슬롯 음성을
실제 JEB로 검증한다. DTO는 크기/빈 상태/미해결 상태, 복제 identity, 빈 복제와 예산 실패를 검사한다.
query에서 Iterable.iterator→Iterator.next를 통한 첫 원소 입력 흐름과 둘째 안전 원소 음성을
실제 JEB로 확인한다. DTO는 별칭/독립 커서/경로 분리, 순서/종료/빈 리스트,
불확실성, 원본 변경, 미지원 forEachRemaining 및 생성 예산을 검증한다.
query의 next 후 remove와 원본 get/다음 next의 안전한 원소 음성도 실제 JEB로 검증한다.
DTO는 앞/중간/마지막 삭제, 위치 이동/불확실성, 별칭/다른 반복자/경로 분리, 안전 원소 삭제,
hasNext 사이 호출, 순서 위반 및 연속 next/remove를 검사한다.
Provider openFile Java fixture는 배열 입력을 리스트에 add하고 get으로 읽은 뒤 sink에 전달한다.
실제 JDK/D8/JEB 분석에서 최초 get 흐름과 toArray 스냅샷의 배열 읽기 흐름을 검출하고,
set 및 clear 후 안전 값의 get과 배열 덮어쓰기 후에는 흐름이 생기지 않음을 검사한다.
Collection.toArray의 배열 수정이 원본 List.get/remove 흐름을 지우지 않는지도 확인한다.
프로젝트 저장/재열기와 Review 증거 확인도 기존 통합 시험에 포함된다.
Provider call fixture에서는 Collection.add/clear와 List.get/set의 실제 invoke-interface DEX를
확인하고, 배열 복사→Collection.add→List.get 및 List.remove(int) 반환 흐름을 검사한다.
Object[] 인자 변환은 실제 JEB에서 Collection 호출의 배열 재사용과 List 호출의 새 배열 생성 흐름을
추가로 검출하고, null로 지운 슬롯과 안전한 꼬리 슬롯은 검출하지 않는다(call의 총 흐름 4개).
DTO 시험은 빈/같은 크기/작은/큰 배열, 별칭, 불확실성, 꼬리 wildcard, 예산 및 미확정 호출을 검증한다.
openFile의 앞쪽 삽입/삭제는 원소 위치 이동 증거와 기존 set/clear 음성을 함께 검증한다.
별도 DTO 시험은 앞/중간/끝 위치, 빈 리스트, 삭제 반환값, 별칭/경로 분리, 불확실성,
잘못된 인덱스와 예산 초과 및 Collection에 없는 위치 지정 메서드 거부를 확인한다.
일반 및 /range DTO 시험은 별칭·별도 객체·덮어쓰기·예산·미지원 호출을 같은 조건으로 검증한다.
APK를 설치하거나 실행한 것은 아니다. 증거는 build/jeb-provider-validation.json에 저장된다.

API 의미 참고: [Java ArrayList](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/ArrayList.html).
인터페이스 계약: [Java List](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/List.html),
[Java Collection](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Collection.html).

## Collections.swap

확인된 ArrayList의 알려진 두 정수 위치를 교환하는 Collections.swap(List,int,int)의
invoke-static 및 /range 호출을 지원한다. 양쪽 trace/불확실성을 교환하고 나머지 위치와 크기는
유지한다. 같은 유효 위치의 교환은 상태를 그대로 유지한다. 별칭은 교환 결과를 공유하지만
형제 분석 경로의 상태는 변경하지 않는다. 64개 원소 한도를 적용한다.
미확정/범위 밖 위치, 빈 리스트, 미확정 내용, 잘못된 형식/예산 초과는 내용을 무효화하고 진단한다.
다른 List 구현체는 추정하지 않는다. 예외 경로의 정상 실행 여부를 증명하는 모델은 아니다.
교환 이전 반복자는 기존 snapshot 정책에 따라 보수적으로 미해결 처리한다.
이는 Java의 비구조적 변경이 반드시 반복자를 무효화한다는 의미가 아니다.
실제 JEB query에서 이동한 입력 위치 양성과 안전 값 위치 음성을 검사하고, 원래 순서로
재교환한 후 기존 Iterator 시험을 유지한다. APK 설치/실행은 하지 않는다.
과거 저장 결과는 자동 재분석하지 않는다.
계약 참고: [Java Collections](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Collections.html#swap(java.util.List,int,int)).

## Collections.reverse

확인된 ArrayList의 Collections.reverse(List) 정적 호출 및 /range를 지원한다.
위치 i의 trace를 size-1-i로 이동시키며 불확실성, 별칭, 원소 수와 경로별 독립성을 유지한다.
빈 리스트와 단일 원소는 상태를 변경하지 않고, 홀수 길이의 중앙 trace도 그대로 보존한다.
64개 원소 한도 및 정확한 호출 형식을 검사하며 미확정 내용/예산/형식 실패는 기존 내용을
무효화하고 진단한다. 다른 List 구현체와 중첩 객체 identity는 지원하지 않는다.
실제 변경 후 기존 반복자는 swap과 동일하게 snapshot 정책상 보수적으로 미해결 처리한다.
이는 Java 런타임의 반복자 무효화나 예외 발생을 증명하는 것이 아니다.
DTO는 길이 0/1/2/3/4/63/64, 양방향 위치 이동, 중앙 값, 두 번 뒤집기, 별칭/경로 분리,
미확정 수신자/내용, 다른 구현체, 잘못된 호출/예산 및 반복자 처리를 검증한다.
실제 JEB query는 입력의 0→2 이동 양성과 안전한 0번 위치 음성을 검증하고 다시 뒤집은 뒤
기존 Iterator 시험을 유지한다. 저장/재열기 및 Review 검증도 유지한다.
계약 참고: [Java Collections.reverse](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Collections.html#reverse(java.util.List)).

## Collections.rotate

확인된 ArrayList와 알려진 Java int 이동량의 rotate(List,int) 정적 호출 및 /range를 지원한다.
원래 위치 i는 (i + distance) mod size로 이동하며 크기와 trace 불확실성을 유지한다.
음수, 길이보다 큰 이동, Java int 최솟값/최댓값을 처리한다. 빈 리스트 및 길이의 배수 이동은
상태를 그대로 유지한다. 별칭은 같은 결과를 보고 형제 분석 경로는 변경하지 않는다.
64개 원소 한도를 적용하며 미확정 내용/이동량, 잘못된 형식/정수 범위와 예산 초과는
내용을 무효화하고 진단한다. 빈 리스트라도 이동량이 미확정이면 보수적으로 미해결 처리한다.
다른 List 구현체/subList 뷰와 중첩 객체 identity는 미지원이다. 변경 전 반복자는 기존 snapshot
정책에 따라 미해결 처리하지만 실제 Java의 반복자 무효화를 단정하는 것은 아니다.
DTO는 양/음수 및 경계 이동량, 원상 복구, 별칭/경로 분리, 무변경과 실패 처리를 검증한다.
실제 JEB query는 길이 3에서 +4 이동의 입력 0→1 양성과 안전한 0번 위치 음성을 검사한다.
-4 이동으로 복구한 후 Iterator 입력 흐름도 확인한다.
계약 참고: [Java Collections.rotate](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Collections.html#rotate(java.util.List,int)).

## Collections.fill

확인된 ArrayList의 fill(List,Object) 정적 호출 및 /range에서 모든 기존 위치를 값 trace로
교체한다. 원소 수는 유지하며 빈 리스트에는 삽입하지 않는다. 입력 trace의 불확실성은 유지하고,
안전한 값/null의 trace 없는 쓰기는 기존 입력 흐름을 제거한다. 별칭은 변경을 공유하되
형제 경로는 변경하지 않는다. trace 부재 자체가 값의 안전성 증명은 아니다.
64개 원소 한도를 적용하며 미확정 내용/호출 형식/예산 실패는 내용을 무효화하고 진단한다.
비어 있지 않은 리스트에 추적 중인 객체 참조(자기 자신 포함)를 채우는 경우 중첩 identity를
지원하지 않으므로 진단 후 내용을 무효화한다. 다른 List 구현체는 지원하지 않는다.
변경 전 반복자는 기존 snapshot 정책에 따라 보수적으로 미해결 처리하며 런타임 무효화 증명은 아니다.
DTO는 길이 0/1/3/64, 입력/안전 값 덮어쓰기, 별칭/경로 분리, 불확실성, 미확정 내용/형식/예산,
중첩 객체와 기존 반복자를 검증한다. 실제 JEB query에서 fill 후 입력 흐름 및 안전 문자열/null
덮어쓰기 후 음성을 확인한다. APK 설치/실행 없이 저장/재열기와 Review도 검증한다.
계약 참고: [Java Collections.fill](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Collections.html#fill(java.util.List,T)).

## Collections.copy

확인된 ArrayList 간 copy(List,List) 정적 호출 및 /range를 지원한다. 원본 크기가 목적지 크기
이하일 때 앞부분의 같은 인덱스에 trace/불확실성을 복사하고 목적지의 나머지 항목과 크기는 유지한다.
trace 없는 원본 슬롯도 덮어쓴다. 원본의 이후 슬롯 변경은 목적지에 영향을 주지 않으며 깊은 복사는 아니다.
빈 원본 및 정확히 같은 객체로의 자기 복사는 상태를 유지한다. 별칭은 결과를 공유하고 형제 경로는 독립적이다.
64개 항목 한도, 양쪽 내용/구현체와 호출 형식을 검사한다. 목적지 크기 부족, 미확정 원본/목적지,
다른 구현체와 잘못된 형식/예산은 진단하고 확인된 목적지 내용을 무효화한다. 원본은 변경하지 않는다.
subList 등 겹치는 뷰, 일반 List 및 중첩 객체 identity는 미지원이다. 예외 경로를 증명하지 않는다.
변경 전 목적지 반복자는 기존 snapshot 정책에 따라 보수적으로 미해결 처리한다.
DTO는 빈/부분/전체 복사, 안전 슬롯 덮어쓰기와 입력 꼬리 보존, 별칭/경로 분리/불확실성,
원본 변경 독립성, 자기 복사와 실패 조건을 검증한다. 실제 JEB query는 복사 후 원본 clear에도
입력 흐름이 유지되고 안전 원본 재복사 후 제거됨을 확인한다. 손대지 않은 null 꼬리는 음성이다.
기존 권한 구분, Review 및 저장/재열기 검증을 유지한다.
계약 참고: [Java Collections.copy](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Collections.html#copy(java.util.List,java.util.List)).

## Collections.addAll의 배열 인자

확인된 ArrayList와 길이가 알려진 String[]/Object[] 사이의 정적 addAll(Collection,Object[])
호출 및 /range를 지원한다. 배열 슬롯을 순서대로 뒤에 추가하고 기존 항목을 유지한다.
빈 배열은 무변경/false, 비어 있지 않은 배열은 추가/true 상수를 반환한다.
원본 배열의 이후 슬롯 변경은 추가된 슬롯에 영향을 주지 않는다. 깊은 객체 복사는 아니다.
배열의 미확정 위치 쓰기(wildcard)는 기존 배열 모델과 같이 외부 trace를 우선하고 불확실성을
유지한다. 별칭은 같은 리스트 상태를 보고 형제 경로는 독립적이다.
배열 길이 한도와 추가 후 리스트 64개 항목 한도를 검사한다. 미확정 내용/길이/구현체,
잘못된 호출/예산 실패는 확인된 목적지 내용을 무효화하고 진단한다. 원본 배열은 변경하지 않는다.
다른 Collection 구현체, 기본형/다차원 배열과 중첩 객체 identity는 미지원이다.
DTO는 String[]/Object[], /range, 빈 배열, 슬롯 순서, prefix 보존, 원본 변경 독립성,
불확실성/wildcard, 상수 반환 및 실패 조건을 검증한다. 실제 JEB query에서 배열 추가 후
원본 덮어쓰기에도 입력 흐름 유지, 안전한 추가 슬롯/prefix 음성과 빈 배열 호출을 검사한다.
후속 Arrays.fill 및 정수 연산 검증을 포함한 query 총 흐름은 12개이며 APK 설치/실행 없이 Review와 저장/재열기도 확인한다.
계약 참고: [Java Collections.addAll](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Collections.html#addAll(java.util.Collection,T...)).
