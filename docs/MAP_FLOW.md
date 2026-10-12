# 제한된 HashMap 데이터 흐름

직접 생성된 java.util.HashMap의 무인자/용량 지정/Map 복사 생성자, put/get/remove/clear/putAll/clone,
getOrDefault/containsKey/size/isEmpty 및 2인자 replace를 지원한다.
HashMap 소유자의 직접 호출과 Map 인터페이스 호출(/range 포함)을 처리한다.
인터페이스 선언만으로 실제 구현체를 HashMap으로 가정하지 않는다.

HashMap(int)는 알려진 0 이상 Java int 용량에서 빈 맵으로 초기화한다. 용량과 키 개수는 별개이며
실제 메모리 할당 성공이나 해시 버킷 구조를 모델링하지 않는다. 음수/미확정 용량은 진단한다.
clone()은 HashMap 소유자의 정확한 호출에서 별도 identity와 키별 trace/불확실성을 복사한다.
항목 사전은 분리되지만 키/값 객체의 깊은 복사는 아니다. 64개 키/128개 맵 객체 한도를 공유하며
미해결 내용/예산 초과는 결과를 생성하지 않고 진단한다. Map 인터페이스의 clone은 지원하지 않는다.

키는 알려진 문자열 상수만 지원하며 키별 값 trace를 독립적으로 저장한다. put은 기존 값을 반환하고
덮어쓰기하며, remove는 삭제된 값을 반환한다. 없는 키의 get/remove에는 입력 trace가 없다.
안전한 값 덮어쓰기와 clear는 기존 입력 흐름을 제거한다. 사전 복사 후 교체 방식으로 별칭은
같은 객체를 보고 형제 CFG 경로의 내용은 바뀌지 않는다. 중첩 객체 identity는 지원하지 않는다.

replace(key, value)는 키가 존재할 때만 값을 교체하고 이전 값 trace를 반환한다.
기존 매핑이 null/trace 없는 값이어도 교체하며, 없는 키에는 삽입하거나 입력 trace를 전달하지 않는다.
기존 키 교체는 항목 수를 늘리지 않는다. 미확정/문자열 아닌 키는 내용을 무효화하고 진단한다.
3인자 조건부 replace의 값 비교는 지원하지 않는다.

putAll(Map)은 내용이 알려진 별도 HashMap의 항목을 복사하며 충돌 키는 원본 값으로 덮어쓴다.
안전한 값/trace 없는 매핑도 기존 입력 trace를 지운다. 목적지에만 있는 키는 유지한다.
HashMap(Map) 생성자는 알려진 원본에서 새 목적지 내용을 초기화한다. 이후 원본 수정은 복사된
슬롯에 영향을 주지 않으며 깊은 객체 복사는 아니다. 복사 후 서로 다른 키의 합집합에 64개 한도를
적용한다. 미확정 원본/putAll 목적지, 다른 구현체, 자기 복사와 한도 초과는 목적지 내용을 무효화하고
진단한다. 빈 원본의 putAll은 내용 유지, 복사 생성자는 빈 맵 초기화다.

getOrDefault는 키가 없을 때만 기본값 trace를 전달한다. 키가 존재하되 값에 trace가 없거나 null인
경우 기본값을 대신 전달하지 않는다. containsKey는 값 trace 유무가 아니라 키 존재 여부를 반환한다.
size/isEmpty는 알려진 항목 수/빈 상태를 상수로 반환하고 조회는 맵 내용을 변경하지 않는다.
미확정 키/내용은 기본값 사용이나 false/0으로 추정하지 않고 미해결로 진단한다.
정밀한 조건 분기 판정은 추가하지 않았으며 중첩 객체 기본값의 identity 반환도 미지원이다.

경로당 HashMap 객체 128개, 객체당 키 64개 한도를 적용한다. 한도 내 기존 키 교체는 가능하다.
미확정/문자열 아닌 키의 get은 결과를 미해결로 진단하고 put/remove/replace는 내용을 무효화한다.
미지원 메서드/잘못된 호출 형식, 외부 미모델 호출도 기존 내용을 재사용하지 않도록 무효화한다.
미확정 수신 객체와 원본 내용도 진단한다. 미검출이나 미해결은 안전성 판정이 아니다.

앱 내부 직접 호출로 전달되는 객체를 추적하며 미해결 가상 호출과 비동기 경계는 값 trace에
불확실성을 유지한다. 분석 정책 식별자는 bounded-hashmap-v5-replace다.
과거 프로젝트를 자동 재분석하지 않는다.

실제 JDK/D8/JEB Provider update fixture는 배열 복사 결과를 Map.put/get으로 전달한다.
최초 get과 없는 키의 getOrDefault 기본값 흐름을 검출하고 안전 값 덮어쓰기/remove/clear 이후 get은
검출하지 않는다. 안전한 값 또는 null 매핑이 있을 때 입력 기본값을 전달하지 않음도 확인한다.
containsKey/size/isEmpty 조회 후 원본 흐름 유지와 DTO의 상수 반환/미해결/불확실성도 검증한다.
update의 복사 생성자→원본 clear→putAll→복사 원본 clear 흐름도 실제 JEB로 검증한다.
안전한 값의 putAll 덮어쓰기 음성을 확인하며 DTO는 빈 맵/충돌 키/합집합 예산/자기 복사/
미확정 내용/다른 구현체/별칭/경로 분리/불확실성을 검사한다.
update의 용량 지정 생성자와 clone 후 원본 clear도 실제 JEB로 검증한다. DTO는 용량 경계와
크기 구분, 빈 복제, 독립 identity/항목 사전, 불확실성 및 복제 한도/미확정 내용 실패를 검사한다.
기존 권한 구분, Review 증거, 저장/재열기 검증도 유지한다. APK 설치/실행 시험은 아니다.
실제 JEB에서 replace 이전 값의 입력 흐름과 교체 후 안전 값/없는 키의 조회 음성을 검증한다.
DTO는 직접/Map 호출 및 /range, null/trace 없는 기존 매핑의 교체, 없는 키의 무삽입,
별칭/경로 분리/불확실성과 미확정 키/내용 및 조건부 replace 미지원 처리를 검사한다.
증거: build/jeb-provider-validation.json. DTO 시험은 별칭/없는 키/이전 값 반환/삭제 반환,
미확정 키/예산/경로 분리/다른 구현체/미지원 호출 및 직접·가상 호출 전달을 포함한다.

null/숫자/객체 키, 사용자 정의 equals/hashCode, 다른 Map 구현체, 부하율 지정 생성자,
compute/merge, keySet/values/entrySet 뷰와 반복자, Set 및 동시성은 미지원이다.
전체 Java 컬렉션 의미 분석이나 런타임 취약점 증명을 의미하지 않는다.

API 의미 참고: [Map](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/util/Map.html).
