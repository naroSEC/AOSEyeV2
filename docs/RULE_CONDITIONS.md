# 문맥 규칙 v2

RuleRegistry는 sources/transfers/sinks만 허용한다. 잘못된 필드/타입, 중복 sink ID,
중복 transfer 시그니처, 잘못된 enum/CWE/인자 인덱스를 ValueError로 거부한다.
YAML은 256KiB, 중첩 32, 노드 20,000 한도이며 alias/중복 mapping 키를 허용하지 않는다.
기존 정상적인 배포 규칙은 변경 없이 읽힌다. Python 식이나 사용자 코드 실행은 없다.

sink에 optional required_conditions 배열(최대 16개)을 지원한다. 모든 조건은 AND다.

```yaml
required_conditions:
  - kind: source_prefix
    prefix: 'Landroid/app/DownloadManager;->getUriForDownloadedFile('
  - kind: argument_constant
    argument: 2
    equals: 1
```

- source_prefix: 현재 trace의 source API 접두사. 미분류 external callback seed는 UNKNOWN.
- argument_constant: invoke register word 위치(인스턴스 receiver 포함)의 알려진 int/string과
  타입까지 비교한다. 넓은 인자는 DEX word 인덱스다. bool/임의 객체는 허용하지 않는다.
- argument_bits: 같은 인덱스의 정수 값에 `(value & mask) == equals`를 적용한다.
  mask는 1..0xffffffff, equals는 mask 밖의 비트가 없는 0..0xffffffff 정수다.
  입력 값은 signed int32 또는 unsigned uint32만 인정하며 bool/string/범위 밖은 UNKNOWN이다.
  예: `{kind: argument_bits, argument: 2, mask: 3, equals: 1}`.
  특정 API의 SDK별 플래그 의미나 권한 성립을 자동 추론하지 않는다.
- MET: 현재 모델의 모든 조건 충족. 런타임 실행/분기 실현/안전성을 확정하지 않는다.
- NOT_MET: 알려진 불일치. 해당 경로의 조건부 규칙 결과를 생성하지 않으며 안전 판정은 아니다.
- UNKNOWN: 값/인자가 미확정. REVIEW/MANUAL_REVIEW/LOW로 유지하고 attack_path를 만들지 않는다.

동일 결과 ID에서 MET 근거가 있으면 UNKNOWN 근거보다 우선한다. 상태는 Finding.validation과
evidence에 남으며 flow_coverage.required_condition_observations에 탐색 중 관측 횟수를 기록한다.
이 횟수는 유일 경로 수나 탐지 수가 아니다. 조건은 규칙 fingerprint에 포함된다.
DownloadManager 규칙이 이 DSL을 실제 사용한다.

제한: sanitizer 인증, 암호 검증, receiver 설정 이력, 일반 heap/분기 솔버, OR/부정/스크립트
조건은 미지원이다. 그 항목을 YAML에 적으면 무시하지 않고 거부한다.
조건의 존재만으로 source를 신뢰하거나 기존 흐름을 전역 제거하지 않는다.

단위/통합 회귀: test_rule_conditions.py, test_application.py, test_jeb_tls.py.
