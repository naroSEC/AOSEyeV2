# 2026-10-11 독립 설치의 의존성 관측

Windows / Python 3.14.2 새 가상환경에서 wheel 설치와 pip check를 통과했다.
이 목록은 해당 설치의 관측값이며 버전 고정 파일, 취약점 검사 결과, SPDX SBOM 또는
법률 검토 결과가 아니다. 버전 범위 내 재설치는 다른 버전을 받을 수 있다.
License-Expression 또는 License 필드가 알려 주는 값만 기록했다.

- cffi 2.1.1: MIT-0
- cryptography 48.0.1: Apache-2.0 OR BSD-3-Clause
- defusedxml 0.7.1: PSFL
- pycparser 3.11: BSD-3-Clause
- PySide6 / PySide6_Addons / PySide6_Essentials / shiboken6 6.12.0:
  LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
- PySide6_Pdf / PySide6_WebEngine 6.12.0.140:
  LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only
- PyYAML 6.0.3: MIT

메타데이터만으로 포함된 모든 Qt/native 코드의 조건을 설명할 수 없다. 각 배포물의
실제 라이선스·고지와 선택한 배포 방식에 따른 조건을 확인해야 한다. AOSEye wheel은
이 의존성을 내장하지 않는다. EXE/오프라인 묶음을 만들 때는 별도의 검토가 필요하다.
자동 취약점 피드 조회나 수동 의존성 보안 검토는 이 실행에 포함되지 않았다.

AOSEye 자체의 MIT 선택과 제3자 조건의 충족은 별개다. release acceptance의 licensing은
MIT 선택만으로 자동 승인하지 않는다. JEB/Java/Android SDK도 이 Python 목록과 별도다.
