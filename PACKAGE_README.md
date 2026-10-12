# AOSEye

Evidence-oriented Android APK static analysis using a user-supplied local JEB
installation. Python / PySide6 / Qt Quick. AOSEye code is MIT licensed; JEB and
other dependencies have separate licenses and are not included in the wheel.

Status: pre-release, incomplete analysis coverage. Automated tests are not a
guarantee of accuracy or a complete security assessment. Windows is the tested
integration platform; other platforms and clean-machine installations are not
yet qualified.

## Prerequisites and startup

Python >=3.11, Java 21 and a separately licensed JEB installation permitting Core
API operations. Actual integration qualification currently uses Python 3.14.2
and JEB 5.47. Install the supplied wheel in a fresh virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install .\aoseye-0.1.0-py3-none-any.whl
.venv\Scripts\aoseye.exe probe --jeb-path 'C:\path\to\licensed-jeb'
.venv\Scripts\aoseye.exe
```

Set the JEB installation directory in **JEB settings** to save it for the GUI.
There is no default path or automatic installation search. AOSEYE_JEB_PATH is an
optional explicit environment setting; saved settings take precedence. CLI
`--jeb-path` overrides the path only for that invocation.

APK files are analyzed statically, not installed or executed. A partial result or
exit code 2 must not be interpreted as an APK safety verdict. Saved projects and
exports may include sensitive original strings or code; review them before sharing.
Back up settings and projects before upgrading. Use a new environment to validate
an update and retain the old environment for rollback.

See LICENSE, THIRD_PARTY_NOTICES.md, SECURITY.md and CONTRIBUTING.md in the source
distribution. Full implementation limits and release blockers are recorded under
docs; publication and owner acceptance are still pending.
