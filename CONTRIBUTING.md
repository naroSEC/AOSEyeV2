# Contributing

Install Python 3.11 or newer and create a dedicated virtual environment. From the
source root, run `python -m pip install -e ".[test]"`, then `python -m pytest -q`.
Tests requiring licensed JEB, Android tools or private samples may skip by default;
that run is not the complete release regression.

For local JEB integration set AOSEYE_JEB_PATH to your licensed installation,
AOSEYE_RUN_JEB=1 and AOSEYE_TEST_AAPT2 to an absolute aapt2 executable path.
Use Java 21. Consult docs/RELEASE_READINESS.md for release evidence requirements.
Never upload your JEB installation or license to a CI service.

Each detection change needs positive and negative synthetic tests, evidence
locations, bounded parsing/traversal and cancellation behavior. Preserve the
distinction between API presence, review candidates and demonstrated weaknesses.
Unknown behavior must not become a safe verdict. Do not add network requests to
target application services or execute supplied APKs as part of static analysis.

Do not commit customer APKs, generated reports, caches, credentials or local paths.
Prefer synthetic source fixtures. Do not add dependencies without reviewing their
licenses and packaging impact. New contributions must be compatible with MIT;
do not submit code or assets you lack permission to contribute.

The project repository is https://github.com/naroSEC/AOSEyeV2. Use issues for
non-sensitive bug reports and feature requests. Follow SECURITY.md for sensitive
reports; never include customer data or credentials in public issues.
