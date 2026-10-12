# Security reporting and safe use

AOSEye is a static analysis aid, not a certificate that an APK is safe. Findings
can be incomplete or incorrect. Review evidence and documented model limitations.
Only analyze applications that you are authorized to inspect.

Treat APKs, project JSON, caches, exported IR and decompiled code as untrusted and
potentially confidential. Reports can contain source code and original strings
even when a finding's secret preview is masked. Use an isolated, least-privileged
analysis environment. Do not run AOSEye with administrator privileges just to parse
an APK. Keep JEB, Java, Python and dependencies updated under your testing policy.

No public vulnerability-reporting address has been configured yet. Before public
release, the maintainer must publish a private reporting channel in the release
repository. Do not post private APKs, license files, credentials or unredacted
projects in public issues. Provide a minimal synthetic reproducer, affected version,
expected/actual behavior and impact through the configured private channel.

There is currently no declared security-support period or response-time guarantee.
Those policies and the private reporting channel are release-owner decisions, not
implied by the presence of this file.
