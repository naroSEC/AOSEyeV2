# AOSEye architecture and delivery roadmap

QML → GUI controller/model → application jobs → analyzers / core → AnalysisBackend → JEB process.
Only the Jython bridge imports JEB types. JSON protocol v1 carries original DEX signatures,
byte offsets, registers, resolved pool references, CFG edges and diagnostics into Python.
Decompiler output is supporting evidence, never the input to taint analysis.

## Core contracts

`AnalysisBackend`: probe, load, class/method/field index, callers/callees/XREF, CFG,
AST and decompiled text. Unsupported capabilities raise an explicit exception.
`Program`: DEX unit inventory, full method declarations, bounded method bodies,
normalized instructions, class hierarchy, manifest and diagnostics. `Method.ast` is
an optional, lazily loaded flat Java AST DTO with parent IDs and physical DEX offsets.
`Finding`: stable identifier, internal rule ID, independent type/severity/confidence/
verification/analysis level, location, source/sink, path, validation, evidence and standards.
`AnalysisResult`: schema version, input SHA-256, provenance, completeness, diagnostics,
findings, program, archive index and analyst notes. JSON is also the v1 project format.

## Implementation order

1. Foundation: package, settings, logging, backend contracts, executable JEB probe,
   versioned models, cancellable subprocess, background jobs and QML shell.
2. APK: bounded ZIP reads without extraction, manifest and component exposure,
   deep-link inventory, sensitive assets with masked evidence, DEX/CFG and call indexes.
3. Flow: CFG-path traversal, register kills/moves, arguments/returns, path-local fields,
   declarative source/transfer/sink models, bounded context-sensitive calls and attack paths.
4. Verification UI: filtering, finding detail, original bytecode, on-demand decompilation,
   callers/callees/CFG, path graph, project reopen/export and notes.
5. Follow-up: object-sensitive heap, virtual dispatch resolution, ICC/lifecycle modeling,
   dominance-checked scheme/host sanitizers, richer AST/IR, resource decoding, TLS/auth/
   storage semantics, performance benchmarking, HTML/CSV and alternate backends.

## Accuracy boundaries

Static evidence is not proof of exploitability. API presence produces REVIEW/INFO.
An actual modeled source-to-sink register path can produce a potential vulnerability.
An enabled, permission-free exported lifecycle entry supports L5, but remains LIKELY
or POTENTIAL, never automatically CONFIRMED. Unknown validation remains UNKNOWN.
Path exploration follows real CFG successors but does not solve branch predicates.
Virtual calls, field aliasing, native/reflection/ICC and budget exhaustion are disclosed.
No absence-based resilience vulnerability is manufactured.

Candidate review adds an independent declared-call reverse search, bounded by 10,000
methods and depth 32, plus explored potential ICC/async edges. `NO_MODELED_PATH_FOUND`
is distinct from `INCOMPLETE` and is never a dead-code proof. A found graph witness is
not a taint witness and does not automatically promote a finding to L5.

For at most 2,000 instructions/128 branches per observed method, review records whether
a branch dominates the sink/return offset and which CFG successors can reach it.
Only an unambiguous invoke→move-result→branch sequence is annotated as a predicate
producer. No predicate meaning, accepting edge or data identity is inferred from this
structure, so scheme/host/null validation remains UNKNOWN. JEB native references are
retained verbatim with separate operand-match annotations; broad native references
are not inserted blindly into the declared call graph.

The initial flow engine supports concrete paths with bounded loop/call depth and per-path
field state. It is deliberately incomplete; instance fields use signatures (not object IDs)
and lower confidence. Unknown external calls do not arbitrarily taint their return values.
Only explicit library transfer models propagate taint. Sanitizer suppression is reserved
for a later implementation that proves checks dominate a sink on its accepting branch.

Transfer rules use exact `signatures` plus explicit `arguments` indices (including the
receiver at index 0 for instance invokes), with an optional boolean `uncertain` flag.
Legacy string-only transfer rules are rejected with a schema error rather than silently
propagating every argument. Bundle lookup keys and URI query parameter names do not
taint the return value by themselves; Bundle defaults can. WebView base URL and HTML
data are separate sink roles; history URLs and evaluation callbacks are not code sinks.
Analysis provenance records the normalized rule-set SHA-256 and policy identifier.

### Bounded object and boundary model

`core/objectflow.py` keeps path-local allocation IDs for Intent and concrete classes
with a resolvable `run()V`. IDs remain distinct across repeated calls to one factory.
Moves, call arguments and returned references preserve identity. Immutable object values
plus copied maps isolate sibling CFG paths. Known-object scalar fields use object identity;
the previous conservative signature-keyed heap remains for untracked objects/static fields.
Nested object-reference fields are not followed and generate coverage diagnostics.

Intent targets require a DEX `const-class` value, not a string resembling a class name.
Supported setters/getters preserve constant-key string extras and traced data; unknown
mutations invalidate modeled payload/target state. A matching enabled Manifest activity
or alias permits a potential `startActivity`→`onCreate(Bundle)` edge, including an inherited
body if resolvable. Runtime enabling, permissions, launch flags and `onNewIntent` selection
are not solved. Other ICC forms do not acquire invented edges.

Handler/View post (including the supported delayed overload), Executor.execute and
Activity.runOnUiThread may reach a known allocation's `run()V`. The callback gets a
snapshot of captured scalar fields and heap. Callback return values and writes do not
become synchronous caller effects. All carried traces gain scheduling/lifecycle
uncertainty; CONFIRMED is never inferred. Cancellation, rejection, task ordering and
later captures/mutations remain unmodeled. This is not a happens-before analysis.

Primary source roots retain their original budgets and run before boundary-only roots.
The inventory is limited to 1,000 explored edges and shares global depth/step limits.
`flow_coverage.boundaries` and GUI Boundaries distinguish `MODELED_POTENTIAL` from
`UNRESOLVED`; neither status is a vulnerability count or whole-app coverage statement.

## Performance and storage

GUI receives queued worker signals. One `JebSession` owns a persistent isolated JVM.
`CoreRunner` initializes `JebCoreService.getInstance(File(jebHome))` and one EnginesContext.
It reuses a project while input path + SHA-256 match; changing inputs unloads that project.
Requests are serialized with cancellation-aware locking. stdin carries JSON envelopes
pointing to private request files; UUID-matched responses are atomically renamed into place.
stdout/stderr are diagnostic logs, never the IPC framing channel. Java objects stay inside
the bridge. Startup verifies Core/Engines; DEX, CFG, XREF, decompiler and AST capabilities
become verified only after actual operations. No shell or vendor CLI launcher is used.

Timeout/cancel terminates the JVM; subsequent requests recreate it and reload the input.
Normal shutdown explicitly closes Engines then Core, with a bounded termination fallback.
GUI shutdown, CLI context managers and an atexit fallback own cleanup. Analysis stages
are shown as progress. SHA-256 + JEB version + both bridge script hashes + method budget
key the normalized cache. Cache reads still require a successful live Core probe.
Lists use Qt models; graph neighborhoods are capped. Decompilation is lazy and cached.
JEB `getCrossReferences` is exposed separately from the bytecode-derived XREF snapshot.
The native XREF endpoint pages results; the GUI requests at most 300 items per view.
Call graph edges are declared DEX invokes, not a claim of resolved virtual dispatch.
Project writes use atomic replacement. APK bytes are never executed or extracted.
Method bodies cross IPC as a private NDJSON stream, consumed one method at a time;
Jython does not accumulate a second full body index or a monolithic JSON string.
Project/cache JSON uses a shallow dataclass encoder instead of recursive `asdict` copies.
Lone UTF-16 surrogates use tagged code-point transport and ASCII-escaped JSON storage
to preserve DEX strings without Jython Unicode conversion failure. Normalized programs
still reside in memory: this is not a disk-backed or incremental-query index.
Reports mask asset secrets, but bytecode/source can contain sensitive data: project files
must be treated as confidential. No network submission is performed.

## Test strategy

Unit tests cover archive limits, manifest defaults, classification, persistence and rules.
Flow tests cover positive paths, overwritten registers, unrelated arguments, return values,
fields, CFG branches, recursion/budgets and uncertainty. GUI smoke tests instantiate QML
offscreen. A locally generated DEX fixture exercises actual JEB parsing and flow extraction;
licensed JEB and its commercial JARs are never distributed with this project.
