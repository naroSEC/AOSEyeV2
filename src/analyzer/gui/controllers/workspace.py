from dataclasses import asdict, replace
import json
import logging
from pathlib import Path
from PySide6.QtCore import QObject, Property, Signal, Slot, QThreadPool, QRunnable, QUrl
from analyzer.app.application import AnalysisApplication
from analyzer.app.settings import Settings
from analyzer.app.jobs import Cancellation, Cancelled
from analyzer.app.project_manager import save_project, open_project
from analyzer.backends.jeb.backend import JebBackend
from analyzer.gui.models.findings import FindingsModel
from analyzer.gui.highlighter import CodeHighlighter
from analyzer.core.graph import reference_query
from analyzer.core.navigation import bytecode_location, reference_links, native_reference_page
from analyzer.gui.coverage import coverage_label
from analyzer.core.call_coverage import coverage_text, call_target_page
from analyzer.gui.review import review_view
from analyzer.gui.dex_browser import dex_page
from analyzer.core.field_references import field_references
from analyzer.gui.field_view import field_page_text
from analyzer.analyzers.network_config import select_cleartext_policy


class JobSignals(QObject):
    progress = Signal(int, str)
    done = Signal(object)
    failed = Signal(str)


class Job(QRunnable):
    def __init__(self, work):
        super().__init__()
        self.work = work
        self.signals = JobSignals()

    def run(self):
        try:
            self.signals.done.emit(self.work(self.signals.progress.emit))
        except Cancelled:
            self.signals.failed.emit('Cancelled')
        except Exception as exc:
            logging.getLogger(__name__).exception('Background job failed')
            self.signals.failed.emit(str(exc))
        finally:
            self.work = None


def local_path(value):
    url = QUrl(value)
    return Path(url.toLocalFile() if url.isLocalFile() else value)


class Workspace(QObject):
    FIELD_PAGE_SIZE = 300
    XREF_PAGE_SIZE = 300
    changed = Signal()
    detailChanged = Signal()
    candidateReady = Signal()
    candidateAccepted = Signal()

    def __init__(self, settings=None):
        super().__init__()
        self.settings = settings or Settings.load()
        self.app = AnalysisApplication(self.settings)
        self.model = FindingsModel(self)
        self.pool = QThreadPool(self)
        self.pool.setMaxThreadCount(1)
        self.cancel_token = Cancellation()
        self._busy = False
        self._stage = 'Open an APK or DEX to start an evidence-based analysis'
        self._progress = 0
        self._backend_status = 'Not verified'
        self._detail = {}
        self._content = ''
        self._result = None
        self._selected = None
        self._project_name = 'No project open'
        self._job = None
        self._finish_callback = None
        self._section = 'Overview'
        self._tab = 'Evidence'
        self._location = {}
        self._history = []
        self._navigation_items = []
        self._review_summary = ''
        self._xref_page = None
        self._xref_pending = False
        self._dex_page = {}
        self._field_selection = None
        self._field_page = None
        self._field_pending = False
        self._reopen_pending = False
        self._probe_pending = False
        self._live_snapshot = None
        self._call_page = None
        self._call_pending = False
        self._candidate_pending = False
        self._candidate_text = ''
        self._candidate_record = None
        self._report_pending = False

    busy = Property(bool, lambda s: s._busy, notify=changed)
    callTargetPage = Property('QVariantMap', lambda s: s._call_page or {}, notify=detailChanged)
    candidateText = Property(str, lambda s: s._candidate_text, notify=changed)
    sectionName = Property(str, lambda s: s._section, notify=detailChanged)
    dexItems = Property('QVariantList', lambda s: s._dex_page.get('items', []), notify=detailChanged)
    coverageLabel = Property(str, lambda s: getattr(s, '_coverage_label', ''), notify=changed)
    dexEmptyLabel = Property(str, lambda s: 'No matches in the saved index for this scope/filter. '
        'Excluded or unindexed items may still exist in the APK.' if s._dex_page and not s._dex_page.get('items') else '', notify=detailChanged)
    dexClass = Property(str, lambda s: s._dex_page.get('class_name', ''), notify=detailChanged)
    dexScope = Property(str, lambda s: ' / '.join(str(v) for v in (
        (s._dex_page.get('unit') or 'Unknown unit') if s._dex_page.get('unit') is not None else 'All units',
        s._dex_page.get('package'), s._dex_page.get('class_name')) if v) or 'Unknown unit', notify=detailChanged)
    dexHasPrevious = Property(bool, lambda s: s._dex_page.get('offset', 0) > 0, notify=detailChanged)
    dexHasNext = Property(bool, lambda s: s._dex_page.get('has_more', False), notify=detailChanged)
    dexPageLabel = Property(str, lambda s: (
        f"{s._dex_page.get('offset', 0) + 1 if s._dex_page.get('items') else 0}–"
        f"{s._dex_page.get('offset', 0) + len(s._dex_page.get('items', []))} / "
        f"{s._dex_page.get('total', 0)}"), notify=detailChanged)
    stage = Property(str, lambda s: s._stage, notify=changed)
    progress = Property(int, lambda s: s._progress, notify=changed)
    backendStatus = Property(str, lambda s: s._backend_status, notify=changed)
    jebPath = Property(str, lambda s: s.settings.jeb_path, notify=changed)
    aapt2Path = Property(str, lambda s: s.settings.aapt2_path, notify=changed)
    jvmHeapMiB = Property(int, lambda s: s.settings.jvm_heap_mib, notify=changed)
    indexOrder = Property(str, lambda s: s.settings.index_order, notify=changed)
    projectName = Property(str, lambda s: s._project_name, notify=changed)
    detail = Property('QVariantMap', lambda s: s._detail, notify=detailChanged)
    content = Property(str, lambda s: s._content, notify=detailChanged)
    currentTab = Property(str, lambda s: s._tab, notify=detailChanged)
    selectedField = Property(str, lambda s: (s._field_selection['name'] + ' · ' +
        (s._field_selection['unit'] or 'Unknown unit')) if s._field_selection else '', notify=detailChanged)
    fieldFilter = Property(str, lambda s: s._field_page['access'] if s._field_page else 'ALL', notify=detailChanged)
    fieldHasPrevious = Property(bool, lambda s: bool(s._field_page and s._field_page['offset'] > 0), notify=detailChanged)
    fieldHasNext = Property(bool, lambda s: bool(s._field_page and s._field_page['has_more']), notify=detailChanged)
    fieldPageLabel = Property(str, lambda s: (
        f"{s._field_page['offset'] + 1 if s._field_page['shown'] else 0}–"
        f"{s._field_page['offset'] + s._field_page['shown']} / {s._field_page['total']} operands"
        if s._field_page else 'No field page loaded'), notify=detailChanged)
    reviewSummary = Property(str, lambda s: s._review_summary, notify=detailChanged)
    xrefHasPrevious = Property(bool, lambda s: bool(s._xref_page and s._xref_page['offset'] > 0), notify=detailChanged)
    xrefHasNext = Property(bool, lambda s: bool(s._xref_page and s._xref_page['has_more']), notify=detailChanged)
    xrefPageLabel = Property(str, lambda s: (f"{s._xref_page['offset'] + 1 if s._xref_page['shown'] else 0}–"
        f"{s._xref_page['offset'] + s._xref_page['shown']} / {s._xref_page['total']} references"
        if s._xref_page else 'No reference page loaded'), notify=detailChanged)
    navigationItems = Property('QVariantList', lambda s: s._navigation_items, notify=detailChanged)
    canGoBack = Property(bool, lambda s: bool(s._history), notify=detailChanged)
    evidenceLocation = Property('QVariantMap', lambda s: s._location, notify=detailChanged)
    findingCount = Property(int, lambda s: len(s.model.items), notify=changed)
    analystNote = Property(str, lambda s: s._result.notes.get(s._selected.id, '')
                           if s._result and s._selected else '', notify=detailChanged)

    @Slot(QObject)
    def highlight(self, quick_document):
        self._highlighter = CodeHighlighter(quick_document.textDocument())

    def _start(self, work, finish):
        if self._busy:
            return
        self._busy = True
        self.cancel_token = Cancellation()
        self._job = Job(work)
        self._job.signals.progress.connect(self._on_progress)
        self._job.signals.failed.connect(self._failure)
        self._finish_callback = finish
        self._job.signals.done.connect(self._success)
        self.changed.emit()
        self.pool.start(self._job)

    @Slot(int, str)
    def _on_progress(self, percent, stage):
        self._progress, self._stage = percent, stage
        self.changed.emit()

    @Slot(str)
    def _failure(self, message):
        self._job = None
        self._finish_callback = None
        self._busy = False
        if self._tab == 'Review' and not (self._reopen_pending or self._probe_pending):
            self._review_summary = 'Review unavailable: ' + message
        if self._backend_status == 'Checking':
            self._backend_status = 'Unavailable'
        preserve_page = ((self._xref_pending and self._xref_page is not None)
                         or self._call_pending
                         or self._candidate_pending
                         or self._report_pending
                         or (self._field_pending and self._field_page is not None)
                         or self._reopen_pending
                         or (self._probe_pending and self._result is not None))
        if not preserve_page:
            self._content = message
        self._xref_pending = False
        self._field_pending = False
        self._reopen_pending = False
        self._probe_pending = False
        self._call_pending = False
        self._candidate_pending = False
        self._report_pending = False
        snapshot, self._live_snapshot = self._live_snapshot, None
        if snapshot is not None and snapshot[0] is self._result and snapshot[1] is self._selected:
            for key, value in snapshot[2].items():
                setattr(self, key, value)
        self._stage = message
        self.detailChanged.emit()
        self.changed.emit()

    @Slot(object)
    def _success(self, value):
        finish = self._finish_callback
        self._finish_callback = None
        self._job = None
        self._busy = False
        try:
            if self._xref_pending or self._live_snapshot is not None:
                self.cancel_token.check()
            if finish is not None:
                finish(value)
            self._live_snapshot = None
        except Exception as exc:
            self._failure(str(exc))
        self.changed.emit()

    @Slot(str)
    def analyze(self, path):
        def run(progress):
            return self.app.analyze(local_path(path), self.cancel_token, progress)
        self._start(run, self._loaded)

    def _loaded(self, result):
        self._call_page = None
        self._candidate_text = ''
        self._candidate_record = None
        self._field_page = None
        self._field_selection = None
        self._dex_page = {}
        self._xref_page = None
        self._location, self._history, self._navigation_items = {}, [], []
        self._tab = 'Evidence'
        self._result = result
        self._coverage_label = coverage_label(result)
        self.app.backend.program = result.program
        self._selected = None
        self._detail = {}
        self._project_name = Path(result.input_path).name
        self.model.reset(result.findings)
        self._backend_status = result.program.capabilities.get('dex', 'Unavailable / unverified')
        self._stage = 'Analysis complete' if result.complete else 'Partial analysis — inspect Diagnostics'
        self.section('Overview')
        self.changed.emit()

    @Slot()
    def cancel(self):
        self.cancel_token.cancel()

    def shutdown(self):
        self.cancel()
        self.pool.waitForDone()
        self._job = None
        self._finish_callback = None
        self.app.backend.close()

    @Slot()
    def checkBackend(self):
        self._check_backend(self.settings.jeb_path, save=False)

    @Slot(str, result=bool)
    def saveAapt2(self, path):
        if self._busy:
            return False
        try:
            candidate = replace(self.settings, aapt2_path=path.strip())
            if candidate.aapt2_path and not Path(candidate.aapt2_path).is_file():
                raise ValueError('aapt2 executable file not found')
            candidate.save()
        except (OSError, ValueError) as exc:
            self._stage = 'aapt2 settings unchanged: ' + str(exc)
            self.changed.emit()
            return False
        self.settings = candidate
        self.app.backend.settings = candidate
        self._stage = 'aapt2 setting saved; applies to new analysis, not saved evidence'
        self.changed.emit()
        return True

    @Slot(int, result=bool)
    def saveJvmHeap(self, value):
        if self._busy:
            return False
        try:
            candidate = replace(self.settings, jvm_heap_mib=value)
            candidate.save()
        except (OSError, ValueError) as exc:
            self._stage = 'JVM heap setting unchanged: ' + str(exc)
            self.changed.emit()
            return False
        self.settings = candidate
        self.app.backend.settings = candidate
        self._stage = 'Heap setting saved; JEB restarts on the next backend request. Saved evidence unchanged.'
        self.changed.emit()
        return True

    @Slot(str)
    def probe(self, path):
        self._check_backend(path, save=True)

    @Slot(str, result=bool)
    def saveIndexOrder(self, value):
        if self._busy:
            return False
        try:
            candidate = replace(self.settings, index_order=value)
            candidate.save()
        except (OSError, ValueError) as exc:
            self._stage = 'Index policy unchanged: ' + str(exc)
            self.changed.emit()
            return False
        self.settings = candidate
        self.app.settings = candidate
        self.app.backend.settings = candidate
        self._stage = 'Index policy saved for new analyses only. Saved evidence and its policy are unchanged.'
        self.changed.emit()
        return True

    def _check_backend(self, path, save):
        if self._busy:
            return
        if not path.strip():
            self._backend_status = 'Not configured'
            self._stage = 'Set your licensed JEB installation directory in JEB settings'
            self.changed.emit()
            return
        self._probe_pending = True
        try:
            candidate = replace(self.settings, jeb_path=path)
            if save:
                candidate.save()
        except (OSError, ValueError) as exc:
            self._failure('Settings were not changed: ' + str(exc))
            return
        self.settings = candidate
        self._stage = 'Checking installed JEB Core API'
        self._backend_status = 'Checking'
        def done(value):
            self.cancel_token.check()
            self._backend_status = value['status'] + ' · ' + value['version']
            if save and self._result is None:
                self._content = json.dumps(value, indent=2)
            self._probe_pending = False
            self._stage = 'Backend probe complete; DEX capabilities require an input file'
            self.detailChanged.emit()
        def run(_):
            if self.app.backend.home != Path(path).resolve():
                self.app.backend.close()
                self.app = AnalysisApplication(self.settings)
                if self._result is not None:
                    self.app.backend.program = self._result.program
            return self.app.backend.probe(self.cancel_token)
        self._start(run, done)

    @Slot(str)
    def search(self, query):
        self.model.reset(query=query)

    @Slot(str)
    def filterSeverity(self, severity):
        self.model.reset(severity=severity)

    @Slot(int)
    def selectFinding(self, index):
        if self._busy:
            return
        if 0 <= index < len(self.model.visible):
            self._selected = self.model.visible[index]
            self._field_selection = None
            self._xref_page = None
            self._location, self._history, self._navigation_items = {}, [], []
            self._detail = asdict(self._selected)
            self.showTab('Evidence')

    @Slot(str)
    def section(self, name):
        if self._busy:
            return
        self._field_page = None
        self._xref_page = None
        self._navigation_items = []
        self._section = name
        if name == 'Network Policy':
            self._tab = 'Network Policy'
        elif self._tab == 'Network Policy':
            self._tab = 'Evidence'
        result = self._result
        if result is None:
            self._content = 'AOSEye\n\nOpen an APK / DEX, or reopen an analysis project.\n\nJEB provides code evidence. Findings distinguish exposure, review, weakness and source-to-sink candidates.'
        elif name == 'Manifest':
            self._content = result.program.manifest or 'Manifest unavailable; see Diagnostics.'
        elif name == 'Network Policy':
            self._content = self._network_policy_text()
        elif name == 'Storage Policy':
            self._content = json.dumps(result.manifest.get('storage_config', {'status': 'NOT_RECORDED'}), ensure_ascii=True, indent=2)
        elif name in ('Components', 'Deep Links'):
            self._content = json.dumps(result.manifest.get('components' if name == 'Components' else 'deep_links', []), ensure_ascii=False, indent=2)
        elif name == 'DEX':
            self._content = 'Browse units, packages, classes and members in the DEX panel. Only saved DEX bodies support exact location navigation. Unit presence is not proof of a declaration; legacy field origins remain unknown.'
            self._query_dex('', '', 0)
        elif name == 'Assets':
            self._content = '\n'.join(f"{f['size']:>10}  {f['path']}" for f in result.files[:3000])
        elif name == 'Diagnostics':
            self._content = coverage_text(result.provenance.get('call_target_coverage'), details=True) + '\n\n' + (
                '\n\n'.join(result.diagnostics) or 'No recorded processing errors. Static-analysis modeling limitations still apply.')
        elif name == 'Boundaries':
            self._content = ('Bounded ICC / async inventory (not proof of execution)\n'
                             'Only explored call sites are listed; budgets and unresolved targets remain.\n\n' +
                             json.dumps(result.provenance.get('flow_coverage', {}).get('boundaries', []),
                                        ensure_ascii=True, indent=2))
        else:
            self._content = (f"{self._project_name}\n\nPackage     {result.manifest.get('package', '—')}\n"
                             f"Findings    {len(result.findings)}\nMethods     {len(result.program.methods)}\n"
                             f"Files       {len(result.files)}\nCoverage    {'Finished' if result.complete else 'Partial'}\n\n"
                             f"SHA-256\n{result.sha256}\n\nSelect a finding to inspect its evidence and flow.\n"
                             'Static candidates require analyst validation. UNKNOWN does not mean absent.')
        self.detailChanged.emit()

    @Slot(str, int)
    def queryCallTargets(self, status, offset):
        if self._busy or self._result is None or self._section != 'Diagnostics':
            return
        result = self._result
        self._call_pending = True
        self._stage = 'Querying saved call targets; previous view retained until success'
        def done(page):
            self.cancel_token.check()
            if self._result is not result or self._section != 'Diagnostics':
                raise ValueError('Stale call-target page discarded')
            self._call_page = page
            self._tab = 'Call Targets'
            self._content = json.dumps(page, ensure_ascii=True, indent=2)
            self._navigation_items = [dict(label=row['status'] + ' · Caller', method=row['caller'],
                offset=row['offset'], unit=row['unit']) for row in page['items'] if row['navigation_allowed']]
            self._call_pending = False
            self._stage = 'Saved call sites only; links open callers, never missing target bodies'
            self.detailChanged.emit()
        self._start(lambda _: call_target_page(result.program, status, offset, cancel=self.cancel_token), done)

    @Slot(int)
    def previewCallTarget(self, kib):
        if self._busy or self._result is None or self._section != 'Diagnostics' or self._tab != 'Bytecode':
            return
        if type(kib) is not int or not 1 <= kib <= 1024:
            self._stage = 'Candidate budget must be 1..1024 KiB'
            self.changed.emit()
            return
        result, location, backend = self._result, dict(self._location), self.app.backend
        self._candidate_pending = True
        self._stage = 'Reading one JEB candidate; saved analysis is not modified'
        def run(_):
            self.cancel_token.check()
            backend.program = result.program
            backend.input_path = Path(result.input_path)
            backend.input_sha256 = result.sha256
            return backend.preview_call_target(location.get('method', ''), location.get('offset'),
                                               self.cancel_token, max_bytes=kib * 1024)
        def done(value):
            self.cancel_token.check()
            if self._result is not result or self._location != location or self._section != 'Diagnostics' or self._tab != 'Bytecode':
                raise ValueError('Stale candidate response discarded')
            if value['status'] == 'BUDGET_EXCEEDED':
                self._stage = 'Candidate exceeds byte budget; no body returned. Saved evidence unchanged.'
            else:
                from analyzer.app.candidate_artifact import snapshot
                self._candidate_record = snapshot(value, backend.version)
                self._candidate_text = ('READ-ONLY CANDIDATE · not merged or reanalyzed · separate export only\n'
                    'Single direct/static target. Byte budget is not a JVM memory limit.\n\n' +
                    json.dumps(value, ensure_ascii=True, indent=2))
                self._stage = 'Candidate preview ready; findings and saved evidence unchanged'
                self.candidateReady.emit()
            self._candidate_pending = False
        self._start(run, done)

    @Slot()
    def discardCandidate(self):
        self._candidate_text = ''
        self._candidate_record = None
        self.changed.emit()

    @Slot(str)
    def reopenCandidate(self, path):
        if self._busy:
            return
        from analyzer.app.candidate_artifact import open_candidate, compare_origin
        result = self._result
        self._candidate_pending = True
        self._stage = 'Validating separate candidate; original analysis retained'
        def run(_):
            value = open_candidate(local_path(path), self.cancel_token)
            comparison = compare_origin(value, result)
            self.cancel_token.check()
            return value, comparison
        def done(payload):
            self.cancel_token.check()
            if self._result is not result:
                raise ValueError('Stale candidate reopen discarded')
            value, comparison = payload
            self._candidate_record = value
            self._candidate_text = ('IMPORTED READ-ONLY CANDIDATE · UNSIGNED · not merged or reanalyzed\n' +
                json.dumps(dict(origin_comparison=comparison, artifact=value), ensure_ascii=True, indent=2))
            self._stage = 'Candidate opened: ' + comparison['status'] + ' · no live APK/JEB verification'
            self._candidate_pending = False
            self.candidateReady.emit()
        self._start(run, done)

    @Slot(str, result=bool)
    def exportCandidate(self, path):
        if self._busy or self._candidate_record is None:
            return False
        from analyzer.app.candidate_artifact import save_candidate
        try:
            save_candidate(local_path(path), self._candidate_record)
        except (OSError, ValueError, TypeError) as exc:
            self._stage = 'Candidate export failed; preview retained: ' + str(exc)
            self.changed.emit()
            return False
        self._stage = 'Candidate exported separately; original analysis unchanged'
        self.changed.emit()
        return True

    @Slot()
    def analyzeCandidate(self):
        if self._busy or self._candidate_record is None or self._result is None:
            return
        from analyzer.app.candidate_analysis import expand_candidate
        result, candidate = self._result, self._candidate_record
        self._candidate_pending = True
        self._stage = 'Reverifying and analyzing expanded scope; original result retained until success'
        def done(value):
            self.cancel_token.check()
            if self._result is not result or self._candidate_record is not candidate:
                raise ValueError('Stale expanded analysis discarded')
            self._candidate_pending = False
            self._loaded(value)
            self._stage = 'Expanded partial analysis ready; findings recomputed, notes retained. Save to a new project file.'
            self.candidateAccepted.emit()
        self._start(lambda progress: expand_candidate(result, candidate, self.app.backend, self.settings,
                                                      self.cancel_token, progress), done)

    @Slot(str, str)
    def exportReport(self, path, format):
        if self._busy or self._result is None:
            return
        from analyzer.app.report_export import export_report
        result = self._result
        self._report_pending = True
        self._stage = 'Exporting saved evidence; no live backend access'
        def done(_):
            self._report_pending = False
            self._stage = 'Report exported to new file; original project unchanged'
        self._start(lambda _: export_report(result, local_path(path), format, self.cancel_token), done)

    def _network_policy_text(self, host=None):
        policy = self._result.manifest.get('network_security_config', {}) if self._result else {}
        if not isinstance(policy, dict):
            policy = {}
        value = dict(view='Saved normalized network policy, not original XML',
                     resource=policy.get('resource'), manifest_reference=policy.get('reference'),
                     policy_status=policy.get('status', 'UNKNOWN'),
                     limitation='Supplied configuration only. NOT_PERMITTED is not TLS safety or runtime enforcement proof.')
        if host is None:
            value['policy'] = policy
            value['help'] = 'Enter a bare ASCII DNS host to select its cleartext rule. No APK, JEB or network access is required.'
        else:
            value['selection'] = select_cleartext_policy(policy, host)
        return json.dumps(value, ensure_ascii=True, indent=2)

    @Slot(str)
    def queryNetworkHost(self, host):
        if self._busy or not self._result or self._section != 'Network Policy' or self._tab != 'Network Policy':
            return
        self._content = self._network_policy_text(host)
        self._stage = 'Host policy selected from saved configuration only; findings unchanged'
        self.detailChanged.emit()
        self.changed.emit()

    @Slot()
    def showNetworkPolicy(self):
        if not self._busy and self._section == 'Network Policy' and self._tab == 'Network Policy':
            self._content = self._network_policy_text()
            self.detailChanged.emit()

    def _query_dex(self, class_name, query, offset, mode='classes', unit=None, package=None):
        if self._busy or self._result is None:
            return
        result = self._result
        self._stage = 'Querying DEX browser'
        def done(page):
            if self._result is not result:
                raise ValueError('Stale DEX browser response discarded')
            self.cancel_token.check()
            self._dex_page = page
            self._stage = 'Saved DEX inventory loaded · totals are saved matches, not whole-APK coverage'
            self.detailChanged.emit()
        self._start(lambda _: dex_page(result.program, class_name, query, offset,
                                      cancel=self.cancel_token, mode=mode, unit=unit, package=package), done)

    def _dex_scope_args(self):
        return {key: self._dex_page.get(key) for key in ('mode', 'unit', 'package')}

    @Slot(str)
    def dexBrowse(self, mode):
        if mode in ('units', 'packages', 'classes'):
            self._query_dex('', '', 0, mode=mode)

    @Slot(int)
    def openDexEntry(self, index):
        if self._busy or not 0 <= index < len(self.dexItems):
            return
        row = self.dexItems[index]
        kind, name, unit = row['kind'], row['name'], row['unit']
        if kind == 'unit':
            self._query_dex('', '', 0, mode='packages', unit=unit)
        elif kind == 'package':
            self._query_dex('', '', 0, unit=unit, package=name)
        elif kind == 'class':
            self._query_dex(name, '', 0, unit=unit)
        elif kind == 'method':
            method = self._result.program.methods.get(name)
            if not row['has_body'] or not method or method.unit != unit:
                self._stage = 'No saved body for this unit; another unit will not be substituted. Excluded bodies require reanalysis.'
                self.changed.emit()
                return
            self.openDexMethod(name)
        else:
            self._field_selection = dict(row)
            self._field_page = None
            self._selected, self._detail, self._xref_page = None, {}, None
            self.showTab('Field XREF')

    @Slot(str)
    def searchDex(self, query):
        self._query_dex(self.dexClass, query, 0, **self._dex_scope_args())

    @Slot(str)
    def openDexClass(self, name):
        self._query_dex(name, '', 0)

    @Slot()
    def dexClasses(self):
        self._query_dex('', '', 0)

    @Slot()
    def nextDexPage(self):
        if self.dexHasNext:
            self._query_dex(self.dexClass, self._dex_page['query'], self._dex_page['offset'] + 300, **self._dex_scope_args())

    @Slot()
    def previousDexPage(self):
        if self.dexHasPrevious:
            self._query_dex(self.dexClass, self._dex_page['query'], max(0, self._dex_page['offset'] - 300), **self._dex_scope_args())

    @Slot(str)
    def openDexMethod(self, signature):
        if self._busy or not self._result:
            return
        method = self._result.program.methods.get(signature)
        if not method or not method.instructions:
            self._stage = 'No indexed DEX body; exact location unavailable. Missing from saved data does not prove absence in APK.'
            self.changed.emit()
            return
        self.navigateMethod(signature)
        self._selected = None
        self._detail = {}
        self.detailChanged.emit()

    @Slot(str)
    def showTab(self, name):
        if self._busy:
            return
        if name in ('AST', 'JEB XREF') and self._result:
            method = self._location.get('method', self._selected.location.method if self._selected else '')
            if method in self._result.program.methods:
                self._begin_live_view()
        self._tab = name
        f = self._selected
        if not self._result:
            return
        method = self._location.get('method', f.location.method if f else '')
        program = self._result.program
        backend = self.app.backend
        backend.program = program
        if name == 'Field XREF':
            self._xref_page = None
            if self._field_selection is None:
                self._navigation_items = []
                self._content = 'Select a field in the DEX inventory to inspect read/write operands.'
                self.detailChanged.emit()
                return
            self._load_field_page(0, self.fieldFilter)
            return
        self._field_page = None
        if name == 'JEB XREF':
            self._load_xref_page(method, 0)
            return
        self._xref_page = None
        self._navigation_items = []
        if not f and name in ('Evidence', 'Review', 'Data Flow'):
            self._content = 'Select a Finding for this view. DEX browsing does not create a security finding.'
            self._review_summary = ''
            self.detailChanged.emit()
            return
        if name in ('XREF', 'Call Graph'):
            self._stage = 'Querying DEX references (up to 300 edges)'
            def run(_):
                value = reference_query(program, method, cancel=self.cancel_token,
                                        invokes_only=name != 'XREF', incoming_only=name == 'XREF')
                self.cancel_token.check()
                return value, reference_links(program, value['edges'])
            def done(value):
                graph, self._navigation_items = value
                self._content = json.dumps(graph, ensure_ascii=True, indent=2)
                self._stage = 'DEX references loaded' + (' — truncated at 300 edges' if graph['truncated'] else '')
                self.detailChanged.emit()
            self.detailChanged.emit()
            self._start(run, done)
            return
        if name == 'AST':
            if method not in program.methods:
                self._content = 'Select a finding with a DEX method location.'
                self.detailChanged.emit()
                return
            self._stage = 'Loading ' + name + ' from JEB'
            def run(_):
                self._prepare_live_backend()
                return backend.get_ast(method, self.cancel_token), []
            def done(value):
                value, self._navigation_items = value
                self._content = json.dumps(value, ensure_ascii=True, indent=2)
                self._stage = name + ' loaded from JEB'
                self.detailChanged.emit()
            self.detailChanged.emit()
            self._start(run, done)
            return
        if name == 'Review':
            self._review_summary = 'Checking review locations against saved DEX…'
            self._stage = 'Preparing review evidence'
            def done(value):
                self._review_summary, self._content, self._navigation_items = value
                self._stage = 'Review locations checked against saved DEX; findings unchanged'
                self.detailChanged.emit()
            self.detailChanged.emit()
            self._start(lambda _: review_view(program, f, self.cancel_token), done)
            return
        if name == 'Evidence':
            self._content = '\n\n'.join([f.description, *f.evidence, 'Validation: ' + json.dumps(f.validation), 'Recommendation: ' + f.recommendation])
        elif name == 'Bytecode':
            if self._location:
                self.navigateLocation(method, self._location['offset'], self._location['unit'])
                return
            m = program.methods.get(method)
            self._content = '\n'.join(f'{i.offset:04x}  {i.text}' for i in m.instructions) if m else (f.bytecode if f else '')
        elif name == 'Code':
            self._content = program.methods[method].source if method in program.methods else (f.decompiled_code if f else '')
            if not self._content:
                self._content = 'Click Decompile to retrieve source from JEB. DEX remains the evidence source.'
        elif name == 'CFG':
            value = backend.get_cfg(method)[:300] if method in program.methods else []
            self._content = json.dumps(value, ensure_ascii=False, indent=2)
        else:
            self._navigation_items = [dict(step, unit=program.methods[step['method']].unit
                                          if step['method'] in program.methods else '')
                                      for step in f.data_flow[:300]]
            self._content = '\n\n↓\n\n'.join(f"{s['label']}\n{s['method']} @ {s['offset']:04x}" for s in f.data_flow) or 'No modeled data flow for this finding.'
        self.detailChanged.emit()

    def _load_field_page(self, offset, access):
        if self._busy or not self._result or self._field_selection is None or self._tab != 'Field XREF':
            return
        selection, result = self._field_selection, self._result
        if self._field_page is None:
            self._content = 'Querying saved DEX field read/write operands…'
            self._navigation_items = []
        self._field_pending = True
        self._stage = 'Querying field page; existing page retained until success'
        def run(_):
            page, links = field_references(result.program, selection['name'], selection['unit'],
                limit=self.FIELD_PAGE_SIZE, cancel=self.cancel_token, offset=offset, access=access)
            if offset and offset >= page['total']:
                raise ValueError('Field page is out of range; previous page retained')
            return page, links, field_page_text(page)
        def done(value):
            self.cancel_token.check()
            if self._result is not result or self._field_selection is not selection or self._tab != 'Field XREF':
                raise ValueError('Stale field reference response discarded')
            self._field_page, self._navigation_items, self._content = value
            self._field_pending = False
            self._stage = 'Field read/write operands loaded · not proof of declaration or execution'
            self.detailChanged.emit()
        self.detailChanged.emit()
        self._start(run, done)

    @Slot(str)
    def filterFieldReferences(self, access):
        if access in ('ALL', 'READ', 'WRITE'):
            self._load_field_page(0, access)

    @Slot()
    def nextFieldPage(self):
        if self.fieldHasNext:
            self._load_field_page(self._field_page['offset'] + self._field_page['shown'], self.fieldFilter)

    @Slot()
    def previousFieldPage(self):
        if self.fieldHasPrevious:
            self._load_field_page(max(0, self._field_page['offset'] - self.FIELD_PAGE_SIZE), self.fieldFilter)

    def _load_xref_page(self, method, offset):
        if self._busy or not self._result:
            return
        if method in self._result.program.methods:
            self._begin_live_view()
        result, selected = self._result, self._selected
        program, backend = result.program, self.app.backend
        if self._xref_page is None:
            self._navigation_items = []
            self._content = 'Loading JEB XREF…'
        if method not in program.methods:
            self._stage = 'Select a finding with a DEX method location.'
            self._content = self._stage
            self.detailChanged.emit()
            self.changed.emit()
            return
        self._xref_pending = True
        self._stage = 'Loading JEB XREF page; existing page retained until success'
        def run(_):
            self._prepare_live_backend()
            page = backend.get_jeb_xrefs(method, self.cancel_token, offset=offset, limit=self.XREF_PAGE_SIZE)
            if (type(page.get('total')) is not int or page['total'] < 0 or page.get('offset') != offset
                    or len(page['items']) != min(self.XREF_PAGE_SIZE, max(0, page['total'] - offset))
                    or (offset > 0 and offset >= page['total'])):
                raise ValueError('Inconsistent XREF page; previous page retained')
            value, links = native_reference_page(program, method, page, self.cancel_token)
            self.cancel_token.check()
            return value, links, json.dumps(value, ensure_ascii=True, indent=2)
        def done(value):
            if self._result is not result or self._selected is not selected or self._tab != 'JEB XREF':
                raise ValueError('Stale XREF response discarded')
            page, links, content = value
            self._xref_page, self._navigation_items, self._content = page, links, content
            self._xref_pending = False
            self._stage = f'JEB XREF loaded · {len(links)} verified location links'
            self.detailChanged.emit()
        self.detailChanged.emit()
        self._start(run, done)

    @Slot()
    def nextXrefPage(self):
        if self._tab == 'JEB XREF' and self.xrefHasNext:
            self._load_xref_page(self._xref_page['requested_element'],
                                 self._xref_page['offset'] + self._xref_page['shown'])

    @Slot()
    def previousXrefPage(self):
        if self._tab == 'JEB XREF' and self.xrefHasPrevious:
            self._load_xref_page(self._xref_page['requested_element'],
                                 max(0, self._xref_page['offset'] - self.XREF_PAGE_SIZE))

    @Slot()
    def decompile(self):
        if self._busy or not self._result:
            return
        method = self._location.get('method', self._selected.location.method if self._selected else '')
        if method not in self._result.program.methods:
            return
        self._begin_live_view()
        self._tab = 'Code'
        self._field_page = None
        self._xref_page = None
        self._navigation_items = []
        def run(_):
            self._prepare_live_backend()
            return self.app.backend.get_decompiled_source(method, self.cancel_token)
        def done(source):
            self._content = source
            self._stage = 'Decompiled source loaded (supporting evidence)'
            self.detailChanged.emit()
        self._start(run, done)

    def _begin_live_view(self):
        if self._live_snapshot is None:
            self._live_snapshot = (self._result, self._selected, {key: getattr(self, key) for key in (
                '_tab', '_content', '_navigation_items', '_xref_page', '_field_page', '_review_summary')})

    def _prepare_live_backend(self):
        original = Path(self._result.input_path)
        # Each public live backend operation validates once, including cached returns.
        self.cancel_token.check()
        self.app.backend.program = self._result.program
        self.app.backend.input_path = original
        self.app.backend.input_sha256 = self._result.sha256

    @Slot(str)
    def save(self, path):
        if self._result:
            self._start(lambda _: save_project(local_path(path), self._result),
                        lambda _: self._on_progress(100, 'Project / JSON report saved'))

    @Slot(str)
    def reopen(self, path):
        if self._busy:
            return
        original = self._result
        self._reopen_pending = True
        def done(result):
            self.cancel_token.check()
            if self._result is not original:
                raise ValueError('Stale project load discarded')
            self._reopen_pending = False
            self._loaded(result)
        self._start(lambda progress: open_project(local_path(path), self.cancel_token, progress), done)

    @Slot(str)
    def note(self, text):
        if self._result and self._selected and not self._busy:
            self._result.notes[self._selected.id] = text

    @Slot(str)
    def navigateMethod(self, signature):
        if not self._busy and self._result and signature in self._result.program.methods:
            m = self._result.program.methods[signature]
            if m.instructions:
                self.navigateLocation(signature, m.instructions[0].offset, m.unit)

    @Slot(str, int, str)
    def navigateLocation(self, signature, offset, unit):
        if self._busy or not self._result:
            return
        try:
            location, content = bytecode_location(self._result.program, signature, offset, unit)
        except ValueError as exc:
            self._stage = 'Navigation refused: ' + str(exc)
            self.changed.emit()
            return
        if self._location and location != self._location:
            self._history.append(dict(self._location))
            self._history = self._history[-100:]
        self._location, self._content = location, content
        self._tab = 'Bytecode'
        self._field_page = None
        self._xref_page = None
        self._navigation_items = []
        self._stage = 'Exact DEX location · source-line mapping unavailable'
        self.detailChanged.emit()
        self.changed.emit()

    @Slot()
    def goBack(self):
        if not self._busy and self._history:
            previous = self._history.pop()
            self._location = {}
            self.navigateLocation(previous['method'], previous['offset'], previous['unit'])

    @Slot()
    def findingLocation(self):
        if self._selected and self._result:
            location = self._selected.location
            if location.offset is None:
                self._stage = 'Finding has no exact DEX instruction location'
                self.changed.emit()
                return
            method = self._result.program.methods.get(location.method)
            self.navigateLocation(location.method, location.offset, method.unit if method else '')
