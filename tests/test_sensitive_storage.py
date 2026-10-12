import pytest
from analyzer.analyzers.sensitive_storage import annotate_sensitive_storage, SQL
from analyzer.core.models import Instruction as I, Finding, Location, Program, AnalysisResult
from analyzer.app.jobs import Cancellation, Cancelled
from conftest import method

BIND = SQL + 'SQLiteStatement;->bindString(ILjava/lang/String;)V'
OPEN = 'Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;'
WRITE = 'Ljava/io/FileOutputStream;->write([B)V'


def case(code, rule, offset, change=''):
    m = method('Ltest/A;->run()V', code, [8, 9])
    m.exception_status = 'NONE'
    if change == 'exception': m.exception_status = 'UNKNOWN'
    if change == 'branch': m.instructions[0].successors = [2, 40]
    if change == 'truncated': m.diagnostics = ['truncated']
    f = Finding(rule, 'test', '', 'STORAGE', type='REVIEW', location=Location(m.class_name, m.signature, offset),
                validation={'persistence_or_exposure': 'UNKNOWN'})
    p = Program(methods={m.signature: m})
    annotate_sensitive_storage(p, [f], Cancellation())
    assert not f.attack_path and f.verification == 'MANUAL_REVIEW'
    assert f.validation['persistence_or_exposure'] == 'UNKNOWN'
    restored = AnalysisResult.from_dict(AnalysisResult('a.apk', '0'*64, program=p, findings=[f]).to_dict())
    assert restored.findings[0].review == f.review
    return f


@pytest.mark.parametrize('execute', ['execute()V', 'executeInsert()J', 'executeUpdateDelete()I'])
@pytest.mark.parametrize('change', ['same', 'alias', 'other', 'rebind', 'other_index', 'clear', 'null',
    'blob', 'long', 'unknown_index', 'invalid_index', 'escape', 'wide', 'exception', 'branch', 'truncated', 'arity'])
def test_sql_bound_value_execution(execute, change):
    extra = {
        'alias': [I(8, 'move-object', [3, 8])],
        'rebind': [I(8, 'invoke-virtual', [8, 1, 7], target=BIND)],
        'other_index': [I(8, 'const/4', [1], literal=2), I(10, 'invoke-virtual', [8, 1, 7], target=BIND)],
        'clear': [I(8, 'invoke-virtual', [8], target=SQL+'SQLiteProgram;->clearBindings()V')],
        'null': [I(8, 'invoke-virtual', [8, 1], target=SQL+'SQLiteProgram;->bindNull(I)V')],
        'blob': [I(8, 'invoke-virtual', [8, 1, 7], target=SQL+'SQLiteProgram;->bindBlob(I[B)V')],
        'long': [I(8, 'invoke-virtual', [8, 1, 6, 7], target=SQL+'SQLiteProgram;->bindLong(IJ)V')],
        'unknown_index': [I(8, 'invoke-virtual', [8, 6, 7], target=BIND)],
        'escape': [I(8, 'invoke-static', [8], target='Lx;->change(Ljava/lang/Object;)V')],
        'wide': [I(8, 'const-wide/16', [7], literal=0)],
    }.get(change, [])
    f = case([I(0, 'const/4', [1], literal=0 if change == 'invalid_index' else 1),
        I(2, 'invoke-virtual', [8, 1, 2], target=BIND), *extra,
        I(40, 'invoke-virtual', [] if change == 'arity' else [9 if change == 'other' else 3 if change == 'alias' else 8],
          target=SQL+'SQLiteStatement;->'+execute), I(46, 'return-void')], 'AOS-SENSITIVE-004', 2, change)
    assert (f.validation['storage_call_context'] == 'MODELED') == (change in ('same', 'alias', 'other_index'))
    if 'sqlite_context' in f.review:
        assert f.review['sqlite_context']['bind_index'] == 1
        assert f.review['sqlite_context']['execute_offset'] == 40


@pytest.mark.parametrize('change', ['same', 'alias', 'other', 'escape', 'overwrite', 'wide',
    'exception', 'branch', 'truncated', 'arity', 'encode'])
@pytest.mark.parametrize('filename', ['private-filename', '../secret', '/absolute', '', None])
def test_internal_file_origin(change, filename):
    extra = {
        'alias': [I(10, 'move-object', [3, 0])],
        'escape': [I(10, 'invoke-static', [0], target='Lx;->change(Ljava/lang/Object;)V')],
        'overwrite': [I(10, 'const/4', [0], literal=0)],
        'wide': [I(10, 'const-wide/16', [0], literal=0)],
        'encode': [I(10, 'invoke-virtual', [2], target='Ljava/lang/String;->getBytes()[B'),
                   I(16, 'move-result-object', [2])],
    }.get(change, [])
    f = case([I(0, 'const-string', [1], literal=filename), I(2, 'const/4', [4], literal=0),
        I(4, 'invoke-virtual', [8, 1, 4], target=OPEN), I(8, 'move-result-object', [0]), *extra,
        I(40, 'invoke-virtual', [9 if change == 'other' else 3 if change == 'alias' else 0, 2]
          if change != 'arity' else [0], target=WRITE), I(46, 'return-void')], 'AOS-SENSITIVE-005', 40, change)
    assert (f.validation['storage_call_context'] == 'MODELED') == (
        filename == 'private-filename' and change in ('same', 'alias', 'encode'))
    assert 'private-filename' not in repr(f.review)


def test_cancellation():
    m = method('Lx;->m()V', [I(0, 'return-void')])
    f = Finding('AOS-SENSITIVE-004', '', '', 'STORAGE', location=Location(m.class_name, m.signature, 0))
    c = Cancellation()
    c.cancel()
    with pytest.raises(Cancelled): annotate_sensitive_storage(Program(methods={m.signature:m}), [f], c)


@pytest.mark.parametrize('mode', [0, 32768, 1, 2, None])
def test_file_mode_is_evidence_not_a_protection_verdict(mode):
    f = case([I(0, 'const-string', [1], literal='name'), I(2, 'const', [4], literal=mode),
        I(4, 'invoke-virtual/range', [8, 1, 4], target=OPEN), I(8, 'move-result-object', [0]),
        I(40, 'invoke-virtual/range', [0, 2], target=WRITE), I(46, 'return-void')], 'AOS-SENSITIVE-005', 40)
    assert f.review['file_context']['mode'] == (mode if mode is not None else 'UNKNOWN')
    assert f.review['file_context']['other_app_access'] == 'UNKNOWN'
    assert f.review['file_context']['encryption'] == 'UNKNOWN'


def test_unknown_charset_callback_drops_file_context():
    f = case([I(0, 'const-string', [1], literal='name'), I(2, 'const', [4], literal=0),
        I(4, 'invoke-virtual', [8, 1, 4], target=OPEN), I(8, 'move-result-object', [0]),
        I(10, 'invoke-virtual', [2, 9], target='Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B'),
        I(16, 'move-result-object', [2]), I(40, 'invoke-virtual', [0, 2], target=WRITE),
        I(46, 'return-void')], 'AOS-SENSITIVE-005', 40)
    assert f.validation['storage_call_context'] == 'UNKNOWN'


@pytest.mark.parametrize('slots,expected', [(128, True), (129, False)])
def test_binding_context_budget(slots, expected):
    code, findings = [], []
    signature = 'Ltest/A;->run()V'
    for n in range(slots):
        code.extend([I(n*4, 'const', [1], literal=n+1), I(n*4+2, 'invoke-virtual', [8, 1, 2], target=BIND)])
        findings.append(Finding('AOS-SENSITIVE-004', '', '', 'STORAGE',
            location=Location('Ltest/A;', signature, n*4+2)))
    code.extend([I(slots*4, 'invoke-virtual', [8], target=SQL+'SQLiteStatement;->execute()V'),
                 I(slots*4+2, 'return-void')])
    m = method(signature, code, [8])
    m.exception_status = 'NONE'
    annotate_sensitive_storage(Program(methods={signature:m}), findings, Cancellation())
    assert all((f.validation['storage_call_context'] == 'MODELED') == expected for f in findings)


def test_method_instruction_limit():
    m = method('Ltest/A;->run()V', [I(n*2, 'nop') for n in range(4001)], [8])
    m.exception_status = 'NONE'
    f = Finding('AOS-SENSITIVE-004', '', '', 'STORAGE', location=Location(m.class_name, m.signature, 0))
    annotate_sensitive_storage(Program(methods={m.signature:m}), [f], Cancellation())
    assert f.validation['storage_call_context'] == 'UNKNOWN'
