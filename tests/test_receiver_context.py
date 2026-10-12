import pytest
from analyzer.analyzers.receiver_context import annotate_receiver_context, GET_SETTINGS, PUT, EDITOR
from analyzer.core.models import Finding, Location, Program, Instruction as I, AnalysisResult
from analyzer.app.jobs import Cancellation, Cancelled
from conftest import method

JS = 'Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V'
LOAD = 'Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V'


def case(code, offset, rule='AOS-WEBVIEW-004'):
    m = method('Ltest/A;->run()V', code, [8, 9])
    m.exception_status = 'NONE'
    f = Finding(rule, 'test', '', 'WEBVIEW', location=Location(m.class_name, m.signature, offset))
    return Program(methods={m.signature: m}), f


def web(value=1, extra=None, receiver=8):
    return case([I(0, 'invoke-virtual', [8], target=GET_SETTINGS), I(2, 'move-result-object', [0]),
        I(4, 'const/4', [1], literal=value), I(6, 'invoke-virtual', [0, 1], target=JS),
        *(extra or []), I(20, 'invoke-virtual', [receiver, 2], target=LOAD), I(22, 'return-void')], 20)


@pytest.mark.parametrize('value,expected', [(1, 'ENABLED'), (0, 'DISABLED'), (2, 'UNKNOWN')])
def test_web_settings_same_receiver(value, expected):
    p, f = web(value)
    annotate_receiver_context(p, [f], Cancellation())
    assert f.validation['webview_javascript'] == expected
    assert f.review['webview_context']['settings']['javascript']['offset'] == 6
    restored = AnalysisResult.from_dict(AnalysisResult('a.apk', '0'*64, program=p, findings=[f]).to_dict())
    assert restored.findings[0].review == f.review and not f.attack_path


@pytest.mark.parametrize('change', ['other', 'call', 'store', 'overwrite', 'wide', 'exceptions', 'diagnostic', 'branch', 'arity'])
def test_web_does_not_retain_unproven_context(change):
    extra = {'call': [I(8, 'invoke-static', [], target='Lx;->mutate()V')],
             'store': [I(8, 'iput-object', [0, 7])],
             'overwrite': [I(8, 'const/4', [8], literal=0)],
             'wide': [I(8, 'const-wide/16', [7], literal=0)]}.get(change)
    p, f = web(extra=extra, receiver=9 if change == 'other' else 8)
    m = p.methods[f.location.method]
    if change == 'exceptions': m.exception_status = 'UNKNOWN'
    if change == 'diagnostic': m.diagnostics = ['truncated']
    if change == 'branch': m.instructions[0].successors = [2, 20]
    if change == 'arity': m.instructions[-2].registers = [8]
    annotate_receiver_context(p, [f], Cancellation())
    assert f.validation['receiver_context'] == 'UNKNOWN'
    assert 'webview_javascript' not in f.validation


def test_alias_and_later_disable():
    p, f = web(extra=[I(8, 'move-object', [3, 0]), I(10, 'const/4', [1], literal=0),
                      I(12, 'invoke-virtual', [3, 1], target=JS)])
    annotate_receiver_context(p, [f], Cancellation())
    assert f.validation['webview_javascript'] == 'DISABLED'


@pytest.mark.parametrize('operation', ['apply()V', 'commit()Z'])
@pytest.mark.parametrize('change', ['same', 'alias', 'fluent', 'other', 'clear', 'overwrite', 'escape'])
def test_editor_flush_connection(operation, change):
    extra = {'alias': [I(4, 'move-object', [3, 8])],
        'fluent': [I(4, 'move-result-object', [3])],
        'clear': [I(4, 'invoke-interface', [8], target=EDITOR+'clear()Landroid/content/SharedPreferences$Editor;')],
        'overwrite': [I(4, 'invoke-interface', [8, 1, 2], target=PUT)],
        'escape': [I(4, 'invoke-static', [8], target='Lx;->change(Ljava/lang/Object;)V')]}.get(change, [])
    receiver = 9 if change == 'other' else 3 if change in ('alias', 'fluent') else 8
    p, f = case([I(0, 'invoke-interface', [8, 1, 2], target=PUT), *extra,
        I(20, 'invoke-interface', [receiver], target=EDITOR+operation), I(22, 'return-void')], 0, 'AOS-SENSITIVE-003')
    annotate_receiver_context(p, [f], Cancellation())
    assert (f.validation['receiver_context'] == 'MODELED') == (change in ('same', 'alias', 'fluent'))
    assert f.verification == 'MANUAL_REVIEW' and not f.attack_path


def test_cancel():
    p, f = web()
    token = Cancellation()
    token.cancel()
    with pytest.raises(Cancelled):
        annotate_receiver_context(p, [f], token)


@pytest.mark.parametrize('change', ['same', 'alias', 'other', 'remove', 'remove_other', 'null',
    'unknown_name', 'escape', 'load_twice', 'wrong_arity', 'disable', 'unknown_remove'])
def test_bridge_registration_context(change):
    from analyzer.analyzers.receiver_context import ADD_BRIDGE, REMOVE_BRIDGE
    extra = {
        'alias': [I(12, 'move-object', [3, 8])],
        'remove': [I(12, 'invoke-virtual', [8, 4], target=REMOVE_BRIDGE)],
        'remove_other': [I(12, 'const-string', [5], literal='different'),
                         I(14, 'invoke-virtual', [8, 5], target=REMOVE_BRIDGE)],
        'escape': [I(12, 'invoke-static', [8], target='Lx;->change(Ljava/lang/Object;)V')],
        'load_twice': [I(12, 'invoke-virtual', [8, 2], target=LOAD)],
        'disable': [I(12, 'const/4', [1], literal=0), I(14, 'invoke-virtual', [0, 1], target=JS)],
        'unknown_remove': [I(12, 'invoke-virtual', [8, 5], target=REMOVE_BRIDGE)],
    }.get(change, [])
    setup = [I(8, 'const-string', [4], literal='private-bridge-name')]
    if change == 'unknown_name': setup = []
    if change == 'null': setup.append(I(9, 'const/4', [9], literal=0))
    setup.append(I(10, 'invoke-virtual', [8, 9, 4] if change != 'wrong_arity' else [8, 9], target=ADD_BRIDGE))
    p, f = web(extra=setup + extra, receiver=9 if change == 'other' else 3 if change == 'alias' else 8)
    annotate_receiver_context(p, [f], Cancellation())
    assert (f.validation.get('webview_bridge_registration') == 'MODELED') == (
        change in ('same', 'alias', 'remove_other', 'disable'))
    assert 'private-bridge-name' not in str(f.review)
    assert not f.attack_path and f.verification == 'MANUAL_REVIEW'
    if change == 'disable':
        assert f.validation['webview_javascript'] == 'DISABLED'
