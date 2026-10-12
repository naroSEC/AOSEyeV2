from analyzer.analyzers.context import constant_context
from analyzer.core.models import Instruction, Program
from conftest import method


def crypto(value):
    m = method('Ltest/Crypto;->use()V', [
        Instruction(0, 'const-string', [0], defs=[0], literal=value),
        Instruction(2, 'invoke-static', [0], target='Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;'),
        Instruction(8, 'return-void')])
    return Program(methods={m.signature: m})


def test_aes_without_mode_not_declared_vulnerable():
    assert constant_context(crypto('AES')) == []


def test_explicit_ecb_is_contextual_weakness():
    findings = constant_context(crypto('AES/ECB/PKCS5Padding'))
    assert findings[0].type == 'WEAKNESS'
    assert findings[0].analysis_level == 'L2'


def test_constant_killed_before_call():
    p = crypto('DES')
    m = next(iter(p.methods.values()))
    m.instructions.insert(1, Instruction(1, 'move-result-object', [0], defs=[0]))
    assert constant_context(p) == []


def test_unknown_move_without_defs_does_not_reuse_weak_algorithm():
    p = crypto('DES')
    next(iter(p.methods.values())).instructions.insert(1, Instruction(1, 'move-object', [0, 3]))
    assert constant_context(p) == []


def test_move_result_without_defs_does_not_reuse_weak_algorithm():
    p = crypto('DES')
    next(iter(p.methods.values())).instructions.insert(1, Instruction(1, 'move-result-object', [0]))
    assert constant_context(p) == []


def test_digest_without_security_purpose_is_review_not_weakness():
    p = crypto('MD5')
    next(iter(p.methods.values())).instructions[1].target = (
        'Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;')
    f = constant_context(p)[0]
    assert f.type == 'REVIEW' and f.severity == 'INFO' and f.analysis_level == 'L2'
    assert f.verification == 'MANUAL_REVIEW'


def test_benign_getters_and_log_predicate_are_not_api_reviews():
    from analyzer.analyzers.security import api_reviews
    from analyzer.core.rules.registry import RuleRegistry
    targets = ['Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z',
               'Landroid/webkit/WebSettings;->getJavaScriptEnabled()Z',
               'Landroid/webkit/WebSettings;->setDefaultTextEncodingName(Ljava/lang/String;)V',
               'Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V',
               'Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I']
    m = method('Ltest/Review;->run()V', [Instruction(n, 'invoke-virtual', target=t)
                                       for n, t in enumerate(targets)])
    findings = api_reviews(Program(methods={m.signature: m}), RuleRegistry())
    assert {f.sink for f in findings} == set(targets[-2:])
    assert all(f.type == 'REVIEW' for f in findings)
