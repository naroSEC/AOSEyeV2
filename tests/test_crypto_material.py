import pytest
from analyzer.analyzers.crypto_material import crypto_material, KEY, IV
from analyzer.analyzers.crypto_material import PBE, DERIVE
from analyzer.core.models import Instruction as I, Program
from analyzer.app.jobs import Cancellation
from conftest import method

INIT = 'Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V'


def program(kind=KEY, mode=1, extra=()):
    constructor = kind + ('-><init>([BLjava/lang/String;)V' if kind == KEY else '-><init>([B)V')
    m = method('Ltest/C;->run()V', [
        I(0, 'const-string', [0], literal='private-material-marker'),
        I(2, 'invoke-virtual', [0], target='Ljava/lang/String;->getBytes()[B'),
        I(8, 'move-result-object', [1]), I(10, 'new-instance', [2], literal=kind),
        I(12, 'invoke-direct', [2, 1, 0] if kind == KEY else [2, 1], target=constructor),
        I(18, 'const/4', [3], literal=mode), *extra,
        I(40, 'invoke-virtual', [9, 3, 2, 8] if kind == KEY else [9, 3, 8, 2], target=INIT),
        I(46, 'return-void')])
    return Program(methods={m.signature: m})


@pytest.mark.parametrize('kind', [KEY, IV])
def test_material_to_init_without_exposing_value(kind):
    f, = crypto_material(program(kind), Cancellation())
    assert f.analysis_level == 'L3' and f.type == 'REVIEW' and f.verification == 'MANUAL_REVIEW'
    assert [s['offset'] for s in f.data_flow] == [0, 2, 12, 40]
    assert 'private-material-marker' not in repr(f) and not f.attack_path


@pytest.mark.parametrize('flags,static,expected', [(0, True, 1), (8, True, 1),
    (None, True, 0), (-1, True, 0), (32, True, 0), (0, False, 0)])
def test_constant_base64_material(flags, static, expected):
    from analyzer.analyzers.crypto_material import BASE64
    p = program()
    m = next(iter(p.methods.values()))
    m.instructions.insert(1, I(1, 'const/4', [7], literal=flags))
    m.instructions[2].target = BASE64
    m.instructions[2].opcode = 'invoke-static' if static else 'invoke-virtual'
    m.instructions[2].registers = [0, 7]
    findings = crypto_material(p, Cancellation())
    assert len(findings) == expected
    assert 'private-material-marker' not in repr(findings)


@pytest.mark.parametrize('mode,expected', [(1, 1), (2, 0), (3, 0), (0, 0), (None, 0)])
def test_iv_requires_encryption_mode(mode, expected):
    assert len(crypto_material(program(IV, mode), Cancellation())) == expected


@pytest.mark.parametrize('extra', [
    [I(20, 'move-object', [2, 7])],
    [I(20, 'invoke-static', [2], target='Lunknown/A;->change(Ljava/lang/Object;)V')],
    [I(20, 'aput-byte', [0, 1, 7])],
    [I(20, 'if-eqz', [7])]])
def test_unknown_mutation_overwrite_or_branch_drops_provenance(extra):
    assert not crypto_material(program(extra=extra), Cancellation())


def test_bytes_mutation_before_copy():
    p = program()
    m = next(iter(p.methods.values()))
    m.instructions.insert(3, I(9, 'invoke-static', [1], target='Lunknown/A;->change([B)V'))
    assert not crypto_material(p, Cancellation())


def test_copy_survives_unknown_call_on_original_bytes():
    p = program(extra=[I(20, 'invoke-static', [1], target='Lunknown/A;->change([B)V')])
    assert len(crypto_material(p, Cancellation())) == 1


def test_block_separation_and_unused_constructor():
    p = program()
    m = next(iter(p.methods.values()))
    m.cfg = [{'offsets': [0, 2, 8, 10, 12, 18]}, {'offsets': [40, 46]}]
    assert not crypto_material(p, Cancellation())
    m.cfg = []
    m.instructions = m.instructions[:-2]
    assert not crypto_material(p, Cancellation())


def test_key_alias_and_decryption_mode():
    p = program(mode=2, extra=[I(20, 'move-object', [6, 2]), I(22, 'move-object', [2, 7])])
    m = next(iter(p.methods.values()))
    m.instructions[-2].registers[2] = 6
    assert len(crypto_material(p, Cancellation())) == 1


def test_wrong_constructor_arity_invalidates_existing_state():
    p = program(extra=[I(20, 'invoke-direct', [2], target=KEY + '-><init>([BLjava/lang/String;)V')])
    assert not crypto_material(p, Cancellation())


@pytest.mark.parametrize('signature,registers', [(PBE + '-><init>([C[BI)V', [2, 8, 1, 7]),
    (PBE + '-><init>([C[BII)V', [2, 8, 1, 7, 6])])
def test_constant_salt_constructor_to_derivation(signature, registers):
    p = program()
    m = next(iter(p.methods.values()))
    m.instructions[3].literal = PBE
    m.instructions[4].target, m.instructions[4].registers = signature, registers
    m.instructions[-2].target, m.instructions[-2].registers = DERIVE, [9, 2]
    f, = crypto_material(p, Cancellation())
    assert f.rule_id == 'AOS-CRYPTO-007' and f.type == 'REVIEW' and f.data_flow[-1]['offset'] == 40
    m.instructions[4].registers[2] = 20
    assert not crypto_material(p, Cancellation())
