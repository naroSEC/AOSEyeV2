import sqlite3
from zipfile import ZipFile
import pytest
from analyzer.analyzers.asset_database import inspect_database, MAX_BYTES
from analyzer.analyzers.apk import inspect_apk
from analyzer.app.jobs import Cancellation, Cancelled


def database(sql, rows=()):
    with sqlite3.connect(':memory:') as connection:
        connection.executescript(sql)
        if rows:
            connection.executemany('INSERT INTO accounts VALUES (?, ?)', rows)
        return connection.serialize()


def test_populated_values_are_candidates_not_confirmed_and_are_redacted():
    data = database('CREATE TABLE accounts (username TEXT, password TEXT);', [('alice', 'private-marker-value')])
    findings, diagnostics = inspect_database(data, 'assets/test.db', Cancellation())
    f, = findings
    assert not diagnostics and f.type == 'REVIEW' and f.verification == 'MANUAL_REVIEW'
    assert f.analysis_level == 'L2' and 'private-marker-value' not in repr(f)
    assert 'alice' not in repr(f) and 'accounts' not in repr(f)


@pytest.mark.parametrize('column,value', [('display_name', 'public'), ('password', ''), ('password', None), ('token_count', 4)])
def test_public_empty_or_noncredential_columns(column, value):
    data = database(f'CREATE TABLE accounts (id INTEGER, {column} TEXT);', [(1, value)])
    findings, diagnostics = inspect_database(data, 'test.db', Cancellation())
    assert not findings and not diagnostics


def test_views_and_triggers_are_not_executed():
    data = database('CREATE TABLE accounts (id INTEGER, public TEXT);'
                    'CREATE VIEW malicious AS SELECT load_extension("never-load") AS password;'
                    'CREATE TRIGGER sideeffect AFTER INSERT ON accounts BEGIN DELETE FROM accounts; END;')
    assert inspect_database(data, 'test.db', Cancellation()) == ([], [])


def test_quoted_table_name_is_not_sql():
    data = database('CREATE TABLE "a""; DROP TABLE accounts; --" (password TEXT);'
                    'INSERT INTO "a""; DROP TABLE accounts; --" VALUES ("secret");')
    findings, diagnostics = inspect_database(data, 'test.db', Cancellation())
    assert len(findings) == 1 and not diagnostics


def test_row_budget_reports_truncation():
    data = database('CREATE TABLE accounts (id INTEGER, password TEXT);', [(n, 'sample') for n in range(105)])
    findings, diagnostics = inspect_database(data, 'test.db', Cancellation())
    assert len(findings) == 1 and any('truncated' in d for d in diagnostics)
    assert 'Sampled rows: 100;' in findings[0].evidence[0]


@pytest.mark.parametrize('data', [b'', b'encrypted', b'SQLite format 3\x00bad', b'SQLite format 3\x00' + b'X' * MAX_BYTES],
                         ids=['empty', 'encrypted', 'malformed', 'oversized'])
def test_malformed_encrypted_and_oversized_databases(data):
    findings, diagnostics = inspect_database(data, 'test.db', Cancellation())
    assert not findings and diagnostics


def test_table_budget():
    data = database(''.join(f'CREATE TABLE t{n} (public TEXT);' for n in range(18)))
    findings, diagnostics = inspect_database(data, 'test.db', Cancellation())
    assert not findings and any('table scan budget' in d for d in diagnostics)


def test_cancel_propagates():
    data = database('CREATE TABLE accounts (id INTEGER, password TEXT);')
    cancel = Cancellation()
    cancel.cancel()
    with pytest.raises(Cancelled):
        inspect_database(data, 'test.db', cancel)


def test_apk_integration(tmp_path):
    apk = tmp_path / 'fixture.apk'
    data = database('CREATE TABLE accounts (id INTEGER, password TEXT);', [(1, 'sample-secret')])
    with ZipFile(apk, 'w') as archive:
        archive.writestr('assets/accounts.db', data)
    _, _, findings, diagnostics = inspect_apk(apk, Cancellation())
    assert not diagnostics
    assert any(f.rule_id == 'AOS-ASSET-002' for f in findings)
    assert 'sample-secret' not in repr(findings)
