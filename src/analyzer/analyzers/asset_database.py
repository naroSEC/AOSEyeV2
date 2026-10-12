"""Bounded, in-memory SQLite credential-column sampling. Never execute stored SQL."""
import re
import sqlite3
from analyzer.core.models import Finding, Location

MAX_BYTES = 2 * 1024 * 1024
SENSITIVE_COLUMN = re.compile(r'^(?:password|passwd|secret|client_secret|api_key|access_token|refresh_token|private_key)$', re.I)


def inspect_database(content, filename, cancel):
    if not content.startswith(b'SQLite format 3\x00'):
        return [], ['SQLite content unavailable or format unsupported: ' + filename]
    if len(content) > MAX_BYTES:
        return [], ['SQLite content scan byte budget exceeded: ' + filename]
    cancel.check()
    findings, diagnostics, ticks = [], [], 0
    def progress():
        nonlocal ticks
        ticks += 1
        return int(cancel.event.is_set() or ticks > 100)
    connection = sqlite3.connect(':memory:')
    try:
        connection.deserialize(content)
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA query_only=ON')
        connection.set_progress_handler(progress, 1000)
        allowed = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ}
        connection.set_authorizer(lambda action, *args: sqlite3.SQLITE_OK if action in allowed else sqlite3.SQLITE_DENY)
        # Read ordinary table names only. Views, triggers, virtual-table module
        # definitions and SQL stored in rows are never executed.
        tables = connection.execute("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY rowid LIMIT 17").fetchall()
        if len(tables) > 16:
            diagnostics.append('SQLite table scan budget exceeded: ' + filename)
        for ordinal, (table, sql) in enumerate(tables[:16]):
            cancel.check()
            if (not isinstance(table, str) or table.startswith('sqlite_') or not isinstance(sql, str)
                    or not re.match(r'^\s*CREATE\s+TABLE\s', sql, re.I)):
                continue
            quoted = '"' + table.replace('"', '""') + '"'
            cursor = connection.execute('SELECT * FROM ' + quoted + ' LIMIT 101')
            columns = [d[0] for d in cursor.description]
            if len(columns) > 64:
                diagnostics.append('SQLite column scan budget exceeded: ' + filename)
                continue
            selected = [n for n, name in enumerate(columns) if SENSITIVE_COLUMN.fullmatch(name)]
            if not selected:
                continue
            rows = cursor.fetchmany(101)
            if len(rows) > 100:
                diagnostics.append('SQLite row sample truncated: ' + filename)
            populated = set()
            for row in rows[:100]:
                cancel.check()
                populated.update(n for n in selected if isinstance(row[n], (str, bytes)) and len(row[n]) > 0)
            if populated:
                # No values, table names or column names leave the parser. Table
                # ordinal gives a deterministic location without leaking data.
                findings.append(Finding('AOS-ASSET-002', 'Bundled SQLite contains populated credential-named columns',
                    'A bounded sample contains nonempty text/blob values in credential-named columns. '
                    'Values may be examples, hashes, ciphertext or public identifiers; credential validity is not established.',
                    'SECRETS', severity='LOW', confidence='MEDIUM', analysis_level='L2',
                    location=Location(file=filename, offset=ordinal),
                    evidence=[f'Sampled rows: {min(len(rows), 100)}; populated credential-named columns: {len(populated)}; all names/values redacted'],
                    recommendation='Review whether bundled database values contain live secrets; remove or rotate only if confirmed.'))
    except (sqlite3.Error, ValueError, OverflowError):
        cancel.check()  # Progress-handler exceptions are converted to SQLite errors.
        diagnostics.append('SQLite scan incomplete (invalid content, unsupported schema or operation budget): ' + filename)
    finally:
        connection.close()
    return findings, diagnostics
