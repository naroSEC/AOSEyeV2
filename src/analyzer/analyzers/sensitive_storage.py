"""Bounded storage-call context on credential flows; no persistence/safety verdict."""
from collections import defaultdict
from analyzer.analyzers.tls import _linear
from analyzer.analyzers.receiver_context import MOVES, CONSTS

SQL = 'Landroid/database/sqlite/'
BIND = {SQL + owner + ';->' + member: count
        for owner in ('SQLiteProgram', 'SQLiteStatement')
        for member, count in (('bindString(ILjava/lang/String;)V', 3), ('bindNull(I)V', 2),
                              ('bindLong(IJ)V', 4), ('bindDouble(ID)V', 4), ('bindBlob(I[B)V', 3))}
CLEAR = {SQL + owner + ';->clearBindings()V' for owner in ('SQLiteProgram', 'SQLiteStatement')}
EXECUTE = {SQL + 'SQLiteStatement;->' + member for member in
           ('execute()V', 'executeInsert()J', 'executeUpdateDelete()I')}
OPEN = {owner + '->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;'
        for owner in ('Landroid/content/Context;', 'Landroid/content/ContextWrapper;',
                      'Landroid/app/Activity;', 'Landroid/app/Service;', 'Landroid/app/Application;')}
WRITE = {owner + '->' + member: count for owner in ('Ljava/io/FileOutputStream;', 'Ljava/io/OutputStream;')
         for member, count in (('write([B)V', 2), ('write([BII)V', 4))}
ENCODE = {'Ljava/lang/String;->getBytes()[B': 1,
          'Ljava/lang/String;->getBytes(Ljava/lang/String;)[B': 2}


def annotate_sensitive_storage(program, findings, cancel):
    grouped = defaultdict(lambda: defaultdict(list))
    for finding in findings:
        if finding.rule_id in ('AOS-SENSITIVE-004', 'AOS-SENSITIVE-005'):
            grouped[finding.location.method][finding.location.offset].append(finding)
            finding.validation['storage_call_context'] = 'UNKNOWN'
    for signature, targets in grouped.items():
        cancel.check()
        method = program.methods.get(signature)
        if method is None or len(method.instructions) > 4000 or not _linear(method):
            continue
        refs = {r: ('parameter', r) for r in method.parameter_registers}
        constants, bindings, streams = {}, {}, {}
        pending = None
        for ins in method.instructions:
            cancel.check()
            rr, op = ins.registers, ins.opcode
            old, values, result = dict(refs), dict(constants), pending
            pending = None
            for reg in ins.defs:
                refs.pop(reg, None)
                constants.pop(reg, None)
            if op in MOVES and len(rr) == 2:
                refs.pop(rr[0], None)
                constants.pop(rr[0], None)
                if rr[1] in old:
                    refs[rr[0]] = old[rr[1]]
                if rr[1] in values:
                    constants[rr[0]] = values[rr[1]]
            elif op == 'move-result-object' and len(rr) == 1:
                refs.pop(rr[0], None)
                constants.pop(rr[0], None)
                if result is not None:
                    refs[rr[0]] = result
            elif op.startswith('const') and len(rr) == 1:
                refs.pop(rr[0], None)
                constants.pop(rr[0], None)
                if op in CONSTS and type(ins.literal) is int:
                    constants[rr[0]] = ins.literal
                elif op in ('const-string', 'const-string/jumbo') and isinstance(ins.literal, str):
                    constants[rr[0]] = ins.literal
                if op.startswith('const-wide'):
                    refs.pop(rr[0] + 1, None)
                    constants.pop(rr[0] + 1, None)
            elif op.startswith('invoke'):
                receiver = old.get(rr[0]) if rr else None
                virtual = op in ('invoke-virtual', 'invoke-virtual/range')
                target = ins.target
                if virtual and target in BIND and len(rr) == BIND[target] and receiver is not None:
                    state = bindings.get(receiver, {}).copy()
                    # Different symbolic parameters can alias: don't retain facts on other receivers.
                    bindings, streams = {}, {}
                    index = values.get(rr[1])
                    if type(index) is int and 1 <= index <= 32766:
                        state.pop(index, None)
                        rows = [f for f in targets.get(ins.offset, []) if f.rule_id == 'AOS-SENSITIVE-004']
                        if target.endswith('->bindString(ILjava/lang/String;)V') and rows:
                            state[index] = rows
                        if len(state) <= 128:
                            bindings[receiver] = state
                elif virtual and target in CLEAR and len(rr) == 1:
                    bindings, streams = {}, {}
                elif virtual and target in EXECUTE and len(rr) == 1 and receiver is not None:
                    for index, rows in bindings.get(receiver, {}).items():
                        for finding in rows:
                            finding.validation.update(storage_call_context='MODELED', sqlite_execute_call='MODELED')
                            finding.review['sqlite_context'] = dict(method=signature, bind_offset=finding.location.offset,
                                bind_index=index, execute_offset=ins.offset, execute_api=target,
                                execution_success='UNKNOWN', transaction_commit='UNKNOWN',
                                database_location='UNKNOWN', encryption='UNKNOWN')
                    # Execution can invoke application callbacks. Do not model subsequent executions.
                    bindings, streams = {}, {}
                elif virtual and target in OPEN and len(rr) == 3:
                    bindings, streams = {}, {}
                    pending = ('opened_file', ins.offset)
                    name = values.get(rr[1])
                    mode = values.get(rr[2])
                    if (isinstance(name, str) and 0 < len(name) <= 255 and name not in ('.', '..')
                            and not any(c in name for c in '/\\\x00\r\n:')):
                        streams[pending] = dict(open_offset=ins.offset, open_api=target,
                            requested_location='APP_INTERNAL_FILES',
                            mode=mode if type(mode) is int and 0 <= mode <= 0x7fffffff else 'UNKNOWN')
                elif virtual and target in WRITE and len(rr) == WRITE[target] and receiver is not None:
                    state = streams.get(receiver)
                    if state:
                        for finding in targets.get(ins.offset, []):
                            if finding.rule_id == 'AOS-SENSITIVE-005':
                                finding.validation.update(storage_call_context='MODELED',
                                                          storage_requested_location='APP_INTERNAL_FILES')
                                finding.review['file_context'] = dict(state, method=signature, write_offset=ins.offset,
                                    runtime_location='UNKNOWN', persistence='UNKNOWN', encryption='UNKNOWN',
                                    other_app_access='UNKNOWN')
                    bindings, streams = {}, {}
                elif virtual and target in ENCODE and len(rr) == ENCODE[target]:
                    # String.getBytes does not mutate a previously opened file or SQL binding.
                    pending = ('encoded_bytes', ins.offset)
                else:
                    bindings, streams = {}, {}
                    pending = ('call_result', ins.offset)
            elif op != 'nop':
                refs, constants, bindings, streams = {}, {}, {}, {}
