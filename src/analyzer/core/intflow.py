"""Small signed-int constant model; not a symbolic arithmetic solver."""
LITERAL_BITS = {'add-int/lit8': 8, 'add-int/lit16': 16, 'mul-int/lit8': 8, 'mul-int/lit16': 16}


def register_arithmetic(ins, old, regs, memory, previous, method, diagnostic):
    rr = ins.registers
    if rr:
        regs.pop(rr[0], None)
        memory.kill(rr[0])
    two_address = ins.opcode.endswith('/2addr')
    if len(rr) != (2 if two_address else 3):
        diagnostic('Malformed integer register arithmetic: ' + method)
        return
    sources = rr if two_address else rr[1:]
    values = [previous.constants.get(r) for r in sources]
    if all(type(v) is int and -2147483648 <= v <= 2147483647 for v in values):
        if ins.opcode.startswith('mul-'):
            result = values[0] * values[1]
        else:
            result = values[0] + values[1] if ins.opcode.startswith('add-') else values[0] - values[1]
        memory.constants[rr[0]] = ((result + 2147483648) % 4294967296) - 2147483648
    else:
        diagnostic('Unresolved integer register arithmetic source: ' + method)
    candidates = [old[r] for r in sources if r in old]
    trace = next((v for v in candidates if v.external), next(iter(candidates), None))
    if trace:
        regs[rr[0]] = trace.step(method, ins.offset, ins.opcode, True)


def literal_arithmetic(ins, old, regs, memory, previous, method, diagnostic):
    rr = ins.registers
    if rr:
        regs.pop(rr[0], None)
        memory.kill(rr[0])
    bits = LITERAL_BITS[ins.opcode]
    literal = ins.literal
    if len(rr) != 2 or type(literal) is not int or not -(1 << (bits - 1)) <= literal < (1 << (bits - 1)):
        diagnostic('Malformed integer literal arithmetic: ' + method)
        return
    value = previous.constants.get(rr[1])
    if type(value) is int and -2147483648 <= value <= 2147483647:
        result = value * literal if ins.opcode.startswith('mul-') else value + literal
        memory.constants[rr[0]] = ((result + 2147483648) % 4294967296) - 2147483648
    else:
        diagnostic('Unresolved integer literal arithmetic source: ' + method)
    trace = old.get(rr[1])
    if trace:
        regs[rr[0]] = trace.step(method, ins.offset, ins.opcode, True)
