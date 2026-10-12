"""Bounded, path-local reference-array slots. No nested object heap or bounds proof."""
from analyzer.core.objectflow import ObjectValue

MAX_ARRAY_LENGTH = 64
MAX_ARRAY_OBJECTS = 128
ARRAYCOPY = 'Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V'
COPY_OF = 'Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;'
COPY_OF_RANGE = 'Ljava/util/Arrays;->copyOfRange([Ljava/lang/Object;II)[Ljava/lang/Object;'
ARRAY_CLONES = {kind + '->clone()Ljava/lang/Object;' for kind in ('[Ljava/lang/String;', '[Ljava/lang/Object;')}
FILL = 'Ljava/util/Arrays;->fill([Ljava/lang/Object;Ljava/lang/Object;)V'
FILL_RANGE = 'Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V'


def length(ins, regs, memory, previous, method, diagnostic):
    rr = ins.registers
    if rr:
        regs.pop(rr[0], None)
        memory.kill(rr[0])
    obj = previous.object(rr[1]) if len(rr) == 2 else None
    if (obj is None or obj.type not in ('[Ljava/lang/String;', '[Ljava/lang/Object;')
            or type(obj.array_length) is not int or not 0 <= obj.array_length <= MAX_ARRAY_LENGTH):
        diagnostic('Unresolved array-length identity/type/length/budget: ' + method)
        return
    memory.constants[rr[0]] = obj.array_length


def fill_call(ins, old, memory, previous, method, diagnostic):
    if ins.target not in (FILL, FILL_RANGE):
        return False
    rr = ins.registers
    obj = previous.object(rr[0]) if rr else None
    ranged = ins.target == FILL_RANGE
    arity = 4 if ranged else 2
    start = previous.constants.get(rr[1]) if ranged and len(rr) == arity else 0
    end = previous.constants.get(rr[2]) if ranged and len(rr) == arity else obj.array_length if obj else None
    if (obj is None or obj.type != '[Ljava/lang/Object;' or type(obj.array_length) is not int
            or not 0 <= obj.array_length <= MAX_ARRAY_LENGTH or len(rr) != arity
            or type(start) is not int or type(end) is not int or not 0 <= start <= end <= obj.array_length
            or ins.opcode not in ('invoke-static', 'invoke-static/range')
            or (start != end and rr[-1] in previous.refs)):
        if obj is not None and obj.type.startswith('['):
            memory.objects[previous.refs[rr[0]]] = ObjectValue(obj.type)
        diagnostic('Unresolved Arrays.fill array/type/length/value/format/budget: ' + method)
        return True
    if start == end:
        return True
    trace = old.get(rr[-1])
    label = 'Arrays.fill range index ' if ranged else 'Arrays.fill index '
    slots = {}
    for index in range(obj.array_length):
        if start <= index < end:
            slots[index] = trace.step(method, ins.offset, label + str(index)) if trace else None
        else:
            # Materialize the wildcard only outside the overwritten interval.
            wildcard = obj.array_elements.get(None)
            candidates = [v for v in (obj.array_elements.get(index), wildcard) if v]
            prior = next((v for v in candidates if v.external), next(iter(candidates), None))
            slots[index] = prior.step(method, ins.offset, 'Arrays.fill preserved index ' + str(index), True) if prior and prior is wildcard else prior
    memory.update(rr[0], array_elements=slots)
    return True


def copy_of_call(ins, memory, previous, method, diagnostic):
    if ins.target not in (COPY_OF, COPY_OF_RANGE) or not ins.opcode.startswith('invoke-static'):
        return False
    rr = ins.registers
    ranged = ins.target == COPY_OF_RANGE
    arity = 3 if ranged else 2
    source = previous.object(rr[0]) if len(rr) == arity else None
    start = previous.constants.get(rr[1]) if ranged and len(rr) == arity else 0
    end = previous.constants.get(rr[-1]) if len(rr) == arity else None
    length = end - start if type(start) is int and type(end) is int else None
    name = 'Arrays.copyOfRange' if ranged else 'Arrays.copyOf'
    if (source is None or source.type not in ('[Ljava/lang/String;', '[Ljava/lang/Object;')
            or source.array_length is None or type(length) is not int or not 0 <= length <= MAX_ARRAY_LENGTH
            or not 0 <= start <= source.array_length
            or sum(v.type.startswith('[') for v in memory.objects.values()) >= MAX_ARRAY_OBJECTS):
        diagnostic('Unresolved ' + name + ' identity/length/budget: ' + method)
        return True
    slots = {}
    for index in range(min(length, source.array_length - start)):
        source_index = start + index
        candidates = [source.array_elements.get(source_index), source.array_elements.get(None)]
        candidates = [trace for trace in candidates if trace]
        trace = next((v for v in candidates if v.external), next(iter(candidates), None))
        label = name + ' index ' + (str(source_index) + ' -> ' + str(index) if ranged else str(index))
        slots[index] = trace.step(method, ins.offset, label,
                                  trace is source.array_elements.get(None)) if trace else None
    # Unpopulated tail slots are null, never a copy of the source wildcard.
    memory.sequence += 1
    identity = ('allocation', memory.sequence)
    memory.objects[identity] = ObjectValue(source.type, array_length=length, array_elements=slots)
    memory.result_ref = identity
    return True


def clone_call(ins, memory, previous, method, diagnostic):
    if ins.target not in ARRAY_CLONES or not ins.opcode.startswith('invoke-virtual'):
        return False
    source = previous.object(ins.registers[0]) if len(ins.registers) == 1 else None
    if (source is None or source.type != ins.target.split('->')[0] or source.array_length is None
            or sum(v.type.startswith('[') for v in memory.objects.values()) >= MAX_ARRAY_OBJECTS):
        diagnostic('Unresolved array clone identity/type/budget: ' + method)
        return True
    memory.sequence += 1
    identity = ('allocation', memory.sequence)
    slots = {key: trace.step(method, ins.offset, 'array clone') if trace else None
             for key, trace in source.array_elements.items()}
    memory.objects[identity] = ObjectValue(source.type, array_length=source.array_length, array_elements=slots)
    memory.result_ref = identity
    return True


def copy_call(ins, memory, previous, method, diagnostic):
    if ins.target != ARRAYCOPY or not ins.opcode.startswith('invoke-static'):
        return False
    rr = ins.registers
    if len(rr) != 5:
        diagnostic('Malformed System.arraycopy arguments: ' + method)
        return False
    source, destination = previous.object(rr[0]), previous.object(rr[2])
    start, target, count = (previous.constants.get(rr[n]) for n in (1, 3, 4))
    valid = (source is not None and destination is not None
             and type(source.array_length) is int and type(destination.array_length) is int
             and 0 <= source.array_length <= MAX_ARRAY_LENGTH and 0 <= destination.array_length <= MAX_ARRAY_LENGTH
             and source.type == destination.type and source.type in ('[Ljava/lang/String;', '[Ljava/lang/Object;')
             and all(type(n) is int and n >= 0 for n in (start, target, count)))
    valid = valid and start + count <= source.array_length and target + count <= destination.array_length
    if not valid:
        diagnostic('Unresolved System.arraycopy identity/type/range; destination content invalidated: ' + method)
        if destination is not None:
            memory.objects[previous.refs[rr[2]]] = ObjectValue(destination.type)
        return True
    if count == 0:
        return True
    # Read exclusively from the pre-call snapshot, including overlapping ranges.
    slots = dict(destination.array_elements)
    wildcard = slots.pop(None, None)
    if wildcard:
        for index in range(destination.array_length):
            if target <= index < target + count:
                continue
            candidates = [v for v in (slots.get(index), wildcard) if v]
            prior = next((v for v in candidates if v.external), candidates[0])
            slots[index] = prior.step(method, ins.offset, 'System.arraycopy preserved index ' + str(index), True) if prior is wildcard else prior
    for n in range(count):
        candidates = [source.array_elements.get(start + n), source.array_elements.get(None)]
        candidates = [value for value in candidates if value]
        trace = next((v for v in candidates if v.external), next(iter(candidates), None))
        slots[target + n] = trace.step(method, ins.offset,
            'System.arraycopy index %d -> %d' % (start + n, target + n),
            trace is source.array_elements.get(None)) if trace else None
    memory.update(rr[2], array_elements=slots)
    return True


def allocate_filled(ins, old, memory, previous, method, diagnostic):
    length = len(ins.registers)
    if (ins.literal not in ('[Ljava/lang/String;', '[Ljava/lang/Object;')
            or length > MAX_ARRAY_LENGTH
            or sum(v.type.startswith('[') for v in memory.objects.values()) >= MAX_ARRAY_OBJECTS):
        diagnostic('Unmodeled filled array allocation (type/length/budget)')
        return
    slots = {}
    for index, register in enumerate(ins.registers):
        if register in previous.refs:
            diagnostic('Nested filled-array object reference unsupported: ' + method)
        trace = old.get(register)
        slots[index] = trace.step(method, ins.offset, 'filled array index ' + str(index)) if trace else None
    memory.sequence += 1
    identity = ('allocation', memory.sequence)
    memory.objects[identity] = ObjectValue(ins.literal, array_length=length, array_elements=slots)
    memory.result_ref = identity


def allocate(ins, memory, previous, diagnostic):
    rr = ins.registers
    length = previous.constants.get(rr[1]) if len(rr) > 1 else None
    if (ins.literal not in ('[Ljava/lang/String;', '[Ljava/lang/Object;') or type(length) is not int
            or not 0 <= length <= MAX_ARRAY_LENGTH
            or sum(v.type.startswith('[') for v in memory.objects.values()) >= MAX_ARRAY_OBJECTS):
        diagnostic('Unmodeled array allocation (type/length/budget)')
        return
    memory.sequence += 1
    identity = ('allocation', memory.sequence)
    memory.refs[rr[0]] = identity
    memory.objects[identity] = ObjectValue(ins.literal, array_length=length)


def access(ins, old, regs, memory, previous, method, diagnostic):
    rr = ins.registers
    if len(rr) < 3:
        diagnostic('Malformed array instruction: ' + method)
        return
    obj = previous.object(rr[1])
    if (obj is None or type(obj.array_length) is not int or not 0 <= obj.array_length <= MAX_ARRAY_LENGTH):
        diagnostic('Unmodeled array identity/content: ' + method)
        return
    index = previous.constants.get(rr[2])
    known = type(index) is int
    if known and not 0 <= index < obj.array_length:
        diagnostic('Array index outside modeled length: ' + method)
        return
    slots = dict(obj.array_elements)
    if obj.array_length == 0:
        diagnostic('Array access on zero-length allocation: ' + method)
        return
    if ins.opcode == 'aput-object':
        trace = old.get(rr[0])
        if rr[0] in previous.refs:
            diagnostic('Nested array/object reference storage unsupported: ' + method)
        if not known:
            diagnostic('Unknown array write index: ' + method)
            slots = {key: value.step(method, ins.offset, 'possible array overwrite', True)
                     for key, value in slots.items() if value}
            if trace:
                # A wildcard applies to all slots until a subsequent strong update.
                prior = slots.get(None)
                trace = prior if prior and prior.external and not trace.external else trace
                slots[None] = trace.step(method, ins.offset, 'array write unknown index', True)
        else:
            wildcard = slots.pop(None, None)
            if wildcard:
                for position in range(obj.array_length):
                    if position == index:
                        continue
                    candidates = [v for v in (slots.get(position), wildcard) if v]
                    prior = next((v for v in candidates if v.external), candidates[0])
                    slots[position] = prior.step(method, ins.offset, 'array preserved index ' + str(position), True) if prior is wildcard else prior
            slots[index] = trace.step(method, ins.offset, 'array write index ' + str(index)) if trace else None
        memory.update(rr[1], array_elements=slots)
    else:
        if not known:
            diagnostic('Unknown array read index: ' + method)
        candidates = ([slots.get(index), slots.get(None)] if known else list(slots.values()))
        candidates = [value for value in candidates if value]
        trace = next((v for v in candidates if v.external), next(iter(candidates), None))
        if trace:
            uncertain = not known or trace is slots.get(None)
            regs[rr[0]] = trace.step(method, ins.offset, 'array read index ' + (str(index) if known else 'unknown'), uncertain)
