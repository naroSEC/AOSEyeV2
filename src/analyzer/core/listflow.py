"""Bounded exact ArrayList allocation/slot model; not a general collection heap."""
from analyzer.core.objectflow import ARRAYLIST, ObjectValue

MAX_LIST_ITEMS = 64
MAX_LIST_OBJECTS = 128
LIST = 'Ljava/util/List;'
COLLECTION = 'Ljava/util/Collection;'
TO_ARRAY_ARGUMENT = 'toArray([Ljava/lang/Object;)[Ljava/lang/Object;'
ADD_ALL = 'addAll(Ljava/util/Collection;)Z'
ADD_ALL_INDEXED = 'addAll(ILjava/util/Collection;)Z'
CAPACITY_INIT = '<init>(I)V'
COLLECTION_INIT = '<init>(Ljava/util/Collection;)V'
SWAP = 'Ljava/util/Collections;->swap(Ljava/util/List;II)V'
REVERSE = 'Ljava/util/Collections;->reverse(Ljava/util/List;)V'
ROTATE = 'Ljava/util/Collections;->rotate(Ljava/util/List;I)V'
FILL = 'Ljava/util/Collections;->fill(Ljava/util/List;Ljava/lang/Object;)V'
COPY = 'Ljava/util/Collections;->copy(Ljava/util/List;Ljava/util/List;)V'
ADD_ALL_ARRAY = 'Ljava/util/Collections;->addAll(Ljava/util/Collection;[Ljava/lang/Object;)Z'


def _add_all_array(ins, memory, previous, method, diagnostic):
    from analyzer.core.arrayflow import MAX_ARRAY_LENGTH
    rr = ins.registers
    dest = previous.object(rr[0]) if rr else None
    source = previous.object(rr[1]) if len(rr) == 2 else None
    known = dest is not None and dest.type == ARRAYLIST
    if (not known or dest.list_items is None or source is None
            or source.type not in ('[Ljava/lang/String;', '[Ljava/lang/Object;')
            or type(source.array_length) is not int or not 0 <= source.array_length <= MAX_ARRAY_LENGTH
            or len(dest.list_items) + source.array_length > MAX_LIST_ITEMS
            or ins.opcode not in ('invoke-static', 'invoke-static/range')):
        if known:
            memory.update(rr[0], list_items=None)
        diagnostic('Unresolved Collections.addAll array/list/length/format/budget: ' + method)
        return True, None
    memory.result_constant = int(source.array_length != 0)
    if not source.array_length:
        return True, None
    items = list(dest.list_items)
    wildcard = source.array_elements.get(None)
    for index in range(source.array_length):
        candidates = [value for value in (source.array_elements.get(index), wildcard) if value]
        value = next((v for v in candidates if v.external), next(iter(candidates), None))
        items.append(value.step(method, ins.offset, 'Collections.addAll array index %d -> %d' % (index, len(items)),
                                value is wildcard) if value else None)
    memory.update(rr[0], list_items=tuple(items))
    return True, None


def _copy(ins, memory, previous, method, diagnostic):
    rr = ins.registers
    dest = previous.object(rr[0]) if rr else None
    source = previous.object(rr[1]) if len(rr) == 2 else None
    known = dest is not None and dest.type == ARRAYLIST
    if (not known or dest.list_items is None or source is None or source.type != ARRAYLIST
            or source.list_items is None or not len(source.list_items) <= len(dest.list_items) <= MAX_LIST_ITEMS
            or ins.opcode not in ('invoke-static', 'invoke-static/range')):
        if known:
            memory.update(rr[0], list_items=None)
        diagnostic('Unresolved Collections.copy lists/size/format/budget: ' + method)
        return True, None
    if not source.list_items or previous.refs[rr[0]] == previous.refs[rr[1]]:
        return True, None
    copied = tuple(value.step(method, ins.offset, 'Collections.copy index ' + str(index)) if value else None
                   for index, value in enumerate(source.list_items))
    memory.update(rr[0], list_items=copied + dest.list_items[len(copied):])
    return True, None


def _fill(ins, old, memory, previous, method, diagnostic):
    rr = ins.registers
    obj = previous.object(rr[0]) if rr else None
    known = obj is not None and obj.type == ARRAYLIST
    if (not known or obj.list_items is None or len(obj.list_items) > MAX_LIST_ITEMS
            or len(rr) != 2 or ins.opcode not in ('invoke-static', 'invoke-static/range')):
        if known:
            memory.update(rr[0], list_items=None)
        diagnostic('Unresolved Collections.fill list/contents/format/budget: ' + method)
        return True, None
    if not obj.list_items:
        return True, None
    if rr[1] in previous.refs:
        memory.update(rr[0], list_items=None)
        diagnostic('Nested Collections.fill object reference unsupported: ' + method)
        return True, None
    value = old.get(rr[1])
    memory.update(rr[0], list_items=tuple(value.step(method, ins.offset, 'Collections.fill index ' + str(index))
                  if value else None for index in range(len(obj.list_items))))
    return True, None


def _rotate(ins, memory, previous, method, diagnostic):
    rr = ins.registers
    obj = previous.object(rr[0]) if rr else None
    known = obj is not None and obj.type == ARRAYLIST
    distance = previous.constants.get(rr[1]) if len(rr) == 2 else None
    if (not known or obj.list_items is None or len(obj.list_items) > MAX_LIST_ITEMS
            or len(rr) != 2 or ins.opcode not in ('invoke-static', 'invoke-static/range')
            or type(distance) is not int or not -2147483648 <= distance <= 2147483647):
        if known:
            memory.update(rr[0], list_items=None)
        diagnostic('Unresolved Collections.rotate list/distance/format/budget: ' + method)
        return True, None
    count = len(obj.list_items)
    shift = distance % count if count else 0
    if shift == 0:
        return True, None
    items = [None] * count
    for source, value in enumerate(obj.list_items):
        destination = (source + shift) % count
        items[destination] = value.step(method, ins.offset, 'Collections.rotate index %d -> %d' % (source, destination)) if value else None
    memory.update(rr[0], list_items=tuple(items))
    return True, None


def _reverse(ins, memory, previous, method, diagnostic):
    rr = ins.registers
    obj = previous.object(rr[0]) if rr else None
    known = obj is not None and obj.type == ARRAYLIST
    if (not known or obj.list_items is None or len(obj.list_items) > MAX_LIST_ITEMS
            or len(rr) != 1 or ins.opcode not in ('invoke-static', 'invoke-static/range')):
        if known:
            memory.update(rr[0], list_items=None)
        diagnostic('Unresolved Collections.reverse list/contents/format/budget: ' + method)
        return True, None
    count = len(obj.list_items)
    if count < 2:
        return True, None
    items = tuple(value.step(method, ins.offset, 'Collections.reverse index %d -> %d' % (count - 1 - index, index))
                  if value and index != count - 1 - index else value
                  for index, value in enumerate(reversed(obj.list_items)))
    memory.update(rr[0], list_items=items)
    return True, None


def _swap(ins, memory, previous, method, diagnostic):
    rr = ins.registers
    obj = previous.object(rr[0]) if rr else None
    known = obj is not None and obj.type == ARRAYLIST
    indices = [previous.constants.get(reg) for reg in rr[1:]]
    valid = (known and obj.list_items is not None and len(obj.list_items) <= MAX_LIST_ITEMS
             and len(rr) == 3 and ins.opcode in ('invoke-static', 'invoke-static/range')
             and all(type(index) is int and 0 <= index < len(obj.list_items) for index in indices))
    if not valid:
        if known:
            memory.update(rr[0], list_items=None)
        diagnostic('Unresolved Collections.swap list/indices/format/budget: ' + method)
        return True, None
    first, second = indices
    if first == second:
        return True, None
    items = list(obj.list_items)
    for source, destination in ((first, second), (second, first)):
        value = obj.list_items[source]
        items[destination] = value.step(method, ins.offset, 'Collections.swap index %d -> %d' % (source, destination)) if value else None
    memory.update(rr[0], list_items=tuple(items))
    return True, None


def _initialize(ins, member, memory, previous, method, diagnostic):
    items = None
    if member == CAPACITY_INIT:
        capacity = previous.constants.get(ins.registers[1])
        if type(capacity) is int and 0 <= capacity <= 2147483647:
            items = ()  # Capacity reserves storage; it is not the logical size.
    else:
        source = previous.object(ins.registers[1])
        if (source is not None and source.type == ARRAYLIST and source.list_items is not None
                and len(source.list_items) <= MAX_LIST_ITEMS
                and previous.refs[ins.registers[0]] != previous.refs[ins.registers[1]]):
            items = tuple(value.step(method, ins.offset, 'ArrayList constructor copy index ' + str(index)) if value else None
                          for index, value in enumerate(source.list_items))
    memory.update(ins.registers[0], list_items=items)
    if items is None:
        diagnostic('Unresolved ArrayList constructor capacity/source/budget: ' + method)
    return True, None


def _add_all(ins, obj, memory, previous, method, diagnostic):
    indexed = ins.target.endswith('->' + ADD_ALL_INDEXED)
    source = previous.object(ins.registers[-1])
    index = previous.constants.get(ins.registers[1]) if indexed else len(obj.list_items or ())
    valid = (obj.list_items is not None and source is not None and source.type == ARRAYLIST
             and source.list_items is not None and type(index) is int and 0 <= index <= len(obj.list_items)
             and previous.refs[ins.registers[0]] != previous.refs[ins.registers[-1]]
             and len(obj.list_items) + len(source.list_items) <= MAX_LIST_ITEMS)
    if not valid:
        memory.update(ins.registers[0], list_items=None)
        diagnostic('Unresolved ArrayList addAll source/index/self-copy/budget: ' + method)
        return True, None
    copied = tuple(value.step(method, ins.offset, 'ArrayList addAll index %d -> %d' % (n, index + n)) if value else None
                   for n, value in enumerate(source.list_items))
    tail = tuple(value.step(method, ins.offset, 'ArrayList addAll shift %d -> %d' % (n, n + len(copied)))
                 if value and copied else value for n, value in enumerate(obj.list_items[index:], index))
    memory.update(ins.registers[0], list_items=obj.list_items[:index] + copied + tail)
    memory.result_constant = int(bool(copied))
    return True, None


def _invalidate_array_argument(ins, memory, previous):
    destination = previous.object(ins.registers[1]) if len(ins.registers) > 1 else None
    if destination is not None and destination.type.startswith('['):
        memory.objects[previous.refs[ins.registers[1]]] = ObjectValue(destination.type)


def _to_array_argument(ins, obj, memory, previous, method, diagnostic):
    from analyzer.core.arrayflow import MAX_ARRAY_LENGTH, MAX_ARRAY_OBJECTS
    destination = previous.object(ins.registers[1])
    valid = (obj.list_items is not None and destination is not None
             and destination.type == '[Ljava/lang/Object;'
             and type(destination.array_length) is int
             and 0 <= destination.array_length <= MAX_ARRAY_LENGTH
             and len(obj.list_items) <= MAX_ARRAY_LENGTH)
    allocate = valid and destination.array_length < len(obj.list_items)
    if not valid or (allocate and sum(v.type.startswith('[') for v in memory.objects.values()) >= MAX_ARRAY_OBJECTS):
        diagnostic('Unresolved ArrayList toArray argument type/contents/length/budget: ' + method)
        # A failed model must not leave stale destination slots usable as evidence.
        _invalidate_array_argument(ins, memory, previous)
        return True, None
    count = len(obj.list_items)
    slots = {index: value.step(method, ins.offset, 'ArrayList toArray argument index ' + str(index)) if value else None
             for index, value in enumerate(obj.list_items)}
    if allocate:
        memory.sequence += 1
        identity = ('allocation', memory.sequence)
        length = count
    else:
        identity = previous.refs[ins.registers[1]]
        length = destination.array_length
        if count < length:
            slots[count] = None
        # Retain only the untouched tail, including unresolved old writes there.
        for index in range(count + 1, length):
            candidates = [destination.array_elements.get(index), destination.array_elements.get(None)]
            candidates = [value for value in candidates if value]
            value = next((v for v in candidates if v.external), next(iter(candidates), None))
            slots[index] = value.step(method, ins.offset, 'ArrayList toArray preserved tail ' + str(index),
                                      value is destination.array_elements.get(None)) if value else None
    memory.objects[identity] = ObjectValue('[Ljava/lang/Object;', array_length=length, array_elements=slots)
    memory.result_ref = identity
    return True, None


def list_call(ins, old, memory, previous, method, diagnostic):
    if ins.target == ADD_ALL_ARRAY:
        return _add_all_array(ins, memory, previous, method, diagnostic)
    if ins.target == COPY:
        return _copy(ins, memory, previous, method, diagnostic)
    if ins.target == FILL:
        return _fill(ins, old, memory, previous, method, diagnostic)
    if ins.target == ROTATE:
        return _rotate(ins, memory, previous, method, diagnostic)
    if ins.target == REVERSE:
        return _reverse(ins, memory, previous, method, diagnostic)
    if ins.target == SWAP:
        return _swap(ins, memory, previous, method, diagnostic)
    from analyzer.core.iteratorflow import ITERATOR, ITERABLE, CREATE, iterator_call, create_iterator
    owner, separator, member = ins.target.partition('->')
    if separator and owner == ITERATOR:
        return iterator_call(ins, memory, previous, method, diagnostic)
    if not separator or owner not in (ARRAYLIST, LIST, COLLECTION, ITERABLE):
        return False, None
    rr = ins.registers
    obj = previous.object(rr[0]) if rr else None
    if obj is None or obj.type != ARRAYLIST:
        if member == TO_ARRAY_ARGUMENT:
            _invalidate_array_argument(ins, memory, previous)
        diagnostic('Unresolved ArrayList receiver: ' + method)
        return True, None
    arity = {'<init>()V': 1, CAPACITY_INIT: 2, COLLECTION_INIT: 2, 'clear()V': 1, 'add(Ljava/lang/Object;)Z': 2,
             'get(I)Ljava/lang/Object;': 2, 'set(ILjava/lang/Object;)Ljava/lang/Object;': 3,
             'add(ILjava/lang/Object;)V': 3, 'remove(I)Ljava/lang/Object;': 2,
             'toArray()[Ljava/lang/Object;': 1, TO_ARRAY_ARGUMENT: 2, ADD_ALL: 2, ADD_ALL_INDEXED: 3,
             'clone()Ljava/lang/Object;': 1, 'size()I': 1, 'isEmpty()Z': 1, CREATE: 1}
    allowed = set(arity)
    if owner != ARRAYLIST:
        allowed.difference_update(('<init>()V', CAPACITY_INIT, COLLECTION_INIT, 'clone()Ljava/lang/Object;'))
    if owner == COLLECTION:
        allowed &= {'clear()V', 'add(Ljava/lang/Object;)Z', 'toArray()[Ljava/lang/Object;', TO_ARRAY_ARGUMENT, ADD_ALL, 'size()I', 'isEmpty()Z', CREATE}
    if owner == ITERABLE:
        allowed &= {CREATE}
    expected = ('invoke-interface' if owner != ARRAYLIST else
                'invoke-direct' if member.startswith('<init>(') else 'invoke-virtual')
    if (member not in allowed or len(rr) != arity[member]
            or ins.opcode not in (expected, expected + '/range')):
        if member == TO_ARRAY_ARGUMENT:
            _invalidate_array_argument(ins, memory, previous)
        memory.update(rr[0], list_items=None)
        diagnostic('Unsupported ArrayList operation: ' + ins.target)
        return True, None
    if member in ('<init>()V', 'clear()V'):
        memory.update(rr[0], list_items=())
        return True, None
    if member in (CAPACITY_INIT, COLLECTION_INIT):
        return _initialize(ins, member, memory, previous, method, diagnostic)
    if member == TO_ARRAY_ARGUMENT:
        return _to_array_argument(ins, obj, memory, previous, method, diagnostic)
    if member in (ADD_ALL, ADD_ALL_INDEXED):
        return _add_all(ins, obj, memory, previous, method, diagnostic)
    if obj.list_items is None:
        diagnostic('Unresolved ArrayList contents: ' + method)
        return True, None
    if member == CREATE:
        return create_iterator(ins, obj, memory, previous, method, diagnostic)
    if member in ('size()I', 'isEmpty()Z'):
        memory.result_constant = len(obj.list_items) if member == 'size()I' else int(not obj.list_items)
        return True, None
    if member == 'clone()Ljava/lang/Object;':
        if (len(obj.list_items) > MAX_LIST_ITEMS
                or sum(v.type == ARRAYLIST for v in memory.objects.values()) >= MAX_LIST_OBJECTS):
            diagnostic('ArrayList clone budget exceeded: ' + method)
            return True, None
        memory.sequence += 1
        identity = ('allocation', memory.sequence)
        copied = tuple(value.step(method, ins.offset, 'ArrayList clone index ' + str(index)) if value else None
                       for index, value in enumerate(obj.list_items))
        memory.objects[identity] = ObjectValue(ARRAYLIST, list_items=copied)
        memory.result_ref = identity
        return True, None
    if member == 'toArray()[Ljava/lang/Object;':
        from analyzer.core.arrayflow import MAX_ARRAY_LENGTH, MAX_ARRAY_OBJECTS
        if (len(obj.list_items) > MAX_ARRAY_LENGTH
                or sum(v.type.startswith('[') for v in memory.objects.values()) >= MAX_ARRAY_OBJECTS):
            diagnostic('ArrayList toArray array budget exceeded: ' + method)
            return True, None
        memory.sequence += 1
        identity = ('allocation', memory.sequence)
        slots = {index: value.step(method, ins.offset, 'ArrayList toArray index ' + str(index)) if value else None
                 for index, value in enumerate(obj.list_items)}
        memory.objects[identity] = ObjectValue('[Ljava/lang/Object;', array_length=len(obj.list_items), array_elements=slots)
        memory.result_ref = identity
        return True, None
    items = list(obj.list_items)
    append = member == 'add(Ljava/lang/Object;)Z'
    insert = member == 'add(ILjava/lang/Object;)V'
    remove = member == 'remove(I)Ljava/lang/Object;'
    if append or insert:
        if len(items) >= MAX_LIST_ITEMS:
            memory.update(rr[0], list_items=None)
            diagnostic('ArrayList item budget exceeded: ' + method)
            return True, None
    if append:
        value_register = rr[1]
    else:
        index = previous.constants.get(rr[1])
        upper = len(items) + (1 if insert else 0)
        if type(index) is not int or not 0 <= index < upper:
            diagnostic('Unresolved/out-of-range ArrayList index: ' + method)
            if member.startswith('set(') or insert or remove:
                memory.update(rr[0], list_items=None)
            return True, None
        value = items[index] if not insert else None
        if member.startswith('get('):
            return True, value.step(method, ins.offset, 'ArrayList get index ' + str(index)) if value else None
        if remove:
            del items[index]
            for position in range(index, len(items)):
                if items[position]:
                    items[position] = items[position].step(method, ins.offset,
                        'ArrayList remove shift ' + str(position + 1) + ' -> ' + str(position))
            memory.update(rr[0], list_items=tuple(items))
            return True, value.step(method, ins.offset, 'ArrayList remove index ' + str(index)) if value else None
        value_register = rr[2]
    if value_register in previous.refs:
        diagnostic('Nested ArrayList object reference unsupported: ' + method)
    trace = old.get(value_register)
    stored = trace.step(method, ins.offset, 'ArrayList ' + ('add' if member.startswith('add(') else 'set')) if trace else None
    if append:
        items.append(stored)
        memory.result_constant = 1
        result = None
    elif insert:
        items.insert(index, stored)
        for position in range(index + 1, len(items)):
            if items[position]:
                items[position] = items[position].step(method, ins.offset,
                    'ArrayList insert shift ' + str(position - 1) + ' -> ' + str(position))
        result = None
    else:
        items[index] = stored
        result = value.step(method, ins.offset, 'ArrayList set previous value') if value else None
    memory.update(rr[0], list_items=tuple(items))
    return True, result
