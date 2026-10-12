"""Exact HashMap instances, bounded known string keys; no general Java heap."""
from analyzer.core.objectflow import HASHMAP, ObjectValue

MAP = 'Ljava/util/Map;'
MAX_MAP_ITEMS = 64
MAX_MAP_OBJECTS = 128
PUT = 'put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;'
GET = 'get(Ljava/lang/Object;)Ljava/lang/Object;'
REMOVE = 'remove(Ljava/lang/Object;)Ljava/lang/Object;'
REPLACE = 'replace(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;'
GET_DEFAULT = 'getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;'
CONTAINS_KEY = 'containsKey(Ljava/lang/Object;)Z'
PUT_ALL = 'putAll(Ljava/util/Map;)V'
COPY_INIT = '<init>(Ljava/util/Map;)V'
CAPACITY_INIT = '<init>(I)V'
CLONE = 'clone()Ljava/lang/Object;'


def _copy_map(ins, obj, memory, previous, method, diagnostic):
    constructing = ins.target.endswith('->' + COPY_INIT)
    source = previous.object(ins.registers[1])
    base = {} if constructing else obj.map_items
    valid = (base is not None and source is not None and source.type == HASHMAP and source.map_items is not None
             and previous.refs[ins.registers[0]] != previous.refs[ins.registers[1]])
    if valid:
        valid = len(set(base) | set(source.map_items)) <= MAX_MAP_ITEMS
    if not valid:
        memory.update(ins.registers[0], map_items=None)
        diagnostic('Unresolved HashMap copy source/contents/self-copy/budget: ' + method)
        return True, None
    copied = dict(base)
    label = 'HashMap constructor copy' if constructing else 'HashMap putAll'
    copied.update({key: value.step(method, ins.offset, label) if value else None
                   for key, value in source.map_items.items()})
    memory.update(ins.registers[0], map_items=copied)
    return True, None


def map_call(ins, old, memory, previous, method, diagnostic):
    owner, separator, member = ins.target.partition('->')
    if not separator or owner not in (HASHMAP, MAP):
        return False, None
    rr = ins.registers
    obj = previous.object(rr[0]) if rr else None
    if obj is None or obj.type != HASHMAP:
        diagnostic('Unresolved HashMap receiver: ' + method)
        return True, None
    arity = {'<init>()V': 1, 'clear()V': 1, PUT: 3, GET: 2, REMOVE: 2,
             GET_DEFAULT: 3, CONTAINS_KEY: 2, 'size()I': 1, 'isEmpty()Z': 1, PUT_ALL: 2, COPY_INIT: 2,
             CAPACITY_INIT: 2, CLONE: 1, REPLACE: 3}
    expected = 'invoke-interface' if owner == MAP else 'invoke-direct' if member.startswith('<init>(') else 'invoke-virtual'
    if (member not in arity or len(rr) != arity[member] or (owner == MAP and (member.startswith('<init>(') or member == CLONE))
            or ins.opcode not in (expected, expected + '/range')):
        memory.update(rr[0], map_items=None)
        diagnostic('Unsupported HashMap operation: ' + ins.target)
        return True, None
    if member in ('<init>()V', 'clear()V'):
        memory.update(rr[0], map_items={})
        return True, None
    if member == CAPACITY_INIT:
        capacity = previous.constants.get(rr[1])
        valid = type(capacity) is int and 0 <= capacity <= 2147483647
        memory.update(rr[0], map_items={} if valid else None)
        if not valid:
            diagnostic('Unresolved/invalid HashMap capacity: ' + method)
        return True, None
    if member in (PUT_ALL, COPY_INIT):
        return _copy_map(ins, obj, memory, previous, method, diagnostic)
    if obj.map_items is None:
        diagnostic('Unresolved HashMap contents: ' + method)
        return True, None
    if member == CLONE:
        if (len(obj.map_items) > MAX_MAP_ITEMS
                or sum(value.type == HASHMAP for value in memory.objects.values()) >= MAX_MAP_OBJECTS):
            diagnostic('HashMap clone budget exceeded: ' + method)
            return True, None
        memory.sequence += 1
        identity = ('allocation', memory.sequence)
        items = {key: value.step(method, ins.offset, 'HashMap clone') if value else None
                 for key, value in obj.map_items.items()}
        memory.objects[identity] = ObjectValue(HASHMAP, map_items=items)
        memory.result_ref = identity
        return True, None
    if member in ('size()I', 'isEmpty()Z'):
        memory.result_constant = len(obj.map_items) if member == 'size()I' else int(not obj.map_items)
        return True, None
    key = previous.constants.get(rr[1])
    if not isinstance(key, str):
        if member in (PUT, REMOVE, REPLACE):
            memory.update(rr[0], map_items=None)
        diagnostic('Unresolved/non-string HashMap key: ' + method)
        return True, None
    if member == CONTAINS_KEY:
        memory.result_constant = int(key in obj.map_items)
        return True, None
    if member == GET_DEFAULT:
        present = key in obj.map_items
        if not present and rr[2] in previous.refs:
            diagnostic('Nested HashMap default object reference unsupported: ' + method)
        value = obj.map_items[key] if present else old.get(rr[2])
        return True, value.step(method, ins.offset, 'HashMap getOrDefault ' + ('mapped' if present else 'default')) if value else None
    if member == REPLACE and key not in obj.map_items:
        return True, None
    value = obj.map_items.get(key)
    label = 'HashMap get' if member == GET else 'HashMap previous value'
    if member == REPLACE:
        label = 'HashMap replace previous value'
    if member != GET:
        items = dict(obj.map_items)
        if member == REMOVE:
            items.pop(key, None)
            label = 'HashMap remove'
        else:
            if key not in items and len(items) >= MAX_MAP_ITEMS:
                memory.update(rr[0], map_items=None)
                diagnostic('HashMap entry budget exceeded: ' + method)
                return True, None
            if rr[2] in previous.refs:
                diagnostic('Nested HashMap object reference unsupported: ' + method)
            trace = old.get(rr[2])
            operation = 'HashMap replace' if member == REPLACE else 'HashMap put'
            items[key] = trace.step(method, ins.offset, operation) if trace else None
        memory.update(rr[0], map_items=items)
    return True, value.step(method, ins.offset, label) if value else None
