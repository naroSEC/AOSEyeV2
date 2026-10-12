"""Bounded ArrayList iterators with own removal; not a fail-fast or loop proof."""
from dataclasses import replace
from analyzer.core.objectflow import ARRAYLIST, ObjectValue

ITERATOR = 'Ljava/util/Iterator;'
ITERABLE = 'Ljava/lang/Iterable;'
CREATE = 'iterator()Ljava/util/Iterator;'
MAX_ITERATORS = 128


def create_iterator(ins, obj, memory, previous, method, diagnostic):
    if sum(value.type == ITERATOR for value in memory.objects.values()) >= MAX_ITERATORS:
        diagnostic('ArrayList iterator budget exceeded: ' + method)
        return True, None
    memory.sequence += 1
    identity = ('allocation', memory.sequence)
    memory.objects[identity] = ObjectValue(ITERATOR, iterator_ref=previous.refs[ins.registers[0]],
                                          iterator_snapshot=obj, iterator_index=0)
    memory.result_ref = identity
    return True, None


def iterator_call(ins, memory, previous, method, diagnostic):
    rr = ins.registers
    obj = previous.object(rr[0]) if rr else None
    member = ins.target.partition('->')[2]
    if obj is None or obj.type != ITERATOR:
        diagnostic('Unresolved iterator receiver: ' + method)
        return True, None
    source = previous.objects.get(obj.iterator_ref)
    if (member not in ('hasNext()Z', 'next()Ljava/lang/Object;', 'remove()V') or len(rr) != 1
            or ins.opcode not in ('invoke-interface', 'invoke-interface/range')):
        if source is not None:
            memory.objects[obj.iterator_ref] = ObjectValue(source.type)
        memory.update(rr[0], iterator_index=None)
        diagnostic('Unsupported iterator operation: ' + ins.target)
        return True, None
    if (source is None or source.type != ARRAYLIST or source.list_items is None
            or source is not obj.iterator_snapshot or type(obj.iterator_index) is not int):
        memory.update(rr[0], iterator_index=None)
        diagnostic('Unresolved or changed iterator source: ' + method)
        return True, None
    index = obj.iterator_index
    if member == 'remove()V':
        last = obj.iterator_last
        if type(last) is not int or last != index - 1 or not 0 <= last < len(source.list_items):
            memory.update(rr[0], iterator_index=None, iterator_last=None)
            diagnostic('Invalid iterator remove state: ' + method)
            return True, None
        items = source.list_items[:last] + tuple(
            value.step(method, ins.offset, 'ArrayList iterator remove shift %d -> %d' % (n, n - 1)) if value else None
            for n, value in enumerate(source.list_items[last + 1:], last + 1))
        updated = replace(source, list_items=items)
        memory.objects[obj.iterator_ref] = updated
        memory.update(rr[0], iterator_snapshot=updated, iterator_index=last, iterator_last=None)
        return True, None
    if member == 'hasNext()Z':
        memory.result_constant = int(index < len(source.list_items))
        return True, None
    if not 0 <= index < len(source.list_items):
        diagnostic('Exhausted iterator next: ' + method)
        return True, None
    memory.update(rr[0], iterator_index=index + 1, iterator_last=index)
    value = source.list_items[index]
    return True, value.step(method, ins.offset, 'ArrayList iterator next index ' + str(index)) if value else None
