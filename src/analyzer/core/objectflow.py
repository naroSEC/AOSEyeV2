"""Path-local allocation identities for bounded Intent/Runnable modeling.

Values are replaced, never mutated, so sibling CFG paths cannot share writes.
This is deliberately not a general Java heap or a scheduler simulation.
"""
from dataclasses import dataclass, field, replace
from typing import Any
from analyzer.core.graph import DeclarationResolver

INTENT = 'Landroid/content/Intent;'
ARRAYLIST = 'Ljava/util/ArrayList;'
HASHMAP = 'Ljava/util/HashMap;'
ASYNC_CALLS = {
    'Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z',
    'Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z',
    'Landroid/view/View;->post(Ljava/lang/Runnable;)Z',
    'Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z',
    'Landroid/app/Activity;->runOnUiThread(Ljava/lang/Runnable;)V',
    'Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V',
}
ICC_CALLS = {
    'Landroid/app/Activity;->startActivity(Landroid/content/Intent;)V',
    'Landroid/content/Context;->startActivity(Landroid/content/Intent;)V',
    'Landroid/app/Activity;->startActivity(Landroid/content/Intent;Landroid/os/Bundle;)V',
    'Landroid/content/Context;->startActivity(Landroid/content/Intent;Landroid/os/Bundle;)V',
}
ICC_COMPONENT_KIND = {target: 'activity' for target in ICC_CALLS}
for owner in ('Landroid/content/Context;', 'Landroid/content/ContextWrapper;',
              'Landroid/app/Activity;', 'Landroid/app/Service;'):
    for member, kind in (
        ('startService(Landroid/content/Intent;)Landroid/content/ComponentName;', 'service'),
        ('startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;', 'service'),
        ('sendBroadcast(Landroid/content/Intent;)V', 'receiver'),
        ('sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V', 'receiver')):
        ICC_COMPONENT_KIND[owner + '->' + member] = kind
ICC_CALLS = set(ICC_COMPONENT_KIND)


@dataclass(frozen=True)
class ClassConstant:
    signature: str


@dataclass(frozen=True)
class ObjectValue:
    type: str
    fields: dict = field(default_factory=dict)
    field_refs: dict = field(default_factory=dict)
    extras: dict = field(default_factory=dict)
    target: str | None = None
    target_package: str | None = None
    data: Any = None
    intent_ref: tuple | None = None
    array_length: int | None = None
    array_elements: dict = field(default_factory=dict)
    list_items: tuple | None = None
    iterator_ref: tuple | None = None
    iterator_snapshot: Any = None
    iterator_index: int | None = None
    iterator_last: int | None = None
    map_items: dict | None = None


@dataclass
class Memory:
    refs: dict = field(default_factory=dict)
    constants: dict = field(default_factory=dict)
    objects: dict = field(default_factory=dict)
    result_ref: tuple | None = None
    result_constant: Any = None
    sequence: int = 0

    def copy(self):
        return Memory(dict(self.refs), dict(self.constants), dict(self.objects),
                      self.result_ref, self.result_constant, self.sequence)

    def arguments(self, registers, parameters):
        return Memory({p: self.refs[r] for p, r in zip(parameters, registers) if r in self.refs},
                      {p: self.constants[r] for p, r in zip(parameters, registers) if r in self.constants},
                      dict(self.objects), sequence=self.sequence)

    def kill(self, register):
        self.refs.pop(register, None)
        self.constants.pop(register, None)

    def object(self, register):
        return self.objects.get(self.refs.get(register))

    def update(self, register, **changes):
        identity = self.refs.get(register)
        if identity in self.objects:
            self.objects[identity] = replace(self.objects[identity], **changes)

    def returned(self, callee):
        result = self.copy()
        result.objects = dict(callee.objects)
        result.sequence = callee.sequence
        result.result_ref, result.result_constant = callee.result_ref, callee.result_constant
        return result


def tracked_type(program, descriptor, resolver=None):
    return isinstance(descriptor, str) and (descriptor in (INTENT, ARRAYLIST, HASHMAP) or
        (resolver or DeclarationResolver(program)).target(descriptor + '->run()V') in program.methods)


def intent_call(target, rr, old, regs, memory, previous, sig, offset, diagnostic):
    """Return (handled, return trace) for a known local Intent instance."""
    obj = previous.object(rr[0]) if rr else None
    if not obj or obj.type != INTENT or not target.startswith(INTENT + '->'):
        return False, None
    member = target.split('->', 1)[1]
    identity = previous.refs[rr[0]]
    if member in ('<init>(Landroid/content/Context;Ljava/lang/Class;)V',
                  'setClass(Landroid/content/Context;Ljava/lang/Class;)Landroid/content/Intent;'):
        target_class = previous.constants.get(rr[2]) if len(rr) > 2 else None
        memory.update(rr[0], target=target_class.signature if isinstance(target_class, ClassConstant) else None,
                      target_package=None)
        if member.startswith('setClass'):
            memory.result_ref = identity
        return True, None
    if member == '<init>()V':
        return True, None
    if member == '<init>(Landroid/content/Intent;)V':
        source = previous.object(rr[1]) if len(rr) == 2 else None
        if source and source.type == INTENT:
            # Snapshot values; later mutation of either Intent must not affect its copy.
            memory.objects[identity] = replace(source, extras=dict(source.extras), fields=dict(source.fields),
                                               field_refs=dict(source.field_refs))
        else:
            memory.objects[identity] = ObjectValue(INTENT)
        return True, None
    if member == 'setClassName(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;':
        package = previous.constants.get(rr[1]) if len(rr) == 3 else None
        name = previous.constants.get(rr[2]) if len(rr) == 3 else None
        if isinstance(package, str) and isinstance(name, str) and package and name and not name.startswith('.'):
            # Unlike Manifest/createRelative, ComponentName(String,String) does not expand '.Name'.
            descriptor = 'L' + name.replace('.', '/') + ';' if not any(c in name for c in '/;[\x00\r\n ') else None
        else:
            descriptor = None
        memory.update(rr[0], target=descriptor, target_package=package if descriptor else None)
        memory.result_ref = identity
        return True, None
    if member == 'putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;':
        key = previous.constants.get(rr[1]) if len(rr) > 1 else None
        if isinstance(key, str) and len(rr) > 2:
            extras = dict(obj.extras)
            trace = old.get(rr[2])
            extras[key] = trace.step(sig, offset, 'Intent extra write') if trace else None
            memory.update(rr[0], extras=extras)
        else:
            diagnostic('Unknown Intent extra key: ' + sig)
            memory.update(rr[0], extras={})
        memory.result_ref = identity
        return True, None
    if member == 'getStringExtra(Ljava/lang/String;)Ljava/lang/String;':
        key = previous.constants.get(rr[1]) if len(rr) > 1 else None
        if not isinstance(key, str):
            diagnostic('Unknown Intent extra lookup key: ' + sig)
        trace = obj.extras.get(key) if isinstance(key, str) else None
        return True, trace.step(sig, offset, 'Intent extra read') if trace else None
    if member == 'setData(Landroid/net/Uri;)Landroid/content/Intent;':
        trace = old.get(rr[1]) if len(rr) > 1 else None
        memory.update(rr[0], data=trace.step(sig, offset, 'Intent data write') if trace else None)
        memory.result_ref = identity
        return True, None
    if member in ('getData()Landroid/net/Uri;', 'getDataString()Ljava/lang/String;'):
        return True, obj.data.step(sig, offset, 'Intent data read') if obj.data else None
    # No synthetic external source for a locally allocated Intent's unknown getter.
    diagnostic('Unsupported local Intent operation: ' + target)
    if not member.startswith(('get', 'has', 'resolve', 'to')):
        memory.objects[identity] = ObjectValue(INTENT)
    return True, None
