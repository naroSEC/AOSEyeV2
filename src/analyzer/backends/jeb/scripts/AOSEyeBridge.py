# Jython 2.7 bridge; all commercial API types are confined to this file.
import codecs
import json
import re
import zipfile
from ExportBudget import ExportBudget
from PhaseTrace import PhaseTrace
from IndexPriority import select_global
from com.pnfsoftware.jeb.core.input import BytesInput
from java.util import Base64
from java.util import ArrayList
from java.lang import Exception as JavaException
from java.lang import String
from java.lang.invoke import MethodHandles
from java.util import Arrays
from java.util.stream import IntStream
from com.pnfsoftware.jeb.core.units.code.android import IDexUnit, IApkUnit
from com.pnfsoftware.jeb.core.units import IXmlUnit
from com.pnfsoftware.jeb.core.output.text import TextDocumentUtil
from com.pnfsoftware.jeb.core.units.code.android.dex import IDalvikInstruction as DI
from com.pnfsoftware.jeb.core.units.code.android.dex import DexPoolType
from com.pnfsoftware.jeb.core.units.code.java import IJavaCall, IJavaIdentifier, IJavaConstant


def java_text(value):
    if value is None:
        return None
    try:
        return unicode(value)
    except ValueError:
        # Jython rejects lone UTF-16 surrogates, which DEX strings can contain.
        # Carry numeric code points without replacing evidence characters.
        return {'__aoseye_utf16_codepoints__': list(value.codePoints().toArray())}


def java_text_call(owner, name, *args):
    try:
        return java_text(getattr(owner, name)(*args))
    except ValueError:
        # Java String returns may be auto-converted before Python sees them.
        # Compose the fallback entirely in Java, returning int[] across Jython.
        lookup = MethodHandles.publicLookup()
        for method in owner.getClass().getMethods():
            params = method.getParameterTypes()
            if (method.getName() == name and method.getReturnType() == String
                    and len(params) == len(args)
                    and all(p.isInstance(a) for p, a in zip(params, args))):
                points = lookup.unreflect(String.getMethod('codePoints', []))
                array = lookup.unreflect(IntStream.getMethod('toArray', []))
                convert = MethodHandles.filterReturnValue(points, array)
                call = MethodHandles.filterReturnValue(lookup.unreflect(method), convert)
                values = call.invokeWithArguments(Arrays.asList([owner] + list(args)))
                return {'__aoseye_utf16_codepoints__': list(values)}
        raise


class AOSEyeBridge(object):
    def execute(self, ctx, request):
        operation = request['operation']
        trace = PhaseTrace(request['output'] + '.phases.jsonl') if operation == 'index' else None
        if trace:
            trace.mark('artifact_open_start')
        if operation == 'probe':
            return dict(ok=True)
        if operation not in ('index', 'method', 'method_candidate', 'xref', 'decompile', 'ast', 'resources', 'network_resource'):
            raise ValueError('Unknown bridge operation: ' + operation)
        ctx.open(request['input'], request['input_sha256'])
        if trace:
            trace.mark('artifact_open_done')
        if operation == 'resources':
            return self.resources(ctx, request)
        if operation == 'network_resource':
            return self.network_resource(ctx, request)
        units = list(ctx.project.findUnits(IDexUnit))
        for dex in units:
            if not dex.isProcessed() and not dex.process():
                raise RuntimeError('DEX processing failed: ' + str(dex.getName()))
        if units:
            ctx.capabilities['dex'] = 'verified'
        if operation == 'index':
            trace.mark('dex_processing_done', dex_units=len(units))
            records = request['output'] + '.methods.jsonl'
            with codecs.open(records, 'w', 'utf-8') as stream:
                program = self.index(ctx, units, request, stream, trace)
            trace.mark('index_done', methods=len(program['method_index']), classes=len(program['class_index']),
                       fields=len(program['field_index']))
            return dict(ok=True, program=program, method_records=records)
        if operation == 'xref':
            xrefs = []
            total = 0
            offset, limit = request.get('offset', 0), request.get('limit', 300)
            for n, dex in enumerate(units):
                element = dex.getMethod(request['element'])
                pool = DexPoolType.METHOD
                if element is None:
                    element, pool = dex.getField(request['element']), DexPoolType.FIELD
                if element is None:
                    continue
                for ref in dex.getCrossReferences(pool, element.getIndex()):
                    if offset <= total < offset + limit:
                        xrefs.append(dict(unit=self.unit_id(n, dex), address=str(ref.getInternalAddress()),
                                          reference_type=str(ref.getReferenceType()),
                                          evidence_origin='JEB getCrossReferences'))
                    total += 1
            ctx.capabilities['xrefs'] = 'verified'
            return dict(ok=True, xrefs=xrefs, total=total)
        matches = []
        for n, dex in enumerate(units):
            if operation != 'method_candidate' and request.get('unit') and request['unit'] != self.unit_id(n, dex):
                continue
            method = dex.getMethod(request['method'])
            if method and method.getData():
                matches.append((n, dex, method))
        if len(matches) != 1:
            raise ValueError('Method missing or ambiguous across DEX units: ' + request['method'])
        n, dex, method = matches[0]
        if operation == 'method_candidate':
            limit = request.get('max_candidate_bytes')
            if type(limit) is not int or not 1 <= limit <= 1048576:
                raise ValueError('Candidate byte limit must be 1..1048576')
            unit = self.unit_id(n, dex)
            if not request.get('unit') or request['unit'] != unit:
                raise ValueError('Candidate unit mismatch or unknown')
            if method.getData().getCodeItem() is None:
                raise ValueError('Candidate has no code')
            result = self.method(dex, method)
            result['unit'] = unit
            budget = ExportBudget(limit)
            record = budget.record(result)
            if record is None:
                return dict(ok=True, status='BUDGET_EXCEEDED', byte_limit=limit)
            return dict(ok=True, status='CANDIDATE', method=result, encoded_bytes=budget.used, byte_limit=limit)
        if operation == 'method':
            result = self.method(dex, method)
            result['unit'] = self.unit_id(n, dex)
            ctx.capabilities['cfg'] = 'verified'
            return dict(ok=True, method=result)
        dec = dex.getDecompiler()
        if dec is None or not dec.decompileMethod(request['method']):
            raise RuntimeError('Decompiler unavailable or method decompilation failed')
        source = java_text_call(dec, 'getDecompiledMethodText', request['method'])
        if source is None:
            raise RuntimeError('Decompiler returned no method text')
        ctx.capabilities['decompiler'] = 'verified'
        if operation == 'decompile':
            return dict(ok=True, source=source)
        unit = dec.decompileToUnit(request['method'])
        if unit is None:
            raise RuntimeError('Decompiler returned no Java source unit')
        element = unit.getASTElement()
        if element is None:
            raise RuntimeError('Java source unit has no AST element')
        # Method source units may expose a surrounding class. Ask for the method
        # AST explicitly so unrelated class methods cannot leak into this result.
        method_ast = dec.getMethod(request['method'], False)
        if method_ast is None:
            raise RuntimeError('Java method AST unavailable')
        ast = self.ast(method_ast, request.get('max_nodes', 5000))
        ast.update(method=request['method'], unit=self.unit_id(n, dex),
                   source_unit_element_type=str(element.getElementType()))
        ctx.capabilities['ast'] = 'verified'
        return dict(ok=True, source=source, ast=ast)

    def resources(self, ctx, request):
        apk = ctx.project.findUnit(IApkUnit)
        if apk is None:
            raise ValueError('No APK unit')
        info = apk.getResourcesInfo()
        resource_type = request.get('resource_type', 'xml')
        if resource_type not in ('xml', 'raw'):
            raise ValueError('Unsupported resource inventory type')
        rows = []
        if info is not None:
            for package in info.getPackages():
                for entry in info.getResourcesByType(package.getId(), resource_type, ''):
                    if len(rows) >= 4096:
                        raise ValueError('Resource inventory budget exceeded')
                    value = entry.getValue() if entry.isSimple() else None
                    rows.append(dict(id=entry.getResourceId(), type=value.getType() if value else None,
                        path=java_text(info.getString(value.getData())) if value and value.getType() == 3 else None))
        manifest = java_text(apk.getManifest().getDocumentAsText()) if apk.getManifest() else ''
        return dict(ok=True, resources=rows, manifest=manifest, configuration='default')

    def network_resource(self, ctx, request):
        apk = ctx.project.findUnit(IApkUnit)
        reference = request['reference']
        resource_id = None
        numeric = re.match(r'^@(?:0x)?([0-9a-fA-F]{8})$', reference)
        named = re.match(r'^@xml/([a-zA-Z0-9_]+)$', reference)
        if apk is None:
            raise ValueError('No APK unit')
        if numeric:
            resource_id = int(numeric.group(1), 16)
            rows = self.resources(ctx, request)['resources']
            matches = [r for r in rows if (r['id'] & 0xffffffff) == resource_id and r['type'] == 3]
            if len(matches) != 1 or not isinstance(matches[0]['path'], basestring):
                raise ValueError('XML resource ID missing, aliased or ambiguous in default configuration')
            path = matches[0]['path']
        elif named:
            path = 'res/xml/' + named.group(1) + '.xml'
        else:
            raise ValueError('Unsupported XML resource reference')
        if not path.startswith('res/') or '..' in path.split('/') or not path.endswith('.xml'):
            raise ValueError('Invalid resource path')
        with zipfile.ZipFile(request['input']) as archive:
            entries = archive.infolist()
            if len(entries) > 100000:
                raise ValueError('ZIP entry budget exceeded')
            matches = [e for e in entries if e.filename == path]
            if len(matches) != 1:
                raise ValueError('Resource path missing or duplicated')
            if named and any(e.filename.startswith('res/xml-') and e.filename.endswith('/' + named.group(1) + '.xml') for e in entries):
                raise ValueError('Configuration-qualified named XML resource')
            entry = matches[0]
            if entry.file_size > 1048576 or entry.file_size / max(1, entry.compress_size) > 1000:
                raise ValueError('XML read budget exceeded')
            with archive.open(entry) as stream:
                data = stream.read(1048577)
            if len(data) > 1048576:
                raise ValueError('XML read budget exceeded')
        import base64
        raw = Base64.getDecoder().decode(base64.b64encode(data))
        processor = ctx.project.getProcessor()
        unit = processor.process('AOSEye resource XML', BytesInput(raw), apk, None, True)
        try:
            if unit is None:
                raise ValueError('Resource decoder did not return a unit')
            queue, xml_units, visited = [unit] if unit else [], [], 0
            while queue:
                current = queue.pop()
                visited += 1
                if visited > 32:
                    raise ValueError('Decoded XML unit budget exceeded')
                if isinstance(current, IXmlUnit):
                    xml_units.append(current)
                queue.extend(current.getChildren())
            if len(xml_units) > 1:
                raise ValueError('Resource decoder returned ambiguous XML units')
            if not xml_units:
                doc = unit.getFormatter().getPresentation(0).getDocument()
                try:
                    text = TextDocumentUtil.getText(doc)
                finally:
                    doc.dispose()
            else:
                text = xml_units[0].getDocumentAsText()
            if len(text) > 1048576:
                raise ValueError('Decoded XML budget exceeded')
            return dict(ok=True, xml=java_text(text), resource=path, resource_id=resource_id,
                        configuration='default-only', origin='JEB resource table / XML decoder')
        finally:
            if unit is not None:
                ctx.project.destroyUnit(unit)

    def unit_id(self, n, dex):
        return str(n) + ':' + str(dex.getName())

    def index(self, ctx, units, request, stream, trace=None):
        program = dict(methods={}, method_index=[], class_index=[], field_index=[], dex_units=[], classes=[], fields=[],
                       class_hierarchy={}, class_interfaces={}, manifest='', diagnostics=[], capabilities={})
        apk = ctx.project.findUnit(IApkUnit)
        if apk and apk.getManifest():
            doc = apk.getManifest().getFormatter().getPresentation(0).getDocument()
            try:
                program['manifest'] = java_text(TextDocumentUtil.getText(doc))
            finally:
                doc.dispose()
        budget_hit = False
        byte_budget = ExportBudget(request.get('max_export_bytes', 64 * 1024 * 1024))
        index_budget = ExportBudget(request.get('max_index_bytes', 8 * 1024 * 1024))
        # Prevent large class/field inventories from starving all method bodies.
        # Both kinds share half the declaration allowance; unused bytes remain
        # available to methods. The overall encoded-byte cap is unchanged.
        metadata_budget = ExportBudget(max(1, index_budget.limit // 2))
        def index_metadata(value):
            if metadata_budget.record(value) is None:
                return None
            return index_budget.record(value)
        ctx.capabilities['declaration_budget'] = 'class/field metadata capped at half; remaining declaration bytes available to methods'
        index_limit = request.get('max_index_entries', 20000)
        if isinstance(index_limit, bool) or not isinstance(index_limit, int) or index_limit < 1:
            raise ValueError('Invalid declaration index count budget')
        omitted = dict(classes=0, fields=0, methods=0)
        exported = set()
        order = request.get('index_order', 'native')
        if order not in ('native', 'manifest-first'):
            raise ValueError('Invalid index order')
        ctx.capabilities['index_order'] = ('native' if order == 'native' else
            'manifest-first (global across JEB units; not ownership/entrypoint proof)')
        for n, dex in enumerate(units):
            unit_id = self.unit_id(n, dex)
            program['dex_units'].append(dict(id=unit_id, name=str(dex.getName()),
                dex_entries=dex.getCountOfDexEntries(), classes=len(dex.getClasses()),
                methods=len(dex.getMethods()), fields=len(dex.getFields())))
        def batches():
            if order == 'native':
                for n, dex in enumerate(units):
                    yield n, dex.getClasses(), dex.getFields(), dex.getMethods()
                return
            # Select and consume one kind at a time: O(limit) retained candidates.
            # Preserve rank order during byte accounting, not just count selection.
            for slot, kind, getter in ((0, 'classes', 'getClasses'),
                                      (1, 'fields', 'getFields'), (2, 'methods', 'getMethods')):
                total = sum(row[kind] for row in program['dex_units'])
                if index_budget.exhausted or (slot != 2 and metadata_budget.exhausted):
                    omitted[kind] += total
                    continue
                if trace:
                    trace.mark('global_selection_start', kind=kind)
                selected = select_global((getattr(dex, getter)() for dex in units), index_limit,
                    request.get('priority_classes', []), request.get('priority_package', ''))
                omitted[kind] += total - len(selected)
                if trace:
                    trace.mark('global_selection_done', kind=kind, selected=len(selected))
                for n, item in selected:
                    rows = [(), (), ()]
                    rows[slot] = (item,)
                    yield n, rows[0], rows[1], rows[2]
                del selected
        for n, classes, fields, methods in batches():
            dex = units[n]
            unit_id = self.unit_id(n, dex)
            if trace and order == 'native':
                trace.mark('dex_metadata_start', dex=n)
            for position, cls in enumerate(classes):
                if len(program['class_index']) >= index_limit or index_budget.exhausted or metadata_budget.exhausted:
                    omitted['classes'] += len(classes) - position
                    break
                signature = str(cls.getSignature(False))
                parent = cls.getSupertypeSignature(False)
                row = dict(signature=signature, unit=unit_id)
                hierarchy = {signature: str(parent)} if parent else {}
                interfaces = {signature: [str(value) for value in cls.getInterfaceSignatures(False)]}
                if index_metadata(dict(class_index=row, classes=signature, class_hierarchy=hierarchy,
                                       class_interfaces=interfaces)) is None:
                    omitted['classes'] += len(classes) - position
                    break
                program['classes'].append(signature)
                program['class_index'].append(row)
                program['class_interfaces'].update(interfaces)
                if parent:
                    program['class_hierarchy'].update(hierarchy)
            for position, field in enumerate(fields):
                if len(program['field_index']) >= index_limit or index_budget.exhausted or metadata_budget.exhausted:
                    omitted['fields'] += len(fields) - position
                    break
                signature = str(field.getSignature(False))
                row = dict(signature=signature, unit=unit_id)
                if index_metadata(dict(field_index=row, fields=signature)) is None:
                    omitted['fields'] += len(fields) - position
                    break
                program['fields'].append(signature)
                program['field_index'].append(row)
            if trace and order == 'native':
                trace.mark('class_field_metadata_done', dex=n, classes=len(program['class_index']), fields=len(program['field_index']))
            for position, method in enumerate(methods):
                if len(program['method_index']) >= index_limit or index_budget.exhausted:
                    omitted['methods'] += len(methods) - position
                    break
                sig = str(method.getSignature(False))
                data = method.getData()
                defined = data is not None and data.getCodeItem() is not None
                row = dict(signature=sig, unit=unit_id, has_code=defined, declared=data is not None)
                if index_budget.record(dict(method_index=row)) is None:
                    omitted['methods'] += len(methods) - position
                    break
                program['method_index'].append(row)
                if trace and len(program['method_index']) % 10000 == 0:
                    trace.mark('method_index_progress', dex=n, declarations=len(program['method_index']),
                               exported=len(exported), export_bytes=byte_budget.used)
                if not defined:
                    continue
                if byte_budget.exhausted:
                    byte_budget.skipped += 1
                    continue
                if len(exported) >= request.get('max_methods', 100000):
                    budget_hit = True
                    continue
                try:
                    normalized = self.method(dex, method)
                    normalized['unit'] = unit_id
                    if sig in exported:
                        program['diagnostics'].append('Duplicate method signature: ' + sig)
                    else:
                        record = byte_budget.record(normalized)
                        if record is None and trace:
                            trace.mark('body_byte_limit', dex=n, declarations=len(program['method_index']),
                                       exported=len(exported), export_bytes=byte_budget.used)
                        if record is not None:
                            stream.write(record)
                            exported.add(sig)
                except (Exception, JavaException) as exc:
                    program['diagnostics'].append('Method export failed: ' + sig + ': ' + str(exc))
        if budget_hit:
            program['diagnostics'].append('Method body indexing budget exhausted; declaration index has separate limits')
        if byte_budget.exhausted:
            program['diagnostics'].append('Method export byte budget exhausted; used=%s limit=%s skipped_bodies=%s; '
                'declaration index has separate limits; exported bodies retained; partial analysis'
                % (byte_budget.used, byte_budget.limit, byte_budget.skipped))
        if any(omitted.values()):
            program['diagnostics'].append('Declaration index budget exhausted; per_kind_limit=%s encoded_bytes=%s byte_limit=%s '
                'omitted_classes=%s omitted_fields=%s omitted_methods=%s; hierarchy and references may be incomplete; partial analysis'
                % (index_limit, index_budget.used, index_budget.limit, omitted['classes'], omitted['fields'], omitted['methods']))
            if trace:
                trace.mark('declaration_index_limit', classes=len(program['class_index']), fields=len(program['field_index']),
                           methods=len(program['method_index']), omitted_classes=omitted['classes'],
                           omitted_fields=omitted['fields'], omitted_methods=omitted['methods'])
        if not units:
            program['diagnostics'].append('No DEX unit found')
        if exported:
            ctx.capabilities['cfg'] = 'verified'
        program['capabilities'] = dict(ctx.capabilities)
        return program

    def ast(self, root, max_nodes):
        # Flat DTO tree avoids Python/JSON recursion limits on large Java methods.
        nodes = []
        stack = [(root, None, 0)]
        while stack and len(nodes) < max_nodes:
            element, parent, depth = stack.pop()
            offset = int(element.getPhysicalOffset()) if element.hasPhysicalOffset() else -1
            node = dict(id=len(nodes), parent=parent, kind=str(element.getElementType()),
                        offset=offset if offset >= 0 else None)
            if isinstance(element, IJavaCall):
                node['target'] = str(element.getMethodSignature())
                node['argument_count'] = element.getArgumentCount()
            elif isinstance(element, IJavaIdentifier):
                node['name'] = str(element.getName())
            elif isinstance(element, IJavaConstant) and element.isString():
                node['value'] = java_text_call(element, 'getString')
            nodes.append(node)
            children = list(element.getSubElements())
            if depth >= 128:
                if children:
                    return dict(nodes=nodes, truncated=True, reason='AST depth budget reached')
            else:
                for child in reversed(children):
                    stack.append((child, node['id'], depth + 1))
        return dict(nodes=nodes, truncated=bool(stack), reason='AST node budget reached' if stack else '')

    def method(self, dex, method):
        code = method.getData().getCodeItem()
        instructions = []
        diagnostics = []
        exception_status = 'UNKNOWN'
        exception_regions = []
        try:
            exception_items = code.getExceptionItems()
            if exception_items is None:
                raise ValueError('Exception table API returned null')
            exception_status = 'PRESENT' if exception_items else 'NONE'
            for region in exception_items:
                handlers = []
                for handler in region.getHandlers():
                    type_index = int(handler.getTypeIndex())
                    handlers.append(dict(address=int(handler.getAddress()), type_index=type_index,
                        type=str(dex.getType(type_index).getSignature()) if type_index >= 0 else '*'))
                exception_regions.append(dict(start=int(region.getTryAddress()),
                    end=int(region.getTryAddress()) + int(region.getTrySize()), handlers=handlers))
        except (Exception, JavaException):
            exception_status = 'UNKNOWN'
            exception_regions = []
            diagnostics.append('Exception table unavailable')
        for ins in code.getInstructions():
            regs = []
            target = ''
            literal = None
            for p in ins.getParameters():
                typ, val = p.getType(), int(p.getValue())
                if typ == DI.TYPE_REG:
                    regs.append(val)
                elif typ == DI.TYPE_RGR:
                    # Documented JEB encoding: low int=first, high int=last inclusive.
                    first, last = val & 0xFFFFFFFF, (val >> 32) & 0xFFFFFFFF
                    if last < first or last - first > 65535:
                        raise ValueError('Invalid JEB register range')
                    regs.extend(range(first, last + 1))
                elif typ == DI.TYPE_IDX:
                    kind = ins.getParameterFirstIndexType()
                    if kind == DI.INDEX_TO_METHOD:
                        target = str(dex.getMethod(val).getSignature(False))
                    elif kind == DI.INDEX_TO_FIELD:
                        target = str(dex.getField(val).getSignature(False))
                    elif kind == DI.INDEX_TO_STRING:
                        literal = java_text_call(dex.getString(val), 'getValue')
                    elif kind == DI.INDEX_TO_TYPE:
                        literal = str(dex.getType(val).getSignature())
                elif typ == DI.TYPE_IMM:
                    literal = val
            defs, uses = ArrayList(), ArrayList()
            try:
                ins.getDefUse(defs, uses)
            except (Exception, JavaException):
                diagnostics.append('Def/use unavailable at ' + str(ins.getOffset()))
            instructions.append(dict(offset=int(ins.getOffset()), opcode=str(ins.getMnemonic()),
                                     registers=regs, defs=[int(v) for v in defs],
                                     uses=[int(v) for v in uses], target=target, literal=literal,
                                     text=java_text_call(ins, 'format', dex), successors=[]))
        by_offset = dict((i['offset'], i) for i in instructions)
        blocks = []
        for block in code.getControlFlowGraph().getBlocks():
            offsets = [int(i.getOffset()) for i in block.getInstructions()]
            successors = [int(b.getFirstAddress()) for b in block.getAllOutputBlocks()]
            normal_successors = [int(b.getFirstAddress()) for b in block.getOutputBlocks()]
            for n, off in enumerate(offsets):
                by_offset[off]['successors'] = [offsets[n + 1]] if n + 1 < len(offsets) else successors
                by_offset[off]['normal_successors'] = [offsets[n + 1]] if n + 1 < len(offsets) else normal_successors
            blocks.append(dict(start=int(block.getFirstAddress()), offsets=offsets, successors=successors))
        return dict(signature=str(method.getSignature(False)), class_name=str(method.getClassTypeSignature(False)),
                    parameter_registers=list(range(code.getRegisterCount() - code.getInputArgumentCount(),
                                                   code.getRegisterCount())),
                    instructions=instructions, cfg=blocks, source='', unit=str(dex.getName()),
                    diagnostics=diagnostics, exception_status=exception_status, exception_regions=exception_regions)
