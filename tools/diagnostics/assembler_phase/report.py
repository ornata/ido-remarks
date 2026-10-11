"""Conservative retained-ugen/final-object view; no instruction equivalence inference."""
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def retained_function(text, function):
    starts = [i for i, line in enumerate(text.splitlines())
              if re.fullmatch(r'\s*\.ent\s+' + re.escape(function) + r'(?:\s+\d+)?\s*', line)]
    if len(starts) != 1:
        raise ValueError('Expected exactly one retained .ent for ' + function)
    lines = text.splitlines()
    start = starts[0]
    for end in range(start + 1, len(lines)):
        if re.fullmatch(r'\s*\.end\s+' + re.escape(function) + r'\s*', lines[end]):
            return [{'line': i + 1, 'text': lines[i]} for i in range(start, end + 1)]
        if re.match(r'\s*\.ent\s+', lines[end]):
            break
    raise ValueError('Missing matching .end for ' + function)


def symbol_scope(table, function):
    matches = []
    for line in table.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[-1] == function and '.text' in fields:
            matches.append((int(fields[0], 16), int(fields[-2], 16)))
    if len(matches) != 1 or matches[0][1] <= 0:
        raise ValueError('Expected one positive-sized .text symbol for ' + function)
    return matches[0]


def final_function(disassembly, start, size):
    result = []
    for number, line in enumerate(disassembly.splitlines(), 1):
        match = re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.+)$', line)
        if match and start <= int(match[1], 16) < start + size:
            result.append({'line': number, 'address': int(match[1], 16),
                           'word': match[2], 'text': match[3]})
    if [r['address'] for r in result] != list(range(start, start + size, 4)):
        raise ValueError('Incomplete final instruction coverage; refusing truncated scope')
    return result


def anchor_order(retained, final, anchors):
    """Each user-specified anchor gives independent regexes, never a guessed mapping."""
    if not isinstance(anchors, list):
        raise ValueError('Anchors must be a list')
    found = []
    names = set()
    for anchor in anchors:
        if set(anchor) != {'name', 'retained', 'final'} or anchor['name'] in names:
            raise ValueError('Each unique anchor needs name, retained and final regexes')
        names.add(anchor['name'])
        entry = {'name': anchor['name'], 'patterns': anchor}
        for key, rows in [('retained', retained), ('final', final)]:
            hits = [r for r in rows if re.search(anchor[key], r['text'])]
            if len(hits) != 1:
                raise ValueError('Anchor %s needs exactly one %s match (got %d)' %
                                 (anchor['name'], key, len(hits)))
            entry[key + '_line'] = hits[0]['line']
        found.append(entry)
    return {'anchors': found,
            'retained_order': [x['name'] for x in sorted(found, key=lambda x: x['retained_line'])],
            'final_order': [x['name'] for x in sorted(found, key=lambda x: x['final_line'])],
            'interpretation': 'Explicit user anchors only; order is not pseudo-instruction equivalence.'}


def make_report(ordinary, kept, assembly, function, anchors=None):
    artifacts = {}
    disassemblies = {}
    textbytes = {}
    for name, obj in [('ordinary', ordinary), ('kept', kept)]:
        # No filename-dependent lines; all sections and relocation records remain.
        raw = subprocess.check_output(['mips-linux-gnu-objdump', '-drz', str(obj)], text=True)
        disassemblies[name] = '\n'.join(x for x in raw.splitlines() if 'file format' not in x)
        with tempfile.TemporaryDirectory(prefix='assembler-phase-') as temp:
            binary = Path(temp) / 'text.bin'
            subprocess.run(['mips-linux-gnu-objcopy', '-O', 'binary', '-j', '.text', str(obj), str(binary)], check=True)
            textbytes[name] = binary.read_bytes()
        artifacts[name] = {'path': str(obj), 'sha256': digest(obj)}
    artifacts['assembly'] = {'path': str(assembly), 'sha256': digest(assembly)}
    equal = textbytes['ordinary'] == textbytes['kept'] and disassemblies['ordinary'] == disassemblies['kept']
    if not equal:
        raise ValueError('Normal versus retained object differs in complete text/disassembly/relocations')
    table = subprocess.check_output(['mips-linux-gnu-objdump', '-t', str(kept)], text=True)
    start, size = symbol_scope(table, function)
    retained = retained_function(assembly.read_text(), function)
    final = final_function(disassemblies['kept'], start, size)
    return {'function': function, 'status': 'transparent', 'artifacts': artifacts,
            'scope': {'start': start, 'size': size, 'instructions': len(final)},
            'retained': retained, 'final': final,
            'complete_final_disassembly': disassemblies['kept'],
            'ordering': anchor_order(retained, final, anchors or []),
            'limits': 'Retained directives and pseudo-instructions are preserved verbatim. No automatic source identities, instruction equivalence, or original compiler input is inferred.'}


def render_markdown(report):
    retained = '\n'.join('%5d  %s' % (r['line'], r['text']) for r in report['retained'])
    final = '\n'.join('%5d  %08x  %s  %s' % (r['line'], r['address'], r['word'], r['text'])
                      for r in report['final'])
    order = report['ordering']
    return ('# Assembler phase: ' + report['function'] + '\n\n'
            'Whole-unit normal versus retained text, disassembly and relocations agree. '
            'Complete function scope: %d instructions / %d bytes.\n\n' %
            (report['scope']['instructions'], report['scope']['size']) +
            'Explicit retained anchor order: ' + repr(order['retained_order']) + '\n\n'
            'Explicit final anchor order: ' + repr(order['final_order']) + '\n\n'
            '## Retained ugen assembly (original file line numbers)\n\n```text\n' + retained + '\n```\n\n'
            '## Final object (complete disassembly line numbers, address, word)\n\n```text\n' + final + '\n```\n\n' +
            report['limits'] + '\n')
