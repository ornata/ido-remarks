"""Paired saved evidence support for explain_near_match; no identity inference."""
from collections import Counter
from difflib import SequenceMatcher
import json
from pathlib import Path
import re
import tempfile
import subprocess

from object_scope import inspect
from dataflow.ido import parse_uopt


def saved_side(diff, directory, function):
    from explain_near_match import explain, sha
    report = json.loads((directory / 'report.json').read_text())
    required = {'ordinary.obj', 'ordinary.text', 'ordinary.dis', 'diagnostic.text',
                'diagnostic.dis', 'candidate.c', 'uopt.txt'}
    artifacts = report.get('artifacts', {})
    if not required <= artifacts.keys() or not report.get('uopt_sha256'):
        raise ValueError('Paired evidence requires hashed object, text, disassembly and optimizer artifacts')
    for name, digest in artifacts.items():
        if Path(name).name != name or sha(directory / name) != digest:
            raise ValueError('Diagnostic artifact hash mismatch: ' + name)
    single = explain(diff, directory, function)
    # Bind the object used for scoped extraction to authenticated saved assembly.
    dis = subprocess.check_output(['mips-linux-gnu-objdump', '-dr',
                                   str(directory / 'ordinary.obj')], text=True)
    normalized = '\n'.join(line for line in dis.splitlines() if 'file format' not in line)
    if normalized != (directory / 'ordinary.dis').read_text():
        raise ValueError('Saved ordinary object differs from authenticated disassembly')
    with tempfile.TemporaryDirectory(prefix='paired-near-match-') as tmp:
        listing = Path(tmp) / 'function.dis'
        scope = inspect(directory / 'ordinary.obj', function, 2**31, listing)
        rows = instruction_rows(listing.read_text(), scope)
    scope.pop('disassembly')
    optimizer = parse_uopt((directory / 'uopt.txt').read_text(), function)
    return {'provenance': single['provenance'], 'scope': scope,
            'instructions': rows, 'stack_accesses': stack_accesses(rows),
            'optimizer': optimizer}


def instruction_rows(text, scope):
    rows = []
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)', line)
        if m:
            rows.append({'offset': int(m[1], 16) - scope['start'],
                         'word': m[2], 'assembly': m[3], 'relocations': []})
            continue
        m = re.match(r'^\s*([0-9a-f]+):\s+(R_MIPS_\w+)\s+(.*)', line)
        if m:
            if not rows or int(m[1], 16) != scope['start'] + rows[-1]['offset']:
                raise ValueError('Unassociated relocation inside function disassembly')
            rows[-1]['relocations'].append([m[2], m[3]])
    if [r['offset'] for r in rows] != list(range(0, scope['size'], 4)):
        raise ValueError('Incomplete function instruction scope')
    return rows


def stack_accesses(rows):
    """Direct raw SP accesses only; never claim recovered C homes or lifetime."""
    return [r for r in rows if re.search(r'\(sp\)|,sp,', r['assembly'])]


def compare_rows(left, right):
    # Include relocation symbol/type, even when unrelocated words are equal.
    def key(row):
        return row['word'], tuple(tuple(r) for r in row['relocations'])
    matcher = SequenceMatcher(None, list(map(key, left)), list(map(key, right)), autojunk=False)
    return [{'kind': kind, 'left': left[a:b], 'right': right[c:d]}
            for kind, a, b, c, d in matcher.get_opcodes() if kind != 'equal']


def range_signatures(side):
    # These are observed record multisets, NOT matched ranges across builds.
    return Counter(json.dumps({'record': r.get('expression_record', {}).get('description')
                               if r.get('expression_record') else None,
                               'internal_color': r['internal_color'],
                               'adjusted_savings': r.get('adjusted_savings')}, sort_keys=True)
                   for r in side['optimizer']['ranges'])


def paired(left_diff, left_dir, right_diff, right_dir, function):
    left = saved_side(left_diff, left_dir, function)
    right = saved_side(right_diff, right_dir, function)
    a, b = range_signatures(left), range_signatures(right)
    def unpack(counts):
        return [{'signature': json.loads(k), 'count': v} for k, v in sorted(counts.items())]
    return {'schema': 1, 'function': function, 'status': 'complete_saved_comparison',
            'left': left, 'right': right,
            'instruction_changes': compare_rows(left['instructions'], right['instructions']),
            'optimizer_record_multiset_changes': {'left_only': unpack(a-b), 'right_only': unpack(b-a)},
            'limits': ['Candidate-to-candidate only; no original compiler allocation evidence.',
                       'Instruction alignment is a word/relocation sequence heuristic, not semantic correspondence.',
                       'Raw SP offsets are not inferred C-variable homes; no alias or lifetime proof.',
                       'Compiler expression IDs, offsets and range numbers are local to each build; multiset changes do not pair identities.',
                       'Internal colors are not architectural register numbers. Read raw block/interference evidence independently.',
                       'Artifact hashes authenticate consistency with supplied producer reports, not external trust; no compilation or ROM acceptance.']}
