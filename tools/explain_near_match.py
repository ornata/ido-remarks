#!/usr/bin/env python3
"""Read-only assembly mismatch and transparent IDO allocation evidence report."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import subprocess

from classify_asm_diff import classify

TIMING = re.compile(r'SECONDS IN (.*?) OF (\w+)\s*$')
IDENTITY = r'\{\s*(\d+)\|(\d+)\}'
VARIABLE = re.compile(IDENTITY + r'\s+\d+ isvar\s+([A-Z])\s+(-?\d+)\s+(-?\d+)(?:vreg)?\s*$')
ACTIVE = re.compile(r'>>>active<<<' + IDENTITY + r'\s+(\d+)\s+(-?\d+)\s*$')
SAVING = re.compile(r'adjsave, hasstore:\s*([-+\d.eE]+)\s+(true|false)\s*$')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def allocations(text, function):
    """Scope by timing boundaries; retain raw compiler IDs, never C-variable names."""
    lines = text.splitlines()
    events = [(i, m[1], m[2]) for i, line in enumerate(lines) if (m := TIMING.search(line))]
    starts = [i for i, phase, name in events if phase == 'LOCAL OPTIMIZATION' and name == function]
    ends = [i for i, phase, name in events if phase == 'REEMISSION' and name == function]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise ValueError('Missing or ambiguous procedure timing boundaries')
    start, end = starts[0], ends[0]
    if any(name != function for i, _, name in events if start <= i <= end):
        raise ValueError('Interleaved procedure timings: cannot scope allocations')
    variables = {}
    rows = []
    for i in range(start + 1, end):
        line = lines[i]
        m = VARIABLE.fullmatch(line)
        if m:
            key = (m[1], m[2])
            value = {'storage_class': m[3], 'block': int(m[4]), 'offset': int(m[5])}
            if key in variables and variables[key] != value:
                raise ValueError('Conflicting compiler variable identity')
            variables[key] = value
        m = ACTIVE.fullmatch(line)
        if m:
            rows.append({'expression_id': f'{m[1]}|{m[2]}', 'range_bit': int(m[3]),
                         'internal_register': int(m[4]), 'line': i + 1, 'evidence': line})
        elif '>>>active<<<' in line:
            raise ValueError('Unsupported allocation row at line ' + str(i + 1))
        m = SAVING.fullmatch(line)
        if m and rows:
            if 'adjusted_saving' in rows[-1]:
                raise ValueError('Ambiguous allocation saving')
            rows[-1].update(adjusted_saving=float(m[1]), has_store=m[2] == 'true')
    if not rows:
        raise ValueError('No supported allocation records inside procedure')
    for row in rows:
        key = tuple(row['expression_id'].split('|'))
        row['recorded_variable'] = variables.get(key)
    return {'scope_lines': [start + 1, end + 1], 'ranges': rows,
            'caveat': 'M/P offsets are compiler identities, not machine sp homes. Split ranges may share identities; internal register numbers are not MIPS register numbers.'}


def explain(diff, directory, function):
    report = json.loads((directory / 'report.json').read_text())
    if report.get('function') != function:
        raise ValueError('Diagnostic report function differs from requested function')
    if (report.get('status') != 'transparent' or report.get('text_equal') is not True
            or report.get('disassembly_and_relocations_equal') is not True):
        raise ValueError('Diagnostic report is not transparent')
    if sha(directory / 'candidate.c') != report.get('candidate_sha256'):
        raise ValueError('Saved candidate hash differs from diagnostic report')
    if sha(diff) != report.get('compile_log_sha256'):
        raise ValueError('Diff log is not the diagnostic compile-log input; refuse to combine candidates')
    for suffix in ('text', 'dis'):
        if (directory / ('ordinary.' + suffix)).read_bytes() != (directory / ('diagnostic.' + suffix)).read_bytes():
            raise ValueError('Ordinary/diagnostic ' + suffix + ' artifacts differ')
    categories = classify(diff.read_text())
    if categories['status'] in ('malformed', 'compile_failure'):
        raise ValueError('Diff classification failed: ' + categories['status'])
    listing = (directory / 'uopt.txt').read_bytes()
    listing_hash = hashlib.sha256(listing).hexdigest()
    if 'uopt_sha256' in report:
        if report['uopt_sha256'] != listing_hash:
            raise ValueError('Uopt listing hash differs from diagnostic report')
        listing_association = 'hash_verified_against_report'
        listing_limit = 'Uopt listing bytes match the producer report hash; this is consistency checking, not independent authentication of that report.'
    else:
        listing_association = 'legacy_unauthenticated'
        listing_limit = 'Legacy diagnostic report does not hash uopt.txt; listing provenance is unauthenticated and relies on the supplied evidence directory.'
    parsed = allocations(listing.decode(), function)
    connections = []
    if categories['counts']['stack_frame']:
        connections.append('Visible-table stack/frame mismatch evidence exists. Inspect recorded M/P identities and assembly accesses separately; no offset-to-home mapping is inferred.')
    if categories['counts']['register_only']:
        connections.append('Visible-table register-only rows exist. Candidate allocation ranges are available below; target allocation costs and C-variable identities are unknown.')
    if categories['counts']['scheduling_order']:
        connections.append('Visible instruction-multiset evidence suggests order changes. Allocation records alone cannot identify the responsible compiler phase.')
    if categories['counts']['opcode_control_flow'] or categories['counts']['insert_delete']:
        connections.append('Visible-table opcode/control or insertion/deletion evidence exists; review actual control/data flow before treating this as allocation-only.')
    return {'function': function, 'status': categories['status'],
            'target_function_scope': 'uopt_only',
            'assembly_scope': 'visible_table_not_function_filtered',
            'provenance': {'diff': str(diff), 'diagnostics': str(directory),
                           'candidate_sha256': report['candidate_sha256'],
                           'uopt_sha256': listing_hash,
                           'uopt_association': listing_association,
                           'transparency': 'saved whole-text and normalized disassembly artifacts independently compared'},
            'assembly': categories, 'candidate_allocations': parsed, 'connections': connections,
            'limits': ['Assembly classification covers the visible table, possibly neighboring functions or truncated output.',
                       'No mapping of target registers, stack accesses, compiler identities, or original C locals is inferred.',
                       'Saved evidence consistency is checked; no compilation, semantic-equivalence proof, or ROM acceptance is performed.',
                       listing_limit]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('diff', type=Path)
    parser.add_argument('diagnostics', type=Path)
    parser.add_argument('function')
    parser.add_argument('--compare-diagnostics', type=Path, help='Second saved diagnostic directory')
    parser.add_argument('--compare-diff', type=Path, help='Compile log used by the second diagnostic')
    args = parser.parse_args()
    if bool(args.compare_diagnostics) != bool(args.compare_diff):
        parser.error('--compare-diagnostics and --compare-diff must be supplied together')
    try:
        if args.compare_diagnostics:
            from paired_near_match import paired
            result = paired(args.diff, args.diagnostics, args.compare_diff,
                            args.compare_diagnostics, args.function)
        else:
            result = explain(args.diff, args.diagnostics, args.function)
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(json.dumps({'status': 'error', 'error': str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
