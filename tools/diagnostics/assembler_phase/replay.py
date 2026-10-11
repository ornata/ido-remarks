"""Authenticated diagnostic replay of retained IDO assembly; never production input."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from .report import digest, make_report, retained_function


def relocation_scope(disassembly, start, size):
    rows = []
    for line in disassembly.splitlines():
        match = re.match(r'\s*([0-9a-f]+):\s+(R_MIPS_\S+)\s+(.+)', line)
        if match and start <= int(match[1], 16) < start + size:
            rows.append((int(match[1], 16), match[2], match[3]))
    return rows


def validate_edit(original, edited, function):
    """Allow changes only inside the selected retained .ent/.end pair."""
    before = original.splitlines(keepends=True)
    after = edited.splitlines(keepends=True)
    a = retained_function(original, function)
    b = retained_function(edited, function)
    if before[:a[0]['line']] != after[:b[0]['line']]:
        raise ValueError('Edited input changes text before/including target .ent')
    if before[a[-1]['line'] - 1:] != after[b[-1]['line'] - 1:]:
        raise ValueError('Edited input changes text after/including target .end')


def validate_flags(flags):
    if set(flags) != {'as0', 'as1'}:
        raise ValueError('Flags JSON must contain exactly as0 and as1 arrays')
    for stage, values in flags.items():
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise ValueError('Stage flags must be string arrays')
        if any(v in {'-o', '-t', '-noglobal'} for v in values):
            raise ValueError('Output/symbol paths and -noglobal are not permitted in stage flags')


def run(args):
    out = args.output.resolve()
    root = Path(__file__).resolve().parents[3]
    if out == root or root in out.parents:
        raise ValueError('Replay evidence must be outside the repository')
    out.mkdir(parents=True, exist_ok=False)
    flags = json.loads(args.flags.read_text())
    validate_flags(flags)
    phase = json.loads(args.phase.read_text())
    function = phase['function']
    if phase['status'] != 'transparent':
        raise ValueError('An authenticated assembler-phase report is required')
    assembly = Path(phase['artifacts']['assembly']['path'])
    if digest(assembly) != phase['artifacts']['assembly']['sha256']:
        raise ValueError('Retained assembly hash differs from phase evidence')
    for key in ['ordinary', 'kept']:
        artifact = phase['artifacts'][key]
        if digest(Path(artifact['path'])) != artifact['sha256']:
            raise ValueError('Compiled phase object hash differs: ' + key)
    authenticated = make_report(Path(phase['artifacts']['ordinary']['path']),
                                Path(phase['artifacts']['kept']['path']), assembly, function)
    for key in ['scope', 'final', 'complete_final_disassembly']:
        if authenticated[key] != phase[key]:
            raise ValueError('Supplied phase evidence no longer reproduces: ' + key)
    # These must be the same capture, not independently chosen binary intermediates.
    binary = assembly.with_suffix('.G')
    symbols = assembly.with_suffix('.T')
    inputs = {'assembly': assembly, 'binary': binary, 'symbols': symbols,
              'phase': args.phase, 'flags': args.flags}
    artifacts = {k: {'path': str(p.resolve()), 'sha256': digest(p)} for k, p in inputs.items()}
    compiler = args.compiler.resolve()
    artifacts.update({s: {'path': str(compiler / s), 'sha256': digest(compiler / s)}
                      for s in ['as0', 'as1']})
    commands = []
    report = {'status': 'incomplete', 'function': function, 'inputs': artifacts,
              'commands': commands,
              'limits': 'Diagnostic only. Raw assembler output precedes asm-processor patches. '
                        'Capture provenance is the supplied authenticated phase report and sibling G/T files. '
                        'No original C, pseudo-instruction identity, or production acceptance is inferred.'}

    def execute(command):
        command = list(map(str, command))
        p = subprocess.run(command, capture_output=True, text=True)
        commands.append({'argv': command, 'returncode': p.returncode,
                         'stdout': p.stdout, 'stderr': p.stderr})
        if p.returncode:
            raise ValueError('Assembler stage failed; see report commands')

    def assemble_text(path, prefix):
        execute([compiler / 'as0', *flags['as0'], path,
                 '-o', out / (prefix + '.G'), '-t', out / (prefix + '.T')])
        execute([compiler / 'as1', *flags['as1'], out / (prefix + '.G'),
                 '-o', out / (prefix + '.o'), '-t', out / (prefix + '.T')])

    try:
        execute([compiler / 'as1', *flags['as1'], binary,
                 '-o', out / 'raw.o', '-t', symbols])
        assemble_text(assembly, 'baseline')
        base = make_report(out / 'raw.o', out / 'baseline.o', assembly, function)
        if base['scope'] != phase['scope'] or [r['word'] for r in base['final']] != [r['word'] for r in phase['final']]:
            raise ValueError('Raw replay target scope differs from authenticated compiled target')
        start, size = base['scope']['start'], base['scope']['size']
        if relocation_scope(base['complete_final_disassembly'], start, size) != relocation_scope(phase['complete_final_disassembly'], start, size):
            raise ValueError('Raw replay target relocations differ from authenticated compiled target')
        report['baseline'] = base
        report['status'] = 'calibrated'
        if args.edited:
            edited = args.edited.read_text()
            validate_edit(assembly.read_text(), edited, function)
            # Preserve the exact supplied file; do not synthesize instructions or directives.
            frozen = out / 'edited.s'
            frozen.write_bytes(args.edited.read_bytes())
            assemble_text(frozen, 'edited')
            # Same-object report enforces positive complete symbol scope, not equivalence.
            changed = make_report(out / 'edited.o', out / 'edited.o', frozen, function)
            report['experiment'] = {'input': {'path': str(args.edited.resolve()), 'sha256': digest(frozen)},
                                    'scope': changed['scope'], 'final': changed['final'],
                                    'complete_final_disassembly': changed['complete_final_disassembly'],
                                    'object_sha256': digest(out / 'edited.o'),
                                    'interpretation': 'One supplied target-local text edit after calibrated baseline. '
                                                      'Edited output is not asserted equivalent or byte matching.'}
            if changed['scope'] == base['scope']:
                report['experiment']['changed_words'] = [
                    {'address': a['address'], 'baseline': a['word'], 'edited': b['word']}
                    for a, b in zip(base['final'], changed['final']) if a['word'] != b['word']]
            else:
                report['experiment']['changed_words'] = None
            report['status'] = 'experiment'
        return report
    except Exception as error:
        report['status'] = 'failed'
        report['error'] = str(error)
        raise
    finally:
        (out / 'replay.json').write_text(json.dumps(report, indent=2) + '\n')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--phase', required=True, type=Path, help='Authenticated assembler-phase.json')
    p.add_argument('--compiler', required=True, type=Path, help='Directory containing measured as0/as1')
    p.add_argument('--flags', required=True, type=Path, help='Exact stage flags JSON from captured driver invocation')
    p.add_argument('--output', required=True, type=Path, help='New evidence directory')
    p.add_argument('--edited', type=Path, help='Optional supplied assembly with edits only inside target')
    args = p.parse_args()
    try:
        report = run(args)
    except (ValueError, KeyError, OSError) as error:
        p.exit(1, str(error) + '\n')
    print(json.dumps({'status': report['status'], 'function': report['function'],
                      'scope': report['baseline']['scope'], 'output': str(args.output)}))


if __name__ == '__main__':
    main()
