#!/usr/bin/env python3
"""Compare selected ordered operand trees in IDO ugen Build dumps."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
from pathlib import Path


class TraceError(ValueError):
    pass


def parse(text):
    sections = []
    active = None
    for line_no, line in enumerate(text.splitlines(), 1):
        if line.startswith('Tree dump after '):
            active = {} if line.strip() == 'Tree dump after Build' else None
            if active is not None:
                sections.append(active)
            continue
        if active is None or not line.strip():
            continue
        match = re.fullmatch(r'\s*(\d+)\s+(\w+)\s*(.*)', line)
        if not match:
            raise TraceError(f'Unrecognized Build line {line_no}: {line}')
        ident, op, rest = match.groups()
        rest = rest.replace('Not visited', '').strip()
        pairs = re.findall(r'(\w+)=([^\s]+)', rest)
        residue = re.sub(r'\w+=[^\s]+', '', rest).strip()
        if residue or len(dict(pairs)) != len(pairs):
            raise TraceError(f'Unsupported/duplicate fields on line {line_no}: {rest}')
        node = {'id': int(ident), 'op': op, 'fields': dict(pairs), 'line': line_no,
                'evidence': line.strip()}
        previous = active.get(node['id'])
        if previous and (previous['op'], previous['fields']) != (op, node['fields']):
            raise TraceError(f'Conflicting node {ident} in Build section {len(sections)}')
        active[node['id']] = node
    if not sections:
        raise TraceError('No Tree dump after Build sections found')
    return sections


def select(sections, selector, section=None):
    try:
        pairs = [part.split('=', 1) for part in selector.split(',')]
        fields = dict(pairs)
    except ValueError:
        raise TraceError('Selector must be key=value pairs, e.g. id=10690')
    if not fields or any(not k or not v for k, v in pairs) or len(fields) != len(pairs):
        raise TraceError('Empty or duplicate selector fields')
    if section is not None and not 1 <= section <= len(sections):
        raise TraceError('Build section index is out of range (one-based)')
    matches = []
    for number, nodes in enumerate(sections, 1):
        if section is not None and section != number:
            continue
        for node in nodes.values():
            values = dict(node['fields'], id=str(node['id']), op=node['op'])
            if all(values.get(k) == v for k, v in fields.items()):
                matches.append((number, nodes, node))
    if len(matches) != 1:
        raise TraceError(f'Selector {selector!r} matched {len(matches)} nodes; require exactly one. '
                         'Use id= and/or a Build section index to disambiguate.')
    return matches[0]


MAX_EXPANDED_NODES = 4096


def tree(nodes, node, ancestors=(), budget=None):
    if budget is None:
        budget = [MAX_EXPANDED_NODES]
    if budget[0] <= 0:
        raise TraceError(f'Expanded operand tree exceeds {MAX_EXPANDED_NODES} nodes')
    budget[0] -= 1
    ident = node['id']
    if ident in ancestors or len(ancestors) >= 200:
        raise TraceError(f'Cyclic or excessively deep operand tree at node {ident}')
    children = {}
    attrs = {}
    for key, value in node['fields'].items():
        if re.fullmatch(r'op\d+', key):
            if key not in ('op1', 'op2'):
                raise TraceError(f'Unsupported operand edge {key}')
            if not value.isdecimal() or int(value) not in nodes:
                raise TraceError(f'Missing/invalid {key} reference {value} at node {ident}')
            children[key] = tree(nodes, nodes[int(value)], ancestors + (ident,), budget)
        elif key not in ('next', 'prior'):
            attrs[key] = value
    return {'op': node['op'], 'attributes': attrs, 'operands': children,
            'node': ident, 'line': node['line'], 'evidence': node['evidence']}


def identity(t):
    return (t['op'], tuple(sorted(t['attributes'].items())),
            tuple((k, identity(v)) for k, v in sorted(t['operands'].items())))


def differences(left, right, path='root'):
    changes = []
    if (left['op'], left['attributes']) != (right['op'], right['attributes']):
        changes.append({'path': path, 'kind': 'operation_or_identity',
                        'left': left['evidence'], 'right': right['evidence']})
    a, b = left['operands'], right['operands']
    if set(a) == set(b) == {'op1', 'op2'} and identity(a['op1']) == identity(b['op2']) and identity(a['op2']) == identity(b['op1']) and identity(a['op1']) != identity(a['op2']):
        changes.append({'path': path, 'kind': 'operand_order_reversed',
                        'left': left['evidence'], 'right': right['evidence']})
        return changes
    for edge in sorted(set(a) | set(b)):
        if edge not in a or edge not in b:
            changes.append({'path': path + '.' + edge, 'kind': 'operand_presence',
                            'left': a.get(edge), 'right': b.get(edge)})
        else:
            changes.extend(differences(a[edge], b[edge], path + '.' + edge))
    return changes


def shared_paths(root):
    paths = {}
    def visit(node, path):
        paths.setdefault(node['node'], []).append(path)
        for edge, child in sorted(node['operands'].items()):
            visit(child, path + '.' + edge)
    visit(root, 'root')
    return sorted(sorted(group) for group in paths.values() if len(group) > 1)


def compare(left_text, right_text, left_selector, right_selector, left_section=None, right_section=None):
    ls, ln, l = select(parse(left_text), left_selector, left_section)
    rs, rn, r = select(parse(right_text), right_selector, right_section)
    lt, rt = tree(ln, l), tree(rn, r)
    changes = differences(lt, rt)
    if shared_paths(lt) != shared_paths(rt):
        changes.append({'path': 'root', 'kind': 'dependency_sharing',
                        'left': shared_paths(lt), 'right': shared_paths(rt)})
    return {'status': 'compared', 'scope': 'selected Build operand trees only',
            'left': {'section': ls, 'tree': lt}, 'right': {'section': rs, 'tree': rt},
            'differences': changes, 'difference_count': len(changes),
            'limitations': ['No semantic equivalence, CFG, alias, or scheduling proof.',
                'next/prior statement links and call argument setup are not followed.',
                'Register offsets/block numbers are preserved, not mapped across compilations.',
                'Constant-pool indices are not resolved to literal values.',
                'Diagnostic transparency must be verified separately against ordinary objects.']}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('left', type=Path)
    p.add_argument('right', type=Path)
    p.add_argument('--left-select', required=True)
    p.add_argument('--right-select', required=True)
    p.add_argument('--left-section', type=int)
    p.add_argument('--right-section', type=int)
    args = p.parse_args()
    try:
        left, right = args.left.read_bytes(), args.right.read_bytes()
        result = compare(left.decode(), right.decode(), args.left_select, args.right_select,
                         args.left_section, args.right_section)
        result['inputs'] = [{'path': str(path), 'sha256': hashlib.sha256(data).hexdigest()}
                            for path, data in ((args.left, left), (args.right, right))]
    except (TraceError, OSError, UnicodeError) as exc:
        print(json.dumps({'status': 'error', 'error': str(exc)}))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
