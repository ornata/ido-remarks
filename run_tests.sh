#!/bin/bash
# Runs every suite. Needs only Python 3.
set -euo pipefail
cd "$(dirname "$0")"
python3 -m unittest discover -s tests
python3 -m unittest discover -s tools -p 'test_*.py'
python3 -m unittest discover -s tools/diagnostics/dataflow -p 'test_*.py'
python3 -m unittest tools.diagnostics.assembler_phase.test_replay tools.diagnostics.assembler_phase.test_report
(cd tools/diagnostics && python3 -m unittest discover -s ugen_compare -p 'test_*.py')
echo "all suites passed"
