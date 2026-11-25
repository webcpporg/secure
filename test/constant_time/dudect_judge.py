#!/usr/bin/env python3
# Copyright (c) 2026 WebCpp.org
#
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt)

"""The CI's judge of dudect's outputs in secure's constant-time lane: crypto's judge
(libs/crypto/test/constant_time/dudect_judge.py, design D7 of crypto's change api-gaps), copied,
since each library keeps its own test support; tools/test/secure_dudect_judge_test.py runs crypto's
judge's test against this copy. Secure's lane runs natively alone.

Usage: dudect_judge.py --bin DIR --target {native,wasip2} [--rerun] [--launcher COMMAND]

Finds every DIR/**/dudect_*.output, which b2 wrote for a dudect program of the constant-time
lane, prints each in a GitHub log group, and emits a warning annotation for every case whose |t|,
as printed, is 10 or more, with the case's evidence line. dudect_planted, whose high value is its
pass, and dudect_harness, a test of the harness with made-up values, are printed and never
warned about. With --rerun, each judged case whose |t| is 10 or more is measured again in two
fresh processes (the program's `--case <name>`, which on wasip2 runs as `COMMAND <program>.wasm
--case <name>`), and fails when at least two of its three values are 10 or more. A case that is
not judged is warned about and never measured again.

Exit status: 0 when nothing failed, 1 when a case failed or an output holds no case line, 2 on a
usage error."""

from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
from pathlib import Path

THRESHOLD = 10.0
# Longer than the 1800 s that the launcher bounds a wasip2 run by, so that its bound fires first.
RUN_TIMEOUT_SECONDS = 2400
CASE_LINE = re.compile(r'^dudect case=(\S+) t=([0-9.]+) threshold=10 judged=(yes|no)$')
# Printed and never judged: the planted program passes by finding a leak; the harness test's
# values are deterministic and made up, and b2 itself judges them.
NOT_MEASURING = ('dudect_planted', 'dudect_harness')


def annotation(text: str) -> str:
    """text as a workflow command's message: the characters it reserves escaped."""
    return text.replace('%', '%25').replace('\r', '%0D').replace('\n', '%0A')


def case_lines(text: str) -> dict[str, tuple[float, bool, list[str]]]:
    """Each case of an output, in order: its t, whether it is judged, and its lines (its own
    line, then its evidence line when it has one)."""
    cases: dict[str, tuple[float, bool, list[str]]] = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        found = CASE_LINE.match(line)
        if found is None:
            continue
        name = found.group(1)
        shown = [line]
        if index + 1 < len(lines) and lines[index + 1].startswith(f'dudect evidence case={name} '):
            shown.append(lines[index + 1])
        cases[name] = (float(found.group(2)), found.group(3) == 'yes', shown)
    return cases


def measure_again(command: list[str], name: str) -> float:
    """The t of case name that a fresh process of command prints."""
    done = subprocess.run([*command, '--case', name], capture_output=True, text=True,
                          check=False, timeout=RUN_TIMEOUT_SECONDS)
    found = case_lines(done.stdout).get(name)
    if found is None:
        raise RuntimeError(f'{shlex.join(command)} --case {name} (exit {done.returncode}) printed '
                           f'no line for the case:\n{done.stdout}{done.stderr}')
    return found[0]


def program_command(output: Path, target: str, launcher: str) -> list[str]:
    """The command that runs the program that wrote output, up to its arguments."""
    program = output.with_suffix('')
    if target == 'wasip2':
        return [*shlex.split(launcher), str(program.with_suffix('.wasm'))]
    return [str(program)]


def judge(output: Path, target: str, rerun: bool, launcher: str) -> bool:
    """Prints and judges one output; whether it passes."""
    program = output.stem
    text = output.read_text(errors='replace')
    print(f'::group::{program} ({target})')
    print(text, end='' if text.endswith('\n') else '\n')
    print('::endgroup::')
    if program in NOT_MEASURING:
        return True
    cases = case_lines(text)
    if not cases:
        print(f'dudect: {output} holds no case line', file=sys.stderr)
        return False
    passed = True
    for name, (value, judged, shown) in cases.items():
        if not value >= THRESHOLD:
            continue
        title = f'dudect {program} {name} ({target})'.replace(':', '%3A').replace(',', '%2C')
        print(f'::warning title={title}::{annotation(chr(10).join(shown))}')
        if not (rerun and judged):
            continue
        command = program_command(output, target, launcher)
        try:
            values = [value, measure_again(command, name), measure_again(command, name)]
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
            print(f'dudect: {name} ({program}, {target}) could not be measured again: {error}',
                  file=sys.stderr)
            passed = False
            continue
        listed = ', '.join(f'{each:.2f}' for each in values)
        over = sum(1 for each in values if each >= THRESHOLD)
        if over >= 2:
            print(f'dudect: {name} ({program}, {target}) exceeded 10 in {over} of 3 runs: {listed}',
                  file=sys.stderr)
            passed = False
        else:
            print(f'dudect: {name} ({program}, {target}) exceeded 10 in {over} of 3 runs, so it '
                  f'passes: {listed}')
    return passed


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description='The CI\'s judge of dudect\'s outputs.')
    parser.add_argument('--bin', required=True, type=Path, help='the directory b2 built under')
    parser.add_argument('--target', required=True, choices=['native', 'wasip2'])
    parser.add_argument('--rerun', action='store_true',
                        help='measure a judged case over 10 again, in two fresh processes')
    parser.add_argument('--launcher', default='tools/boost/asio-wasip2/run.sh',
                        help='the command that runs a .wasm program (wasip2)')
    arguments = parser.parse_args(argv)
    outputs = sorted(arguments.bin.rglob('dudect_*.output'))
    if not outputs:
        print(f'dudect: no dudect_*.output under {arguments.bin}', file=sys.stderr)
        return 1
    passed = True
    for output in outputs:
        passed = judge(output, arguments.target, arguments.rerun, arguments.launcher) and passed
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
