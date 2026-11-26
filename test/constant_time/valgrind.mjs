// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Runs the program under Valgrind's memcheck and passes with its exit status: 99 when
// memcheck found a use of an undefined value, which a branch on a secret or an index by one is.
// With --expect-leak, it passes only when memcheck found one: a planted leak's build; with
// --in <function> besides, only when a report's first frame is in that function, the planted
// one. Crypto's driver, copied, without its suppressions: secure links no C library whose own
// branches on a verdict need one. Valgrind is told not to translate across a call
// (--vex-guest-chase=no): on arm64, a check of an index in a leaf function the caller's
// translation ran into was reported at the call, in the caller's frame (measured with
// Valgrind 3.22 on Linux arm64, 2026-11-25: planted_lookup's load reported in run_planted), and
// every report must name the function that ran the instruction.
import {spawnSync} from 'node:child_process'

const program = process.argv[process.argv.length - 1]
const expectLeak = process.argv.includes('--expect-leak')
const inAt = process.argv.indexOf('--in')
const plantedIn = inAt === -1 ? undefined : process.argv[inAt + 1]
const run = spawnSync('valgrind', ['--error-exitcode=99', '--track-origins=yes', '--quiet',
    '--vex-guest-chase=no', program],
    {stdio: ['inherit', 'inherit', plantedIn === undefined ? 'inherit' : 'pipe'], encoding: 'utf8'})
if (run.error) {
    console.error(`valgrind could not run: ${run.error.message}; install valgrind (Linux)`)
    process.exit(1)
}
if (plantedIn !== undefined) {
    process.stderr.write(run.stderr ?? '')
}
if (expectLeak) {
    // memcheck's report: the error's line, then its frames, the first "at", the next "by".
    const named = plantedIn === undefined ||
        new RegExp(`^==\\d+==\\s+at 0x[0-9A-F]+: .*\\b${plantedIn}\\b`, 'm').test(run.stderr ?? '')
    process.exit(run.status === 99 && named ? 0 : 1)
}
process.exit(run.status ?? 1)
