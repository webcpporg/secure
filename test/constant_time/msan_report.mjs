// Copyright (c) 2026 WebCpp.org
//
// Distributed under the Boost Software License, Version 1.0. (See
// accompanying file LICENSE_1_0.txt or copy at
// https://www.boost.org/LICENSE_1_0.txt)

// Runs a planted build under MemorySanitizer and passes only when MemorySanitizer reported a
// use of an uninitialised value with its exit code 77, the report's first frame in the planted
// function --in names. Any other end of the program, a crash or a success, fails. The report is
// symbolised by the toolchain's llvm-symbolizer (llvm-symbolizer-18 on the lane's runner,
// installed with the lane's packages), named in MSAN_SYMBOLIZER_PATH; without symbols the frames
// are bare addresses, so the driver refuses to judge and says what is missing. Crypto's driver,
// copied: without --in, the report must be in msan_test.cpp's main.
import {spawnSync} from 'node:child_process'

const program = process.argv[process.argv.length - 1]
const inAt = process.argv.indexOf('--in')
const plantedIn = inAt === -1 ? undefined : process.argv[inAt + 1]
const symbolizer = ['llvm-symbolizer-18', 'llvm-symbolizer']
    .map(name => spawnSync('sh', ['-c', `command -v ${name}`], {encoding: 'utf8'}).stdout.trim())
    .find(path => path !== '')
if (symbolizer === undefined) {
    console.error('msan_planted: no llvm-symbolizer-18 or llvm-symbolizer on PATH; install ' +
        'llvm-18 (the lane constant-time lists it among its packages)')
    process.exit(1)
}
const run = spawnSync(program, [], {
    encoding: 'utf8',
    env: {...process.env, MSAN_OPTIONS: 'exitcode=77', MSAN_SYMBOLIZER_PATH: symbolizer},
})
process.stdout.write(run.stdout ?? '')
process.stderr.write(run.stderr ?? '')
const stderr = run.stderr ?? ''
const reported = stderr.includes('WARNING: MemorySanitizer: use-of-uninitialized-value')
// The planted branch is in main, in msan_test.cpp: the first frame or the SUMMARY line names it;
// with --in, the first frame names the function given.
const inTheTest = plantedIn !== undefined
    ? new RegExp(`^\\s*#0 .* in .*\\b${plantedIn}\\b`, 'm').test(stderr)
    : /msan_test\.cpp:\d+/.test(stderr) ||
      /^SUMMARY: MemorySanitizer: use-of-uninitialized-value .* in main$/m.test(stderr)
if (run.status === 77 && reported && inTheTest) {
    console.log('msan_planted: MemorySanitizer reported the planted branch')
    process.exit(0)
}
const where = plantedIn ?? 'msan_test.cpp'
console.error(`msan_planted: expected MemorySanitizer's report in ${where} and exit 77; ` +
    `got status ${run.status}, signal ${run.signal}, report ${reported}, ` +
    `in the test ${inTheTest}`)
process.exit(1)
