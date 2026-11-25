#!/usr/bin/env python3
# Copyright (c) 2026 WebCpp.org
#
# Distributed under the Boost Software License, Version 1.0. (See
# accompanying file LICENSE_1_0.txt or copy at
# https://www.boost.org/LICENSE_1_0.txt)

"""Measures bench/timing.cpp natively and renders doc/performance.adoc from its data, after
webcpp::hash's collect.py reduced to the guard.

    collect.py --timing <path> \\
        --data libs/secure/doc/measurements.json --page libs/secure/doc/performance.adoc
    collect.py --render-only \\
        --data libs/secure/doc/measurements.json --page libs/secure/doc/performance.adoc

Run from the superproject's root, with the program bench/Jamfile builds at variant=release,
`b2 libs/secure/bench//timing`; --data and --page are relative to the same root. `--render-only`
rewrites the page from the data and measures nothing.

The page is built only from release builds: a program whose build directory, b2's
bench/<toolset>/<variant>/..., is not variant=release, or does not say, is refused before it runs,
and `--render-only` refuses data whose build is not BUILD. A measurement is for an idle machine:
it records the machine's 1, 5 and 15 minute load averages before and after the run, and the page
states them, so that a measurement taken under load says so.

The guard's cost (secure::timing_guard, which every function of webcpp that computes on a secret
holds and which sets 64-bit ARM's DIT where the CPU has it) is `timing --measure`'s one line:
whether the guard sets DIT on this machine, and the nanoseconds a guard adds to a call entered from
a thread whose DIT is clear, from one where it is already set, and a disengaged guard's (a call
keyed only by its arguments, made without a key), each the median of five runs of 10^7 guards minus
an empty loop's, with the fastest and slowest run. The data keeps it with the date (UTC's), the
machine and the load. A line or a data file that is not the form this script writes (an older
program's, a key missing or of another type) is refused with a message naming what is wrong, before
anything is written.
"""

import argparse
import datetime
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

# What the page is built from, and only from: bench/Jamfile's timing, at variant=release.
BUILD = "variant=release"
# The 1 minute load average at or above which a measurement says the machine was not idle.
IDLE_LOAD = 2
RELEASE_ONLY = "the page is built only from release builds: bench/Jamfile's timing at " + BUILD


def variant_of(exe):
    """The variant b2 built exe at, as its build directory names it, bench/<toolset>/<variant>/...;
    None when its path does not say."""
    parts = Path(exe).resolve().parts
    if "bench" not in parts:
        return None
    last = len(parts) - 1 - parts[::-1].index("bench")
    after = parts[last + 1:]
    return after[1] if len(after) > 2 else None


def check_release(exe):
    """Exits naming exe when it was not built at variant=release, before anything runs."""
    variant = variant_of(exe)
    if variant is None:
        sys.exit(f"collect.py: timing={exe} is not in b2's bench/<toolset>/<variant>/..., so its "
                 f"variant cannot be read: {RELEASE_ONLY}")
    if variant != "release":
        sys.exit(f"collect.py: timing={exe} was built at variant={variant}: {RELEASE_ONLY}")


NUMBER = (int, float)
# bench/timing.cpp's line, and the data this script writes from it: each key's type, or the shape
# of a nested object.
LINE_SHAPE = {"dit": bool, "clear": NUMBER, "set": NUMBER, "disengaged": NUMBER,
              "clear_fastest": NUMBER, "clear_slowest": NUMBER, "set_fastest": NUMBER,
              "set_slowest": NUMBER, "disengaged_fastest": NUMBER, "disengaged_slowest": NUMBER,
              "iterations": int, "runs": int, "target": str, "compiler": str}
DATA_SHAPE = {"date": str, "build": str, "target": str, "compiler": str, "iterations": int,
              "runs": int, "dit": bool,
              "machine": {"cpu": str, "architecture": str, "cores": int, "os": str},
              "load_average_before_after": [[NUMBER]],
              **{f"{part}{spread}_ns": NUMBER for part in ("clear", "set", "disengaged")
                 for spread in ("", "_fastest", "_slowest")}}


def wrong(value, shape, where):
    """The first place in value that shape requires and value lacks or holds otherwise, named as
    a path from where; None when value has the shape. A one-element list is a non-empty list of
    that shape; a bool is never a number."""
    if isinstance(shape, dict):
        if not isinstance(value, dict):
            return f"{where} (not an object)"
        for key, inner in shape.items():
            if key not in value:
                return f"{where}.{key} (missing)"
            found = wrong(value[key], inner, f"{where}.{key}")
            if found is not None:
                return found
        return None
    if isinstance(shape, list):
        if not isinstance(value, list) or not value:
            return f"{where} (not a list, or empty)"
        return next((found for index, item in enumerate(value)
                     if (found := wrong(item, shape[0], f"{where}[{index}]")) is not None), None)
    types = shape if isinstance(shape, tuple) else (shape,)
    if isinstance(value, bool) and bool not in types:
        return where
    return None if isinstance(value, types) else where


def utc_today():
    """Today's date in UTC, the date every measurement of the page states."""
    return datetime.datetime.now(datetime.timezone.utc).date().isoformat()


def sysctl(name):
    try:
        out = subprocess.run(["sysctl", "-n", name], capture_output=True, text=True, check=False)
        return out.stdout.strip()
    except OSError:
        return ""


def measure_timing(exe):
    """The guard's cost, timing --measure's line, natively, with when, where and under what load
    it was measured; exits naming what is wrong when the program fails or its line is not the
    form this script reads."""
    loads = [os.getloadavg()]
    done = subprocess.run([exe, "--measure"], capture_output=True, text=True, check=False)
    loads.append(os.getloadavg())
    if done.returncode != 0:
        sys.exit(f"collect.py: timing --measure: exit {done.returncode}\n"
                 f"{done.stdout}{done.stderr}")
    lines = done.stdout.strip().splitlines()
    try:
        line = json.loads(lines[-1]) if lines else None
    except ValueError:
        line = None
    found = wrong(line, LINE_SHAPE, "line") if line is not None else "line (not JSON)"
    # LINE_SHAPE is an object's, so wrong finds nothing only in a dict; the isinstance states that
    # to the type checker.
    if found is not None or not isinstance(line, dict):
        printed = lines[-1] if lines else ""
        sys.exit(f"collect.py: timing --measure printed {printed!r}, which is not the form "
                 f"collect.py reads: {found} is wrong; build bench/Jamfile's timing again from "
                 "this tree")
    return {
        "measurement": "the nanoseconds secure::timing_guard adds to a call, bench/timing.cpp",
        "date": utc_today(),
        "machine": {
            "cpu": sysctl("machdep.cpu.brand_string") or platform.processor() or platform.machine(),
            "architecture": platform.machine(),
            "cores": os.cpu_count() or 1,
            "os": f"{platform.system()} {platform.release()}",
        },
        "load_average_before_after": [list(loads[0]), list(loads[1])],
        "build": BUILD,
        "target": line["target"],
        "compiler": line["compiler"],
        "iterations": line["iterations"],
        "runs": line["runs"],
        "dit": line["dit"],
        **{f"{part}{spread}_ns": line[f"{part}{spread}"]
           for part in ("clear", "set", "disengaged") for spread in ("", "_fastest", "_slowest")},
    }


def fmt_load(load):
    return "/".join(f"{x:.2f}" for x in load)


def fmt_ns(value):
    """Nanoseconds as the page shows them: one decimal, a figure that rounds to zero or below it
    shown as 0.0, the empty loop's noise."""
    return "0.0" if round(value, 1) <= 0 else f"{value:.1f}"


def render(data, page):
    machine_info = data["machine"]
    load = data["load_average_before_after"]
    sets = ("The guard sets DIT on this machine." if data["dit"] else
            "The guard does not set DIT on this machine (no FEAT_DIT, or a target it does not "
            "cover): every row is the loop's noise.")
    lines = [
        "// Copyright (c) 2026 WebCpp.org",
        "//",
        "// Distributed under the Boost Software License, Version 1.0. (See",
        "// accompanying file LICENSE_1_0.txt or copy at",
        "// https://www.boost.org/LICENSE_1_0.txt)",
        "",
        "// Generated by bench/collect.py from doc/measurements.json: do not edit.",
        "",
        "[#secure-performance]",
        "== The guard's cost",
        "",
        "Every function of webcpp that computes on a secret (a MAC, a key derivation, a tag's",
        "comparison, a cipher) runs inside `timing_guard`, which on 64-bit ARM under macOS, iOS,",
        "Linux, Android and Windows, where the CPU has FEAT_DIT, sets DIT (data-independent",
        "timing) for the call and restores the thread's state after it (<<secure-guard>>): one",
        "`mrs`, and where DIT was clear, two `msr` each followed by an `isb`. Elsewhere (x86,",
        "WebAssembly, ARM64EC) it executes no instruction. A function keyed only by its",
        "arguments, called without a key, holds a disengaged guard, which reads its flag and",
        "does nothing else.",
        "",
        f"Measured natively on {data['date']} (UTC) on {machine_info['cpu']}",
        f"({machine_info['architecture']}), {machine_info['os']}, built with {data['build']}",
        f"by {data['compiler']} (bench/timing.cpp): each row is the median of",
        f"{data['runs']} runs of {data['iterations']:,} guards around a store, with the",
        "fastest and slowest run beside it, each minus the median of the same loop without the",
        "guard, in nanoseconds per call; a figure that rounds to zero or below, the loop's",
        "noise, shows as 0.0.",
        f"{sets} The machine's 1, 5 and 15 minute load averages were {fmt_load(load[0])}",
        f"before and {fmt_load(load[1])} after, on {machine_info['cores']} cores: the figures",
        f"are to be taken on an idle machine, one whose 1 minute load average is below {IDLE_LOAD}.",
        "",
    ]
    if max(load[0][0], load[1][0]) >= IDLE_LOAD:
        lines += [
            f"NOTE: the 1 minute load average was {load[0][0]:.2f} before and {load[1][0]:.2f}",
            f"after, and that rule asks for below {IDLE_LOAD} at both: read the figures",
            "as an upper bound of an idle machine's.",
            "",
        ]
    rows = (
        ("clear", "clear, as a program that sets nothing has it",
         "reads DIT, sets it, and clears it on the way out"),
        ("set", "already set, by the program or by an outer guard",
         "reads DIT and leaves it set"),
        ("disengaged", "any: a function keyed by its arguments, called without a key",
         "reads its flag and does nothing else"),
    )
    lines += [
        '[cols="2,4,1,1,1",options="header"]',
        "|===",
        "| The thread's DIT on entry | What the guard does | Median (ns) | Fastest (ns) "
        "| Slowest (ns)",
    ]
    for part, entry, does in rows:
        lines += [
            "",
            f"| {entry}",
            f"| {does}",
            f"| {fmt_ns(data[part + '_ns'])}",
            f"| {fmt_ns(data[part + '_fastest_ns'])}",
            f"| {fmt_ns(data[part + '_slowest_ns'])}",
        ]
    lines += ["|===", ""]
    with open(page, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def release_data(path):
    """The data at path and None, or None and what is wrong with it: it cannot be read, was not
    built at BUILD, or is not the form this script writes."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as error:
        return None, f"{path} cannot be read ({error}); --timing writes it"
    if not isinstance(data, dict) or data.get("build") != BUILD:
        build = data.get("build") if isinstance(data, dict) else None
        return None, f"{path} was measured with build {build}, not {BUILD}: {RELEASE_ONLY}"
    found = wrong(data, DATA_SHAPE, "data")
    if found is not None:
        return None, (f"{path} is not the data collect.py writes: {found} is wrong; measure the "
                      "guard again with --timing")
    return data, None


def main():
    parser = argparse.ArgumentParser(description="Measures bench/timing.cpp and renders its page.")
    parser.add_argument("--data", required=True)
    parser.add_argument("--page", required=True)
    parser.add_argument("--timing", metavar="PATH",
                        help="bench/Jamfile's timing at variant=release, run natively")
    parser.add_argument("--render-only", action="store_true",
                        help="rewrite the page from the data and measure nothing")
    args = parser.parse_args()
    if args.render_only == (args.timing is not None):
        sys.exit("collect.py: give --timing to measure, or --render-only to render the data")
    if args.render_only:
        data, fault = release_data(args.data)
        if data is None:
            sys.exit(f"collect.py: {fault}")
    else:
        check_release(args.timing)
        data = measure_timing(args.timing)
        with open(args.data, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
    render(data, args.page)


if __name__ == "__main__":
    main()
