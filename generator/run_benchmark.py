#!/usr/bin/env python3
"""Run an NS3-DDoSBench generation grid (replaces the run_*_benchmark.sh scripts).

    python3 bench/run_benchmark.py <bench_*.json> --out <dir> [--jobs N] [--only REGEX] [--list]

The config gives the NS-3 program, the parameter grid (every combination is one scenario), the fixed
arguments and the scenario-name template. Each scenario is an independent, seeded NS-3 process, so they run
in parallel and give the same CSVs as the old one-at-a-time loops. Finished scenarios are skipped, so an
interrupted run resumes where it stopped. Output: <out>/<scenario>_hybrid_windows.csv and <out>/runs.csv.
"""
import argparse, concurrent.futures as cf, csv, itertools, json, os, re, subprocess, sys, time
from pathlib import Path

NS3 = Path(os.environ.get("NS3_DIR", Path(__file__).resolve().parents[2] / "ns-3.47"))


def scenarios(c):
    keys = list(c["grid"])
    for values in itertools.product(*(c["grid"][k] for k in keys)):
        p = dict(zip(keys, values))
        sid = c["scenario"].format(**p)
        args = [f"--{k}={v}" for k, v in p.items()] + [f"--scenarioId={sid}"]
        args += [f"--{k}={v}" for k, v in c["fixed"].items()]
        yield sid, args


def binary(program):
    b = NS3 / "build/scratch" / f"ns3.47-{program}-default"
    if not b.exists():
        sys.exit(f"{b} not found: run ./ns3 build {program} in {NS3}")
    return b


def run_one(sid, args, b, out):
    final = out / f"{sid}_hybrid_windows.csv"
    if final.exists():
        return sid, "skipped", 0
    work = out / ".work" / sid                      # the program writes results/<id>_hybrid_windows.csv
    (work / "results").mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    p = subprocess.run([str(b), *args], cwd=work, capture_output=True, text=True)
    produced = work / "results" / final.name
    if p.returncode or not produced.exists():
        (out / "failed").mkdir(exist_ok=True)
        (out / "failed" / f"{sid}.log").write_text(p.stdout[-5000:] + p.stderr[-5000:])
        return sid, "failed", time.time() - t0
    os.replace(produced, final)
    for d in (work / "results", work):
        d.rmdir()
    return sid, "ok", time.time() - t0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("config"); ap.add_argument("--out", required=True)
    ap.add_argument("--jobs", type=int, default=None); ap.add_argument("--only", default="")
    ap.add_argument("--list", action="store_true", help="print the scenarios and arguments, run nothing")
    a = ap.parse_args()
    c = json.loads(Path(a.config).read_text())
    todo = [(s, x) for s, x in scenarios(c) if re.search(a.only, s)]
    if a.list:
        for s, x in todo:
            print(s, " ".join(x))
        return
    out = Path(a.out); out.mkdir(parents=True, exist_ok=True)
    b = binary(c["program"])
    jobs = a.jobs or c.get("jobs", os.cpu_count() // 2)
    print(f"{len(todo)} scenarios, {jobs} at a time, {b.name}", flush=True)
    with open(out / "runs.csv", "a", newline="") as log, cf.ThreadPoolExecutor(jobs) as ex:
        w = csv.writer(log)
        for i, (sid, status, secs) in enumerate(ex.map(lambda t: run_one(*t, b, out), todo), 1):
            w.writerow([sid, status, f"{secs:.0f}", time.strftime("%F %T")]); log.flush()
            print(f"[{i}/{len(todo)}] {sid} {status} {secs:.0f}s", flush=True)
    if (out / ".work").exists() and not any((out / ".work").iterdir()):
        (out / ".work").rmdir()
    failed = list((out / "failed").glob("*.log")) if (out / "failed").exists() else []
    if failed:
        sys.exit(f"{len(failed)} scenarios failed; logs in {out / 'failed'}")


if __name__ == "__main__":
    main()
