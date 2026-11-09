#!/usr/bin/env python3
"""Build the NS3-DDoSBench datasets from the per-scenario CSVs written by run_benchmark.py.

    python3 bench/build_datasets.py all  <scenario dir> <out _all.csv> [--source NAME --extra-cols]
    python3 bench/build_datasets.py classification <medium _all.csv> <highbot _all.csv> <out.csv>
    python3 bench/build_datasets.py balanced <classification.csv> <out.csv>

all            : concatenates every <scenario>_hybrid_windows.csv in filename order (one header).
                 With --source NAME it builds the hard-UDP extension release instead: pandas concat with
                 scenario_group=hard_udp_background and dataset_source=NAME (as merge_hard_udp_extension.py did).
classification : the released 5.27M-record dataset: medium + high-bot rows, without the address/port and
                 severity columns, with dataset_source = the _all file it came from.
balanced       : every normal row plus an equal-size random sample of attack rows, shuffled (random_state 42).

Files are streamed as text, so values are copied exactly as NS-3 wrote them (no re-formatting).
"""
import argparse, csv, sys
from pathlib import Path

CLASSIFICATION_COLS = [
    "scenario_id", "seed", "n_tcp", "n_attackers", "attack_rate", "attack_type", "attack_duration",
    "attack_start", "attack_stop", "bandwidth", "delay", "packet_size", "flow_id", "protocol", "window_start",
    "window_end", "tx_bytes_window", "rx_bytes_window", "throughput_mbps", "lost_packets_window",
    "duration_seconds", "tcp_goodput_mbps", "packet_loss_rate", "delay_seconds", "jitter_seconds", "phase",
    "label", "attack_flag"]


def build_all(scen_dir, out, source=None, group=None):
    files = sorted(Path(scen_dir).glob("*_hybrid_windows.csv"))
    if not files:
        sys.exit(f"no *_hybrid_windows.csv in {scen_dir}")
    if source:   # as the hard-UDP release was built (merge_hard_udp_extension.py): through pandas
        import pandas as pd
        dfs = []
        for f in files:
            df = pd.read_csv(f)
            df["scenario_group"] = group
            df["dataset_source"] = source
            dfs.append(df)
        pd.concat(dfs, ignore_index=True).to_csv(out, index=False)
        print(f"{out}: {len(files)} scenario files")
        return
    with open(out, "w", newline="") as w:
        for i, f in enumerate(files):
            with open(f, newline="") as r:
                header = r.readline().rstrip("\r\n")
                if i == 0:
                    w.write(header + "\n")
                for line in r:
                    line = line.rstrip("\r\n")
                    w.write(line + "\n")
    print(f"{out}: {len(files)} scenario files")


EOL = "\r\n"   # the released dataset uses CRLF line endings; keep them so checksums match


def build_classification(parts, out):
    n = 0
    with open(out, "w", newline="") as w:
        w.write(",".join(CLASSIFICATION_COLS + ["dataset_source"]) + EOL)
        for part in parts:
            source = Path(part).stem                     # e.g. performance_medium_overnight_benchmark_all
            with open(part, newline="") as r:
                cols = r.readline().rstrip("\r\n").split(",")
                idx = [cols.index(c) for c in CLASSIFICATION_COLS]
                for line in r:
                    v = line.rstrip("\r\n").split(",")
                    w.write(",".join(v[i] for i in idx) + f",{source}" + EOL)
                    n += 1
    print(f"{out}: {n} records")


def build_balanced(src, out, seed=42):
    """As released: all normal rows + attack rows sampled with random_state 42, concatenated in that
    order, then shuffled with random_state 42 (pandas .sample(frac=1)). Written with LF line endings."""
    import pandas as pd
    flag = pd.read_csv(src, usecols=["attack_flag"])["attack_flag"]
    normal, attack = flag[flag == 0], flag[flag == 1]
    order = pd.concat([normal, attack.sample(n=len(normal), random_state=seed)]).sample(
        frac=1, random_state=seed).index.to_numpy()
    keep = set(order.tolist())
    with open(src, newline="") as r:
        header = r.readline().rstrip("\r\n")
        lines = {i: l.rstrip("\r\n") for i, l in enumerate(r) if i in keep}
    import io
    text = header + "\n" + "\n".join(lines[i] for i in order) + "\n"
    # the release was written by pandas (e.g. 0 -> 0.0 in float columns): round-trip the same way
    pd.read_csv(io.StringIO(text)).to_csv(out, index=False, lineterminator="\n")
    print(f"{out}: {len(order)} records ({len(normal)} normal + {len(normal)} attack, shuffled)")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("all"); a.add_argument("scen_dir"); a.add_argument("out")
    a.add_argument("--source"); a.add_argument("--group", default="hard_udp_background")
    c = sub.add_parser("classification"); c.add_argument("medium"); c.add_argument("highbot"); c.add_argument("out")
    b = sub.add_parser("balanced"); b.add_argument("src"); b.add_argument("out")
    x = ap.parse_args()
    if x.cmd == "all":
        build_all(x.scen_dir, x.out, x.source, x.group)
    elif x.cmd == "classification":
        build_classification([x.medium, x.highbot], x.out)
    else:
        build_balanced(x.src, x.out)


if __name__ == "__main__":
    main()
