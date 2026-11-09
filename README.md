# NS3-DDoSBench

A performance-aware, time-windowed dataset for behaviour-based UDP-flood DDoS detection, generated with the
NS-3 network simulator (ns-3.47), together with the simulation script and configuration files that produce it.

## Files
| File | What |
|---|---|
| `NS3-DDoSBench_dataset.csv` | the dataset: 5,270,508 flow-window records, 29 columns (Git LFS) |
| `Hard_UDP_Background_Extension_Dataset.tar.gz` | hard-scenario extension: 456,786 records with 10/30/50 benign UDP nodes |
| `generator/hybrid_performance_attack.cc` | the NS-3 scenario (dumbbell topology, TCP clients, benign UDP background, UDP flooding bots; FlowMonitor statistics per 1 s window) |
| `generator/bench_perf_medium.json`, `bench_perf_highbot.json` | the two parameter grids of the dataset (648 + 216 = 864 scenarios) |
| `generator/bench_hard_udp.json` | the parameter grid of the hard-UDP extension (648 scenarios) |
| `generator/run_benchmark.py` | runs every scenario of a grid (in parallel, resumable) |
| `generator/build_datasets.py` | merges the per-scenario CSVs into the released files, and builds the balanced subset |
| `SHA256SUMS` | checksums of the released CSV files |

## Dataset
- 864 scenarios = 432 parameter configurations x 2 seeds; each run lasts 9 s and yields one record per flow per
  1-second window.
- Factors: TCP clients {5, 20}; attackers {100, 300, 1000, 2000, 3000} (2000/3000 with 5 TCP clients only);
  attack type {constant, bursty, mixed}; attack rate {500 Kbps, 1 Mbps, 2 Mbps}; packet size {64, 512, 1024} B;
  attack duration {short, long}; bottleneck 50 Mbps, 10 ms; attack start 3.633 s.
- Classes: 216,108 normal (`attack_flag = 0`; 193,644 TCP + 22,464 benign UDP) and 5,054,400 attack
  (`attack_flag = 1`). Labels come from the node role in the simulation, not from traffic measurements.
- Columns: scenario parameters (`scenario_id, seed, n_tcp, n_attackers, attack_rate, attack_type, attack_duration,
  attack_start, attack_stop, bandwidth, delay, packet_size`), flow and window (`flow_id, protocol, window_start,
  window_end, duration_seconds`), traffic and performance features (`tx_bytes_window, rx_bytes_window,
  throughput_mbps, lost_packets_window, tcp_goodput_mbps, packet_loss_rate, delay_seconds, jitter_seconds`),
  labels (`phase, label, attack_flag`) and `dataset_source` (the grid a record comes from).
- Balanced subset (432,216 records): every normal record plus an equal random sample of attack records
  (`random_state = 42`), built with `build_datasets.py balanced` (below).

## Regenerating the data
Requires ns-3.47 and Python 3 (pandas only for the balanced subset and the extension).
```bash
cp generator/hybrid_performance_attack.cc <ns-3.47>/scratch/
cd <ns-3.47> && ./ns3 configure && ./ns3 build hybrid_performance_attack && cd -
export NS3_DIR=<ns-3.47>                 # default: an ns-3.47 directory next to this repository

python3 generator/run_benchmark.py generator/bench_perf_medium.json  --out runs/medium  --jobs 8
python3 generator/run_benchmark.py generator/bench_perf_highbot.json --out runs/highbot --jobs 8
python3 generator/build_datasets.py all runs/medium  runs/performance_medium_overnight_benchmark_all.csv
python3 generator/build_datasets.py all runs/highbot runs/performance_highbot_overnight_benchmark_all.csv
python3 generator/build_datasets.py classification runs/performance_medium_overnight_benchmark_all.csv \
        runs/performance_highbot_overnight_benchmark_all.csv NS3-DDoSBench_dataset.csv
python3 generator/build_datasets.py balanced NS3-DDoSBench_dataset.csv balanced_ddos_classification_dataset.csv

# hard-UDP extension
python3 generator/run_benchmark.py generator/bench_hard_udp.json --out runs/hard_udp --jobs 8
python3 generator/build_datasets.py all runs/hard_udp hard_udp_background_extension_dataset.csv \
        --source hard_udp_background_extension
sha256sum -c SHA256SUMS
```
`run_benchmark.py <config> --out <dir> --list` prints every scenario and its arguments without running it.
Scenarios with 2000-3000 attackers take up to about an hour each. Rebuilding the released files from the
per-scenario CSVs with these scripts reproduces them byte for byte (checked 2026-11-09).

## License and citation
- **Code** (`generator/`): MIT License, see [`LICENSE`](LICENSE).
- **Data** (`NS3-DDoSBench_dataset.csv`, `Hard_UDP_Background_Extension_Dataset.tar.gz` and the files built from
  them): Creative Commons Attribution 4.0 International (CC BY 4.0), see [`LICENSE-DATA`](LICENSE-DATA).
  You may use, share and adapt the data for any purpose, provided you give appropriate credit.

If you use NS3-DDoSBench, please cite the accompanying paper (reference to be added on publication) and this
repository: https://github.com/AashirAmaar/NS3-DDoSBench
