# SecureConnect evaluation log

This file records results copied from the local experiment artifacts. These are prototype measurements and controlled message-layer trials, not evidence of production security or end-to-end network performance.

## Run A: cryptography microbenchmark

- Run ID: `20261122-233356-7b451b93`
- Command: `java -jar target/secureconnect-1.0-SNAPSHOT.jar benchmark 200 100`
- Environment: Java 21.0.13, Windows 11, amd64, 16 reported processors
- Payloads: 1 KB, 10 KB, 100 KB, 1 MB
- Samples: 200 per metric and payload; 100 warm-up iterations
- Method: metrics warmed together and measured in rotating interleaved order
- Timed protected operations include nonce generation, message-key derivation, and AES-256-GCM. Sockets, TLS, account authentication, UI, and storage are excluded.
- Baseline: retained in-memory byte-array copy. This is not a plaintext network-chat baseline.

Latency values below are medians and 95th percentiles in microseconds. The source CSV also contains means and standard deviations.

| Payload | Encrypt median / p95 (µs) | Decrypt median / p95 (µs) | Round trip median / p95 (µs) |
|---|---:|---:|---:|
| 1 KB | 79.50 / 187.80 | 62.65 / 163.90 | 136.65 / 299.30 |
| 10 KB | 76.75 / 150.80 | 78.65 / 147.30 | 156.50 / 275.10 |
| 100 KB | 240.75 / 410.60 | 251.85 / 507.30 | 475.90 / 808.10 |
| 1 MB | 2,263.15 / 3,411.00 | 2,403.10 / 3,614.90 | 4,672.10 / 6,633.50 |

The generated summary CSV reports mean round-trip throughput of approximately 11.84, 113.53, 356.49, and 402.69 MiB/s for the four payload sizes. Round-trip throughput counts both the bytes encrypted and the bytes decrypted. The single run is preliminary: repeat the benchmark in multiple fresh JVM processes and summarize between-run variability before making performance claims. Small-payload timings are especially sensitive to JVM scheduling and runtime noise.

Local artifacts (ignored by Git):

- `experiments/results/secureconnect-20261122-233356-7b451b93-raw.csv`
- `experiments/results/secureconnect-20261122-233356-7b451b93-summary.csv`
- `experiments/results/secureconnect-20261122-233356-7b451b93-metadata.txt`
- `experiments/results/secureconnect-20261122-233356-7b451b93-latency.png`
- `experiments/results/secureconnect-20261122-233356-7b451b93-throughput.png`

## Run group: five fresh JVM benchmark runs

- Aggregate ID: `20261122-234100-94e14673`
- Run IDs: `20261122-234038-cc9b8a74`, `20261122-234042-2e7d3d2d`, `20261122-234047-6d05314e`, `20261122-234051-407baf23`, and `20261122-234055-cbda19ed`
- Settings matched across all five: 200 measured samples and 100 warm-ups per metric and payload; Java 21.0.13 on Windows 11 amd64.
- Aggregation method: average of the five per-run means; ± is sample standard deviation across those five run means. This is between-run variation, distinct from the within-run standard deviations in each individual summary.

| Payload | Encrypt (µs) | Decrypt (µs) | Round trip (µs) |
|---|---:|---:|---:|
| 1 KB | 117.32 ± 14.29 | 81.44 ± 8.58 | 183.86 ± 23.09 |
| 10 KB | 94.18 ± 15.45 | 89.52 ± 13.23 | 177.62 ± 25.60 |
| 100 KB | 284.92 ± 23.86 | 284.51 ± 16.53 | 549.97 ± 33.98 |
| 1 MB | 2,593.66 ± 146.66 | 2,673.40 ± 84.34 | 5,150.70 ± 229.77 |

For 1 MB, the between-run standard deviation is about 3–6% of the mean for these protected operations; the 1 KB and 10 KB results vary more relative to their means. The encryption mean at 10 KB being lower than at 1 KB indicates fixed per-operation costs and run-to-run noise matter at small sizes. These are local microbenchmark results only; the plaintext-copy column is not a comparable communication implementation.

Aggregate CSV (ignored by Git): `experiments/results/secureconnect-aggregate-20261122-234100-94e14673.csv`. The five source raw files, individual summary CSVs, and metadata files remain in the same results directory.

## Run B: message-layer attack-control trials

- Run ID: `20261122-233343-24507672`
- Command: `java -jar target/secureconnect-1.0-SNAPSHOT.jar security-evaluation 500`
- Outcome: 500/500 tampered envelopes, duplicate sequences, out-of-order sequences, and incorrect key versions were rejected (100% in each category).
- Artifact (ignored by Git): `experiments/results/secureconnect-security-20261122-233343-24507672.csv`

These trials exercise local cryptographic and sequence-validation code. They do not pass attacks through a live TLS relay, test account controls, or estimate attack success rates under independent network conditions. Repeated loop iterations are not substitutes for independent experiments or an external security review.

## First live TLS relay benchmark (preliminary)

- Run ID: `20261123-114408-66ca52ae`
- Accounts: Alice to Bob on the loopback TLS relay
- Settings: 100 measured samples and 10 warm-ups per payload
- Latency summary: 1 KB mean/median/p95 = 1.077/0.954/1.872 ms; 10 KB = 1.295/1.267/1.794 ms; 100 KB = 38.095/3.795/314.854 ms; 1 MB = 31.094/26.983/34.390 ms.
- Raw data had 11 samples above 300 ms for 100 KB and one such sample for 1 MB.

Do not use this run for final performance conclusions. Inspection found that the relay sent `SENT` before appending the per-message audit event. The relay now appends the audit event before sending `SENT`, and the benchmark waits for that acknowledgement between samples. This prevents that append from overlapping the next sample's timed interval.

Local artifact files (ignored by Git): `experiments/results/secureconnect-network-20261123-114408-66ca52ae-{raw,summary}.csv` and `-metadata.txt`.

## Second live TLS relay benchmark (still preliminary)

- Run ID: `20261123-114915-9359b0ed`
- Same account pair and settings as the first run
- Latency mean/median/p95: 1 KB = 0.909/0.775/1.576 ms; 10 KB = 1.315/1.220/1.843 ms; 100 KB = 41.555/3.976/315.653 ms; 1 MB = 27.608/26.931/31.192 ms.
- Raw data again had 11/100 100 KB samples above 300 ms, with a maximum of 627.543 ms; one 1 MB sample reached 355.085 ms.

The audit-write ordering change did not remove these long pauses, so the first diagnosis was incomplete. The benchmark now records stage timings for sender encryption/encoding, send-to-delivery, receiver decode/decrypt, total send-to-decrypt, and the post-decrypt relay acknowledgement wait. Capture a new run with this version and inspect the raw stage timings to locate where pauses occur before drawing conclusions. The summary for this second run predates those stage columns and remains preliminary.

Local artifact files (ignored by Git): `experiments/results/secureconnect-network-20261123-114915-9359b0ed-{raw,summary}.csv` and `-metadata.txt`.

## Third live TLS relay benchmark (stage timing; preliminary)

- Run ID: `20261123-120632-e5860a36`
- Settings: 100 measured samples and 10 warm-ups per payload
- 100 KB end-to-end latency: mean 37.751 ms, median 3.482 ms, p95 308.828 ms.
- Mean stages at 100 KB: sender encrypt/encode 0.535 ms; send-to-delivery 36.009 ms; receiver decode/decrypt 1.207 ms; post-delivery acknowledgement wait 0.022 ms.
- In raw samples, 9/100 send-to-delivery intervals exceeded 100 ms; the maximum was 625.135 ms. For 1 MB, the maximum send-to-delivery interval was 31.830 ms and no sample exceeded 100 ms.

This locates the 100 KB outliers before Bob receives the delivery frame; they are not explained by the sender's cryptographic work, Bob's decrypt, or the audit acknowledgement. It does not yet separate the sender's socket write from waiting for the delivery. The benchmark now records those as separate raw columns; collect another run with the current build before attributing the stalls to a particular network or relay operation.

Local artifacts (ignored by Git): `experiments/results/secureconnect-network-20261123-120632-e5860a36-{raw,summary}.csv` and `-metadata.txt`.

## Fourth live TLS relay benchmark (split socket stages; preliminary)

- Run ID: `20261123-122716-cd55d09c`
- Settings: 100 measured samples and 10 warm-ups per payload
- 100 KB end-to-end latency: mean 28.795 ms, median 3.469 ms, p95 314.276 ms.
- Mean 100 KB phases: sender encrypt/encode 0.549 ms; sender socket write/flush 9.816 ms; wait for delivery 17.261 ms; receiver decode/decrypt 1.168 ms; post-decrypt acknowledgement 0.023 ms.
- The raw data had 3 socket writes over 100 ms and 5 delivery waits over 100 ms; those 8 slow samples account for the high end-to-end tail. Neither sender cryptography nor receiver decryption had a sample above 100 ms.
- At 1 MB the end-to-end median was 27.431 ms and p95 30.397 ms; no phase exceeded 100 ms.

The 100 KB stalls appear in both the sender socket write and the wait for delivery, while receiver cryptography and audit acknowledgement remain short. This locates the delay in the TLS/TCP send-and-delivery path but does not identify whether the cause is runtime pauses, OS scheduling, socket behavior, or relay processing. Keep the run preliminary until controlled diagnostics distinguish those possibilities.

Local artifacts (ignored by Git): `experiments/results/secureconnect-network-20261123-122716-cd55d09c-{raw,summary}.csv` and `-metadata.txt`.

## Fifth live TLS relay benchmark (GC diagnostic attempt; preliminary)

- Run ID: `20261123-135945-275c021a`
- Settings: 100 measured samples and 10 warm-ups per payload; Alice to Bob over the local TLS relay.
- Latency mean/median/p95: 1 KB = 1.534/1.320/2.521 ms; 10 KB = 2.367/2.327/3.425 ms; 100 KB = 30.810/5.654/316.229 ms; 1 MB = 38.837/36.582/51.694 ms.
- At 100 KB, phase means were sender encryption/encoding 0.784 ms, socket write 10.047 ms, wait for delivery 18.114 ms, receiver decode/decrypt 1.865 ms, and post-decrypt acknowledgement wait 0.050 ms.
- The 100 KB tail remains concentrated in socket write and delivery wait. The 1 MB mean increased compared with the prior run, demonstrating run-to-run variability; do not interpret an individual run as a stable performance estimate.

The attempted GC option was `-Xlog:gc*:time,uptime,level,tags`. The JVM warned that it could not rename a file named `time,uptime,level,tags`; therefore this run has no usable GC diagnostic evidence. Correct syntax uses an explicit output file, for example `-Xlog:gc*:file=experiments/results/relay-gc.log:time,uptime,level,tags`, with separate files for relay and benchmark processes. Keep this run's measurements as a valid benchmark run; classify the GC logging attempt as failed.

Artifacts (ignored by Git): `experiments/results/secureconnect-network-20261123-135945-275c021a-{raw,summary}.csv` and `-metadata.txt`.

## Initial network benchmark aggregation (two runs; preliminary)

- Aggregate ID: `20261123-145739-83eb4c49`
- Source runs: `20261123-122716-cd55d09c` and `20261123-135945-275c021a`, each with 100 measured samples and 10 warm-ups per payload.
- The aggregate calculates the average of each run's mean and the sample standard deviation across the two run means. It also reports average per-run medians and p95 values. These two runs are an initial diagnostic pair, not enough independent runs for a strong performance estimate.

| Payload | Mean of run means ± between-run SD (ms) | Mean run median (ms) | Mean run p95 (ms) |
|---|---:|---:|---:|
| 1 KB | 1.101 ± 0.612 | 0.967 | 1.800 |
| 10 KB | 1.703 ± 0.938 | 1.709 | 2.475 |
| 100 KB | 29.802 ± 1.425 | 4.561 | 315.252 |
| 1 MB | 33.332 ± 7.785 | 32.007 | 41.046 |

At 100 KB, per-run p95 remains much higher than the median despite similar run means. The live relay path therefore has a heavy tail in both runs; aggregate charts make that comparison visible but do not explain its cause. Continue collecting identical runs and use process-specific GC logs or other diagnostics before attributing the pauses.

Artifacts (ignored by Git): `experiments/results/secureconnect-network-aggregate-20261123-145739-83eb4c49.csv`, `-latency.png`, and `-phases.png`.

## GC diagnostic network benchmark (benchmark process only)

- Run ID: `20261123-152421-bc7379ac`
- Settings: 100 measured samples and 10 warm-ups per payload. The benchmark JVM used `-Xlog:gc*:file=experiments/results/benchmark-gc.log:time,uptime,level,tags`; the relay process was not started with GC logging.
- Its GC log contains 39 stop-the-world pause entries totaling 70.402 ms. The longest was 4.735 ms; none exceeded 10 ms.
- 100 KB mean/median/p95 was 27.515/5.441/310.369 ms. Seven of 100 samples exceeded 100 ms. The largest samples were split between sender socket writes (up to 313.21 ms) and waiting for delivery (up to 318.46 ms).

No benchmark-process stop-the-world pause was long enough to explain the roughly 300 ms message delays. Raw CSV samples do not contain wall-clock timestamps, so individual pauses cannot be paired to sample indices exactly. Because the relay JVM was not logged, this diagnostic cannot rule out a relay pause. Keep this GC-instrumented run separate from the uninstrumented performance aggregate.

Artifacts (ignored by Git): `experiments/results/secureconnect-network-20261123-152421-bc7379ac-{raw,summary}.csv`, `-metadata.txt`, and `benchmark-gc.log`.

## Next measurement step

Repeat the live TLS benchmark in at least five fresh JVM runs with the same server/client configuration, payload sizes, sample counts, and warm-up counts. Aggregate those summaries with `network-benchmark-aggregate`; it reports mean latency across run means, between-run sample standard deviation, min/max run means, mean per-run median and p95, throughput, and phase means, and creates latency and phase charts. Use the corrected GC logging option for both relay and benchmark processes if diagnosing collection pauses. Keep the 500-trial security-control result as a deterministic implementation check and separately record live localhost proxy demonstrations for tamper and replay behavior.
