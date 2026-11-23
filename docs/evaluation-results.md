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

## Next measurement step

Repeat the microbenchmark in at least five fresh JVM runs on the same machine, retaining every raw CSV and metadata file. Aggregate the matching summary CSVs with `benchmark-aggregate`; it reports mean latency across run means, between-run sample standard deviation, min/max run means, and the average per-run median and p95. Keep the 500-trial security-control result as a deterministic implementation check and separately record live localhost proxy demonstrations for tamper and replay behavior.
