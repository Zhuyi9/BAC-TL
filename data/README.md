<<<<<<< HEAD

=======
# Data

This directory contains dataset metadata and compact experiment results. Raw
PCAP files and full intermediate CSV/NumPy datasets are intentionally excluded
because the local research workspace exceeds 90 GB and the source datasets have
independent redistribution terms.

## Data sources

| Experiment label | Source | Project usage |
| --- | --- | --- |
| DoS | CIC-IDS2017 | Attack flows and IDS-2017 background flows |
| XSS | CIC-IDS2017 | XSS attack flows and IDS-2017 background flows |
| P2P Botnet | CTU-13 scenario 12 | P2P botnet positive flows |
| Zeus | USTC-TFC2016 | Zeus malware positive flows |
| Scan | SCU-Scan | Locally captured web-scan positive flows |

Official sources:

- CIC-IDS2017: <https://www.unb.ca/cic/datasets/ids-2017.html>
- CTU-13: <https://www.stratosphereips.org/datasets-ctu13/>
- USTC-TFC2016: <https://github.com/davidyslu/USTC-TFC2016>

## Local raw-data layout

After downloading or collecting the data, use the following local structure:

```text
data/raw/
├── pcap/
│   ├── CTU-13-Dataset/12/botnet-capture-20110819-bot.pcap
│   ├── trojan/Malware/Zeus.pcap
│   ├── scan/web_scan.pcap
│   └── xss/XSS.pcap
└── csv_output/wednesday/
    └── flows_100000_to_200000_from_chunks_labeled.csv
```

DoS positives and background samples are selected from the labeled
CIC-IDS2017 Wednesday flow CSV. The exact selection and generation settings for
each published experiment are recorded under `manifests/`.

## Included records

```text
manifests/
  dos/ scan/ xss/ zeus/ p2p_botnet/  Dataset construction settings
  long_term_drift/                    Ten-window drift dataset settings

results/
  method_comparison/                  None, SMOTE, and BAC-TL comparisons
  temporal_granularity/               13 temporal-granularity configurations
  long_term_drift/                    Ten-round Recall/F1 evolution
  efficiency/                         Runtime, CPU, and memory measurements
  traffic_reconstruction/             Original-feature reconstruction evidence
  transformed_feature_construction/   Behavior-transformed traffic evidence
```

The result tables contain no raw packet payload. Paths in copied manifests are
provenance records rather than runnable configuration. Their original machine
prefixes have been replaced with `<ORIGINAL_PROJECT_ROOT>` and
`<TEMP_WORK_DIR>`; see `manifests/README.md`.
>>>>>>> 3ea559a (Initial BAC-TL release)
