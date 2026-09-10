<<<<<<< HEAD
=======
# Source Code

This directory is the executable project root.

```text
src/                     Core traffic parsing, behavior construction,
                         centroid prediction, and classification modules
comparison_experiments/  Paper experiment implementations and shell entry points
scripts/                 CSV labeling, extraction, and merge utilities
```

Backups, deprecated implementations, bytecode caches, trained model files, and
temporary experiment outputs are intentionally excluded from this release.

The principal modules are:

- `src/UnifiedPcapToCSV.py`: PCAP parsing and bidirectional flow extraction.
- `src/drift_prediction/`: centroid construction, Transformer training, and
  single-step behavior prediction.
- `src/behavior_change/drift_reshaper.py`: packet-count, frame-byte, and timing
  behavior reshaping under payload constraints.
- `src/ReconstitutePackets.py`: protocol-aware packet reconstruction.
- `src/classification/`: multiscale behavior vectorization, PCA, MLP training,
  fine-tuning, and evaluation.

Every experiment directory includes its own README or executable shell script.
Large data inputs are documented in `../data/README.md`.
>>>>>>> 3ea559a (Initial BAC-TL release)

