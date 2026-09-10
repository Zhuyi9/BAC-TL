# Dataset Manifests

These files preserve the parameters, sample counts, window metadata, and file
names used to construct the reported datasets. They are experiment provenance,
not self-contained datasets.

Two path placeholders are used in this release:

- `<ORIGINAL_PROJECT_ROOT>`: root of the original research workspace.
- `<TEMP_WORK_DIR>`: ephemeral working directory created during a run.

Raw captures, generated flow CSV files, trained checkpoints, and temporary
centroid arrays are intentionally not included. Re-run the corresponding script
under `../../src/comparison_experiments/` to regenerate them locally.
