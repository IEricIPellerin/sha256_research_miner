# Phase 2A — white-box PRE_SCAN enrichment

Phase 2A is an offline, discovery-only analysis of an already completed context
campaign. It never invokes the header-space scanner or an OpenCL/GPU path.

## Partition barrier

The Phase 2 loader accepts feature rows whose partition is exactly `discovery`.
While reading labels, it checks the top-level partition and skips `validation`
and `holdout` before accessing the `quality` object. The command rejects
`--partition validation`, `--partition holdout`, and `--finalize-holdout`.

Context references are selected by the minimum tuple
`(SHA256(ASCII block_id), block_id)` among PRE_SCAN rows in that context.
Prevhash-relative references use the same rule. Labels never participate in a
reference choice.

## Commands

Validate a completed campaign without writing an artifact or running the
statistical analysis:

```bat
build\windows-release\Release\sha256_context_analyzer.exe phase2 ^
  --campaign results\context_analysis\ctx_20260904_165537_41323536 --check
```

After reviewing the dry check, create the full Phase 2A artifacts:

```bat
build\windows-release\Release\sha256_context_analyzer.exe phase2 ^
  --campaign results\context_analysis\ctx_20260904_165537_41323536
```

The interactive `05_ANALYSEUR_CONTEXTE.bat` menu exposes the same operation as
option 9 and displays the partition boundary before confirmation.

The output directory is fixed to `phase2_discovery_v1` below the campaign and
is never overwritten. Source file SHA-256 digests are checked before and after
the analysis.

## Statistical status

All univariate, grouped-bootstrap, permutation, top-k, and nested grouped-CV
results remain exploratory. Scaling and feature selection are fit only on the
relevant training split; lambda selection uses an inner prevhash-grouped CV.
Nothing in Phase 2A is labelled validated.
