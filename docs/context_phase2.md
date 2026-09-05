# Phase 2A — classement intra-contexte PRE_SCAN

Phase 2A is an offline, discovery-only analysis of an already completed context
campaign. It never invokes the header-space scanner or an OpenCL/GPU path.
It is locked to campaign `ctx_20260904_165537_41323536`.

## Primary operational route

The primary question is whether PRE_SCAN features can rank the extranonce2
candidates inside each Stratum context `J`. For every context, mean ranks of
`quality_bits` (including ties) define the POST_SCAN response only:

```text
context_quality_score = (n_context - mean_rank_quality_bits) / (n_context - 1)
```

The score is 1 for the best untied candidate and 0 for the worst. It is never
admissible as an input feature. `intra_context_feature_summary.csv` first
computes a Spearman statistic in each context, averages the context statistics
inside each prevhash, then summarizes and bootstraps whole prevhash units.

`topk_lift_intra_context.csv` independently selects `ceil(n_context * f)` rows
inside every context for `f = 1%, 5%, 10%, 25%`, then combines the selections.
Its quality and tail lift intervals resample complete prevhash units. The
primary ridge model also targets `context_quality_score`; its inner and outer
folds are grouped by prevhash, with normalization, feature selection, and
lambda selection fit on training rows only. OOF predictions are ranked within
their own contexts. Its train-only feature score is the absolute mean, over
training prevhashes, of Spearman correlations computed separately inside the
training contexts.

Features in family `SANITY_BASELINE` remain in univariate and top-k negative
controls, but are categorically excluded from the primary ridge feature
selection. Primary discovery candidate ordering uses the mean prevhash-level
intra-context Spearman statistic. Any permutation p-value following that
selection is labelled post-selection, exploratory, unadjusted, and not
evidence.

Primary operational artifacts are:

- `intra_context_feature_summary.csv`
- `topk_lift_intra_context.csv`
- `grouped_cv_rank_summary.json`
- `grouped_cv_rank_predictions.csv`

The pooled `quality_bits` ridge model, global univariate summaries, and
`topk_lift_global_descriptive.csv` are retained only as secondary/descriptive
analyses.

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
Validation and holdout rows used are always zero. Nothing in Phase 2A is
labelled validated.
