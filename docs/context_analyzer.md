<!--docs\context_analyzer.md-->
# Analyseur contextuel d'espaces complets B(J,e)

`sha256_context_analyzer` travaille hors ligne à partir de `results/stratum_jobs.jsonl`. Son unité scientifique est exclusivement le couple contexte Stratum exact `J` / extranonce2 `e`, dont les `2^32` nonces sont parcourus intégralement. Il ne cherche pas un ordre de nonces à l'intérieur d'un header.

## Dimensionnement choisi par l'utilisateur

`05_ANALYSEUR_CONTEXTE.bat` expose QUICK, PILOT, FULL, reprise, analyse, CUSTOM et smoke. Les trois profils sont des exemples modifiables dans `config/context_analysis.json`; FULL est initialisé par un budget de temps et n'est lié à aucun total fixe de blocs.

Trois méthodes sont disponibles:

```powershell
# Total exact libre
sha256_context_analyzer.exe plan --profile CUSTOM --total-blocks 2000 --prevhashes 20 --contexts 40

# Géométrie explicite
sha256_context_analyzer.exe plan --profile CUSTOM --prevhashes 20 --contexts 40 --blocks-per-context 50

# Budget mesuré sur le GPU réel
sha256_context_analyzer.exe plan --profile CUSTOM --minutes 480 --prevhashes 32 --contexts 64
```

Avant `new`, l'outil benchmarke un vrai header reconstruit et affiche le nombre de prevhash, de contextes, le minimum/maximum de blocs par contexte, le total de blocs et de hashes, le débit, l'ETA et le stockage. En interactif: `A` accepte, `M` redimensionne, `C` annule sans créer de manifeste. Un faible échantillon déclenche un avertissement, jamais un refus.

## Sélection et séparation scientifique

- Les contextes sont dédupliqués par `work_fingerprint`, équilibrés entre prevhash puis sélectionnés par seed.
- Les extranonce2 respectent la taille archivée et utilisent un PRNG déterministe avec stratification du premier octet; une suite contiguë n'est jamais le corpus unique.
- Discovery, validation et holdout possèdent des prevhash entièrement disjoints. Avec moins de trois prevhash, l'outil avertit que les trois partitions ne peuvent pas être constituées.
- Les seuils de queue et métriques principales sont pré-déclarés dans le manifeste avant le premier scan.
- `features.jsonl` porte uniquement `feature_stage=PRE_SCAN`; `block_labels.jsonl` porte uniquement les résultats post-scan.

## Reprise et fichiers

Chaque campagne se trouve sous `results/context_analysis/<campaign_id>/`:

```text
manifest.json              contexte exact, seed, sélection, partitions, paramètres
checkpoint.json            progression atomique et dernier B(J,e) durable
features.jsonl             variables disponibles avant scan
block_labels.jsonl         minimum exact, nonce, difficulté, queues, network hits
analysis_summary.json      rapport statistique machine-readable
report.md                  synthèse humaine
holdout_evaluation.json    évaluation finale créée une seule fois
```

Le label n'est écrit avec `complete=true` qu'après `2^32` hashes. Au redémarrage, les identifiants complets présents dans `block_labels.jsonl` sont récupérés avant le checkpoint: un crash entre l'append et le checkpoint ne provoque donc pas de rescan ni de doublon. Le bloc courant non terminé peut être recommencé, jamais les blocs précédents.

## Analyse

`analyze` relit les données sans scanner. Le JSON produit sépare les partitions, contrôle les queues contre leur espérance binomiale/Poisson, rapporte les corrélations simples et les baselines de ranking, les top 1/5/10/25 %, le lift et le coût. Les résultats discovery sont marqués exploratoires. Aucun avantage n'est revendiqué sans réplication sur prevhash holdout.

Le premier pipeline conserve le minimum exact et les compteurs de queue/réseau mais pas encore un top-K exact de 32 ou 64 hashes par bloc. Les modèles complexes et intervalles permutationnels restent volontairement absents tant que le corpus labellisé ne justifie pas leur coût et leur risque de sur-ajustement.
