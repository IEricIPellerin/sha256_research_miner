# Phase 3 — POST_SCAN Y-SORT / TRAJECTORY

## Statut scientifique

Phase 3 est une expérience indépendante, discovery/exploratory et non validée. La piste PRE_SCAN/T30 de Phase 2 est suspendue faute de signal généralisable (dernier test selection-aware/max-stat : `p ≈ 0,95025`). Aucun score, ridge ou résultat de Phase 2 ne participe à la sélection de `J`, `e` ou `n`. Phase 3 pose une autre question : comment la trajectoire SHA256d complète d'un header fixé se rapporte-t-elle à sa valeur finale `Y` ?

Cette instrumentation peut révéler ou réfuter une structure descriptive. Elle ne constitue pas, par elle-même, une faiblesse de SHA-256 ni une preuve cryptanalytique.

## Unités et seuil

- `J` est un contexte Stratum réel archivé.
- `e` est un `extranonce2` fixé.
- `n` est le nonce Bitcoin `uint32`.
- `BJE = B(J,e)` fixe les 76 premiers octets du header et couvre exactement les `2^32` nonces.
- `BJEN = B(J,e,n)` est le header Bitcoin complet de 80 octets.
- `Y` est l'entier PoW canonique big-endian déjà représenté par `header_space::PowValue`; une valeur plus petite est meilleure.
- `T20` est le prédicat strict `Y < 2^236`, soit au moins 20 bits de tête nuls dans cette représentation.

Un hash uniforme passe T20 avec probabilité `2^-20`. Un BJE complet contient donc en moyenne `2^32 / 2^20 = 4096` hits. C'est une espérance binomiale, jamais une cardinalité exigée.

## Capture sparse CPU/GPU

Le comportement historique de `GpuScanner::scan()` est inchangé. La nouvelle API opt-in `scan_sparse_hits()` lance un kernel distinct : chaque nonce de la plage appartient à exactement un stride de work-item, le SHA256d est comparé au seuil canonique et seul le nonce `uint32` d'un hit est ajouté au buffer. Aucun digest de 32 octets n'est transféré par hash.

Le compteur atomique mesure tous les hits, y compris au-delà de la capacité. Le résultat expose le total, le nombre réellement capturé et le drapeau d'overflow. Une capture en overflow est refusée et le BJE est rescanné avec une capacité doublée jusqu'à obtenir tous les hits. La capacité initiale de production est 8192.

Après le GPU, le CPU trie les nonces numériquement, refuse les doublons, recalcule chaque SHA256d, revérifie T20 et reconstruit `Y`. Une campagne scientifique garde T20 fixe; les seuils T8/T10 ne sont accessibles qu'aux primitives internes et au smoke test.

## Artefacts, atomicité et reprise

Une campagne vit sous `results/trajectory_analysis/traj_...` et contient `manifest.json`, `checkpoint.json`, `capture_summary.json`, `audit.json`, `report.md` et `captures/`.

Pour chaque BJE :

- `<block_id>.t20.bin` contient exclusivement des records `uint32` little-endian, triés par nonce numérique croissant et jamais par `Y`;
- `<block_id>.json` contient le contexte figé, le device, les temps, le débit, le nombre T20 observé, le z-score descriptif, la capacité, les retries, la vérification CPU et le SHA-256 du binaire.

L'écriture utilise un fichier temporaire puis un renommage atomique; le JSON final et le checkpoint ne sont écrits qu'après la vérification. Une reprise recalcule le checksum et valide la structure. Un BJE valide et complet n'est jamais rescanné. Un artefact incomplet ou corrompu est conservé sous un suffixe `.invalid...` avant une nouvelle capture.

Le manifeste fige la sélection exacte des contextes, extranonce2, préfixes de header, block IDs et partitions, ainsi que les checksums de l'archive et du kernel. Une modification ultérieure de l'archive ne change donc pas une reprise.

## Sélection et partitions

La sélection est déterministe pour un seed donné et n'utilise aucune mesure POST_SCAN antérieure. Elle vise environ huit prevhash pour 16 BJE (deux BJE par groupe), puis environ huit BJE par prevhash pour les grandes campagnes; 512 BJE visent ainsi environ 64 prevhash et 1024 en visent davantage. Si l'archive limite la diversité, le N exact est réparti équitablement avec un avertissement. Les contextes d'un prevhash sont équilibrés et leurs extranonce2 sont échantillonnés par la méthode déterministe stratifiée existante.

Les prevhash complets sont assignés à `discovery / validation / holdout` avec cibles `50 / 25 / 25`. Un prevhash ne traverse jamais deux partitions. La capture brute est permise partout, mais l'analyse, les exports Y et les traces détaillées sont discovery-only. Validation et holdout restent scellés; aucun classement Y pratique n'y est produit.

## Tri Y, contrôles et ordre des entrées

Pour chaque BJE discovery, le CPU reconstruit tous les `Y` T20 et les trie numériquement croissants, avec nonce croissant comme tie-break. Les cohortes sont :

- `EXTREME` : rangs 1 à 16;
- `VERY_GOOD` : rangs 17 à 64;
- `GOOD` : rangs 65 à 256;
- `T20_CONTROL` : 256 rangs sans remplacement, déterministes, tirés à partir du rang 257;
- `RANDOM_CONTROL` : 256 nonces uniques du même BJE, déterministes et vérifiés non-T20.

Le total cible est 768 BJEN par BJE. Une cardinalité T20 insuffisante est signalée et le BJE est adapté ou exclu; aucun rang n'est inventé. `selected_bjen.csv` est le seul inventaire compact des spécimens rejoués. Le CSV complet d'un BJE n'est produit qu'à la demande.

L'analyse Y-order emploie tous les T20 du BJE et mesure, entre voisins de rang, la distance absolue, la distance circulaire uint32, le popcount XOR, les préfixes/suffixes communs et le Spearman rang-Y/nonce. Deux cents permutations déterministes intra-BJE donnent le contrôle nul. Les BJE sont ensuite agrégés dans leur prevhash et le prevhash est l'unité forte de bootstrap.

## Replay et features de trajectoire

`trace_reduced_sha256d(header, 64)` doit reproduire le SHA256d production et exactement 192 rounds globaux :

- `0..63` : premier SHA-256, compression 0;
- `64..127` : premier SHA-256, compression 1;
- `128..191` : second SHA-256, compression 0.

Chaque round conserve également `sha_pass`, `compression_index` et `local_round`. L'extracteur compact reste en mémoire et décrit les états `a..h` avant round, `W`, `Sigma0`, `Sigma1`, `Ch`, `Maj`, `T1`, `T2` par valeur normalisée, popcount et transitions de bits. Il reconstruit les carries exacts de `T1`, `T2`, `new_e` et `new_a` par colonnes entières : nombre de colonnes, chaîne maximale, nombre de chaînes et popcount du masque.

Les contrastes round-by-round utilisent le rank-biserial avec ties et la distance KS pour cinq comparaisons. Les effets BJE sont moyennés dans chaque prevhash puis résumés avec IC bootstrap 95 % par prevhash. `round_max_effect_descriptive.csv` est explicitement multiple-looks, non ajusté et non probant. Aucun modèle complexe n'est entraîné.

## Commandes

```text
sha256_context_analyzer.exe trajectory-new --bje 16 [--seed S] [--yes]
sha256_context_analyzer.exe trajectory-resume [--campaign <dir>]
sha256_context_analyzer.exe trajectory-analyze --campaign <dir>
sha256_context_analyzer.exe trajectory-export-bje --campaign <dir> --block-id <id>
sha256_context_analyzer.exe trajectory-trace --campaign <dir> --block-id <id> --nonce N
sha256_context_analyzer.exe trajectory-smoke
```

`trajectory-new` affiche avant confirmation le N exact, les diversités et min/max, `N × 2^32`, les estimations temps/disque, le seed, le device, T20 et les partitions. `trajectory-export-bje` écrit à la demande `rank, nonce, nonce_hex, Y_hex, leading_zero_bits, quality_bits`. `trajectory-trace` produit dans un nouveau sous-dossier non écrasable l'artefact white-box exhaustif habituel d'un BJEN discovery.

L'option 11 de `05_ANALYSEUR_CONTEXTE.bat` lance la création Phase 3 avec 16 BJE par défaut. L'option 12 reprend la dernière campagne Phase 3 incomplète.

`trajectory-smoke` utilise une plage réduite et T10, compare exactement les ensembles CPU/GPU quand OpenCL est disponible, revérifie les `Y` et le mapping des 192 rounds. Il annonce toujours `scientific_ground_truth = false` et ne remplace jamais un BJE complet.
