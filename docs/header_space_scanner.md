<!--docs\header_space_scanner.md-->
# Cartographe GPU exact d'un header-space

`sha256_header_space` est un outil de recherche hors ligne indépendant du mineur live. Il fixe les 76 premiers octets d'un header Bitcoin, parcourt une plage exacte de nonces `uint32` et ne conserve que des statistiques agrégées. Aucun hash individuel n'est écrit.

## Définition et endianness

Le `pow_value` est le digest SHA256d brut interprété comme un entier `uint256` little-endian, conformément à la comparaison Proof of Work de Bitcoin. Son écriture hexadécimale big-endian est identique au hash Bitcoin affiché, c'est-à-dire aux 32 octets du digest brut inversés. Les minima sont comparés sur les 256 bits complets; une égalité choisit le plus petit nonce.

Le nonce numérique est sérialisé little-endian aux octets 76 à 79. Le vecteur Genesis vérifie au démarrage le header, les octets `1d ac 2b 7c`, le hash affiché connu et `pow_value <= target(0x1d00ffff)`.

## Architecture GPU

Un workgroup possède exactement une zone statistique. Chaque work-item calcule une sous-suite disjointe de nonces, conserve son minimum 256 bits, sept compteurs de queue 64 bits et le compteur exact sous la target réseau, puis le workgroup effectue une réduction en mémoire locale. Une seule fiche compacte par zone est copiée vers le CPU. Il n'y a ni atomic globale par hash, ni transfert de digest par nonce.

La taille de zone statistique (`--zone-size`, `2^20` par défaut) est indépendante du batch GPU (`--batch-zones`, 256 par défaut). Avec `--local-size 64`, un batch plein de 256 zones utilise un global size de 16 384 work-items. Le découpage en batches borne la durée d'un kernel sous Windows sans changer la carte produite.

`zone_index` vaut toujours `floor(nonce / zone_size)`. Il ne dépend ni du header ni du début d'un scan partiel. Les zones de bord d'une plage partielle peuvent donc être partielles. Des cartes plus grossières se construisent sans rescanner en additionnant les compteurs de zones adjacentes et en sélectionnant leur minimum exact avec le même tie-break.

## Utilisation

Depuis la racine du dépôt:

```powershell
build\windows-release\Release\sha256_header_space.exe `
  --preset genesis `
  --nonce-start 0 `
  --nonce-count 1048576 `
  --zone-size 1048576 `
  --device "AMD Radeon RX 7900 XTX" `
  --local-size 64
```

Scan complet exact:

```powershell
build\windows-release\Release\sha256_header_space.exe `
  --preset genesis `
  --full-space `
  --zone-size 1048576 `
  --device "AMD Radeon RX 7900 XTX" `
  --local-size 64
```

Une entrée personnalisée utilise `--header-hex` avec exactement 160 caractères hexadécimaux représentant les 80 octets sérialisés. Le nonce fourni dans ces 80 octets est ignoré: les 76 premiers octets définissent l'espace et l'outil fixe le nonce selon la plage CLI.

`--cpu-verify-count` vaut 65 536 par défaut. L'outil compare exactement CPU et GPU sur cette sous-plage avant un grand scan. Pour une validation complète de `2^20`, utiliser `--nonce-count 1048576 --cpu-verify-count 1048576`.

## Sorties et reprise

Par défaut, les sorties sont:

```text
results\header_space\<experiment_id>\summary.json
results\header_space\<experiment_id>\zones.csv
```

`space_id` est le SHA-256 complet du préfixe de 76 octets. `experiment_id` ajoute la plage et la taille de zone, ce qui évite qu'un scan partiel écrase un full-space. `--output-prefix` change la racine du dossier. Les fichiers sont écrits via un fichier temporaire et `summary.json` portant `status=COMPLETE` est publié après `zones.csv`.

La première version ne reprend pas un espace incomplet à l'intérieur d'une exécution. Un résultat terminé est toutefois durable avant qu'une future campagne ne passe à l'espace suivant. L'option `--overwrite` est nécessaire pour remplacer le même résultat déterministe.

## Protocole scientifique

Le scanner mesure; il ne qualifie aucune zone de « favorable » et ne fait aucune conclusion cryptanalytique. Les seuils T26, T28, T30, T32, T34, T36 et T38 correspondent, pour un bloc complet, à environ 64, 16, 4, 1, 1/4, 1/16 et 1/64 hits attendus. Les histogrammes complets de leading zeros et de préfixes 8 bits restent reportés pour préserver une réduction légère sans atomics globaux par hash.

Toute campagne multi-header future doit séparer les espaces en ensembles `DISCOVERY` et `HOLDOUT` avant analyse. Une règle issue de `DISCOVERY` doit être gelée avant l'ouverture de `HOLDOUT`. Les comparaisons de milliers de zones, plusieurs seuils et plusieurs headers exigent aussi une correction explicite des tests multiples.
