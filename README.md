<!--README.md-->
# sha256_research_miner

Mineur et laboratoire SHA-256d C++20 pour Windows 11, VS Code, Solo CKPool et GPU AMD/OpenCL. Le dépôt sépare strictement le travail live, les scans historiques et les expériences reduced-rounds.

> Un CPU ou un GPU grand public n'est pas compétitif avec un ASIC Bitcoin. Ce projet vise la recherche, la validation du chemin Stratum et l'expérimentation reproductible. Il ne garantit aucun revenu.

## Ce qui est implémenté

- Stratum V1 TCP: `mining.subscribe`, `mining.authorize`, `mining.set_difficulty`, `mining.notify`, `client.show_message`, réponses JSON-RPC et `mining.submit`.
- Réception continue des jobs, reconnexion, arrêt rapide par génération atomique et distinction nouveau `prevhash` / mise à jour du job.
- Construction coinbase, racine Merkle et header Bitcoin 80 octets avec conversions d'endianness testées.
- SHA-256 de référence, SHA256d et SHA-256 à N rondes par compression; N=64 est identique à la référence.
- Cible réseau exacte depuis `nBits`, cible de share depuis la difficulté et comparaison uint256 complète.
- 30 workers CPU par défaut, plages disjointes et aucun mutex/allocation/sortie console par hash.
- Backend OpenCL optionnel: détection GPU, préférence AMD, informations matériel/pilote, auto-tuning de local/global/batch et profil persistant.
- Extranonce2 distincts CPU/GPU quand la taille annoncée le permet; sinon plages de nonce disjointes.
- Checkpoints atomiques sérialisés, reprise du `nonce_next` durable et états `PENDING`, `IN_PROGRESS`, `COMPLETE`, `STALE`.
- Sauvegarde prioritaire d'un candidat réseau avant sa soumission, puis mise à jour atomique avec la réponse CKPool.
- Audit durable `share_audit_*.json` de chaque share, avec le job complet, le header reconstructible, le nonce numérique/Stratum/header et la réponse exacte.
- Modes `benchmark`, `historical_test`, `research` et `mock_stratum`, sans connexion ni soumission CKPool dans les modes hors ligne.
- Télémétrie agrégée une fois par seconde et événements critiques immédiats.
- Tests Genesis, vecteurs SHA, Merkle, cibles, endianness, parser Stratum, checkpoint, allocateur et chaîne mock complète.
- Validation OpenCL/CPU bit à bit sur 4 096 headers lorsque OpenCL est disponible.

## Prérequis Windows 11

1. Installer **Visual Studio 2022 ou plus récent** avec la charge de travail « Développement Desktop en C++ », le SDK Windows 11, CMake et Ninja; Visual Studio 2026 est pris en charge.
2. Installer [Visual Studio Code](https://code.visualstudio.com/) et accepter les extensions recommandées `C/C++` et `CMake Tools`.
3. Pour AMD/OpenCL:
   - installer le pilote AMD Adrenalin récent, qui fournit le runtime `OpenCL.dll`;
   - installer les headers/import libraries OpenCL (par exemple `vcpkg install opencl:x64-windows`) ou le [Khronos OpenCL SDK](https://github.com/KhronosGroup/OpenCL-SDK).
4. Une connexion Internet est requise au premier `cmake` si `nlohmann/json` et Asio ne sont pas déjà installés; CMake télécharge leurs versions épinglées.

Sans SDK OpenCL, CMake construit automatiquement le backend CPU et affiche un message explicite. Une panne GPU en exécution ne coupe pas le CPU.

## Construire dans VS Code

Ouvrir le dossier du dépôt, choisir le preset `windows-release`, puis utiliser `Ctrl+Shift+B`. En terminal PowerShell:

```powershell
cmake --preset windows-release
cmake --build --preset windows-release
ctest --preset windows-release
```

Construction CPU seulement:

```powershell
cmake --preset windows-cpu-only
cmake --build --preset windows-cpu-only
```

L'exécutable se trouve sous `build/windows-release/Release/sha256_research_miner.exe` avec Visual Studio.

## Configuration et sécurité des modes

Tout passe par JSON; aucune constante du code n'est à modifier.

- `config/miner.json`: live CKPool.
- `config/benchmark.json`: benchmark SHA256d CPU/OpenCL strictement hors ligne.
- `config/research.json`: scan historique Genesis court et reproductible.
- `config/reduced_rounds.json`: laboratoire N=1..64.
- `config/mock.json`: test Stratum local; aucune connexion à CKPool.

Le mode live refuse de démarrer tant que `ckpool.username` vaut `CHANGE_ME`. Remplacer cette valeur par `ADRESSE_BITCOIN[.worker]`. Le password par défaut est `x`.

Les champs `historical` ne sont jamais consultés en live. Les modes `historical_test` et `research` ne créent aucun client réseau. `mock_stratum` utilise uniquement l'endpoint explicitement configuré, ici `127.0.0.1:3334`.

## Benchmark SHA256d hors ligne

Le benchmark utilise le vrai SHA256d CPU et le noyau `kernels/sha256d.cl`. Il énumère tous les GPU OpenCL, valide 4 096 résultats GPU contre le CPU, puis mesure séparément les threads CPU et une grille GPU bornée. Par défaut, chaque configuration reçoit 250 ms d'échauffement puis 1 000 ms de mesure: la fenêtre réduit le bruit tout en gardant l'exécution complète raisonnable.

```powershell
build\windows-release\Release\sha256_research_miner.exe --config config\benchmark.json
```

`gpu.platform` et `gpu.device` acceptent `auto`, `index:N` ou un nom exact/non ambigu. Sur cette machine, `platform: "index:0"` et `device: "AMD Radeon RX 7900 XTX"` distinguent la carte dédiée du GPU intégré, même lorsque le runtime expose seulement le nom technique `gfx1100`. Le meilleur profil est remplacé atomiquement dans `config/performance_profile.json`. Le benchmark combiné CPU+GPU n'est pas mesuré: les résultats individuels restent comparables et aucune duplication de plage n'est introduite.

Valider un fichier sans lancer le mineur:

```powershell
build\windows-release\Release\sha256_research_miner.exe --config config\miner.json --check-config
```

## Test Genesis historique

`config/research.json` contient le header Genesis et une petite plage englobant le nonce `2083236893`:

```powershell
build\windows-release\Release\sha256_research_miner.exe --config config\research.json
```

Hash attendu:

```text
000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
```

Pour scanner 2^32 nonces, mettre `scan_full_nonce_space` à `true`. Le programme ne saute pas directement au `known_nonce`; cette valeur sert uniquement à valider le vecteur avant le scan.

## Laboratoire reduced-rounds

```powershell
build\windows-release\Release\sha256_research_miner.exe --config config\reduced_rounds.json
```

Pour chaque compression SHA-256, seules les N premières rondes sont exécutées. Les résultats `results/research_round_N.json` contiennent compteurs de bits, distance de Hamming moyenne, meilleur hash et nonce associé. Les agrégats sont sauvegardés par round; le noyau `kernels/reduced_sha256.cl` fournit le chemin d'agrégation GPU sans transfert de tous les états.

Le reduced-round SHA-256 n'est référencé par aucun chemin du mode live.

## Trace white-box Genesis

L'exécutable de recherche autonome `sha256_whitebox` construit une trace strictement
forward du header Genesis à travers les trois compressions de SHA256d. Il enregistre
les 192 rounds, les trois schedules complets, le padding, les opérations bitwise,
les colonnes de carry entières, les projections modulo 2^k et les feed-forwards.
La génération s'arrête en erreur si le hash Bitcoin final n'est pas le vecteur
Genesis connu.

```powershell
build\windows-release\Release\sha256_whitebox.exe --output-dir results\whitebox
```

Les sorties déterministes sont
`results/whitebox/genesis_sha256d_whitebox.json` et
`results/whitebox/genesis_sha256d_whitebox_summary.md`. Cette instrumentation
réutilise la trace CPU existante à 64 rounds, mais reste hors du mineur live et des
noyaux OpenCL.

## Cartographie GPU d'un header-space

L'exécutable research indépendant `sha256_header_space` cartographie exactement une plage de nonces d'un header fixe. Il produit un minimum 256 bits et les compteurs T8, T12, T16, T20, T24, T28 et T32 par zone, sans sauvegarder les hashes individuels et sans utiliser le chemin du mineur live.

Validation Genesis CPU/GPU sur `2^20` nonces:

```powershell
build\windows-release\Release\sha256_header_space.exe --preset genesis --nonce-count 1048576 --cpu-verify-count 1048576
```

Un full-space utilise `--full-space`; la zone scientifique par défaut vaut `2^20`. Les sorties déterministes sont placées sous `results/header_space/<experiment_id>/`. L'architecture, l'endianness PoW, le CLI complet, les sorties et les limites de reprise sont documentés dans [docs/header_space_scanner.md](docs/header_space_scanner.md).

## Test Stratum bout en bout

Le test automatisé lance le serveur local, s'abonne, autorise le worker, envoie une difficulté facile, mine, reconstruit indépendamment le header depuis les cinq paramètres soumis, vérifie le nonce/target, traite une réponse acceptée puis une réponse rejetée dans les bons audits, et remplace le job avec `clean_jobs=true`. Il maintient aussi un verrou volontaire sur le `.tmp` du checkpoint afin de prouver qu'une erreur de persistance ne coupe pas Stratum:

```powershell
ctest --preset windows-release -R mock_stratum_end_to_end
```

Exécution manuelle dans deux terminaux:

```powershell
build\windows-release\Release\mock_stratum_server.exe 3334
build\windows-release\Release\sha256_research_miner.exe --config config\mock.json
```

## Live Solo CKPool

Après avoir renseigné l'adresse dans `config/miner.json`:

```powershell
build\windows-release\Release\sha256_research_miner.exe --config config\miner.json
```

Endpoint par défaut: `stratum.ckpool.org:3333`. À chaque solution, seuls les cinq paramètres Stratum standards sont envoyés: username, job_id, extranonce2, ntime et nonce. Le nonce soumis est le `uint32` formaté en huit chiffres hexadécimaux (`c2608b15`), tandis que ses octets dans le header restent little-endian (`158b60c2`). CKPool reste responsable de la validation et de la propagation.

## Checkpoints et reprise

Les fichiers sont dans `state/`:

```text
state/live_state.json
state/research_state.json
state/gpu_profile.json
```

Une sauvegarde écrit `state.json.tmp`, flush les données, puis utilise un remplacement atomique avec write-through sous Windows. Les checkpoints d'un même allocateur sont sérialisés. Sous Windows, les verrouillages transitoires `ERROR_SHARING_VIOLATION` et `ERROR_ACCESS_DENIED` sont retentés quatre fois avec un backoff total borné à 85 ms. Il n'y a aucune écriture par hash. Les workers publient leur curseur en mémoire par lots; le thread de checkpoint le rend durable périodiquement et lors d'un arrêt propre.

- Un arrêt propre reprend exactement au `nonce_next` sauvegardé.
- Après une coupure brutale, le dernier checkpoint atomique valide est repris; seul le travail postérieur non durable du batch courant peut être rejoué.
- Une unité `COMPLETE` n'est jamais réattribuée.
- Après reconnexion live, `job_id`, `prevhash`, `extranonce1` et `extranonce2_size` doivent tous correspondre pour autoriser la reprise.
- En `live`/`mock_stratum`, un fingerprint incompatible remplace les anciennes unités: le checkpoint est l'état de reprise du seul travail courant, pas un historique. Avec un `extranonce2`, les unités `COMPLETE` sont aussi retirées dès que `next_extranonce2_counter` garantit qu'elles ne seront jamais réallouées; sans extranonce, elles restent nécessaires et sont conservées. `hashes_tested`, `completed_ranges` et le meilleur hash de l'allocateur décrivent donc seulement les unités de reprise retenues pour le fingerprint courant; les compteurs de télémétrie cumulatifs restent conservés séparément.
- Dans les modes historiques/recherche, la politique d'unités existante reste inchangée. Un `clean_jobs=true` invalide immédiatement le travail live actif avant sa compaction au lancement du nouveau job.
- Quand un espace 2^32 est terminé, l'allocateur réserve atomiquement un nouvel extranonce2 sans duplication CPU/GPU.

Cette distinction est nécessaire: garantir zéro rejeu après une perte de courant exigerait une écriture durable par nonce, ce qui contredirait l'interdiction d'écrire à chaque hash.

## Résultats et arrêt

Les candidats réseau sont toujours écrits dans `results/block_candidate_YYYYMMDD_HHMMSS_mmm.json`. En plus, chaque share live est écrite dans `results/share_audit_YYYYMMDD_HHMMSS_mmm.json` avant `mining.submit`, puis mise à jour atomiquement avec son identifiant, son statut, la réponse JSON-RPC exacte et sa latence. `logging.save_share_audits` contrôle ces audits et vaut `true` par défaut. Aucun mot de passe n'est sérialisé.

Arrêter avec `Ctrl+C`. Le contrôleur invalide la génération, rejoint CPU/GPU et écrit un dernier checkpoint.

## Structure

```text
include/     interfaces modulaires
src/         implémentations C++20
kernels/     SHA256d, cartographie header-space et agrégats reduced-round OpenCL
docs/        protocoles et architecture des expériences isolées
config/      modes JSON
state/       checkpoints locaux
tests/       références, mock Stratum et intégration
results/     journaux et candidats (ignorés par Git)
```

La CI GitHub compile et exécute les tests CPU + mock sur `windows-latest`. Le test GPU s'active automatiquement sur une machine possédant le SDK et un périphérique OpenCL.
