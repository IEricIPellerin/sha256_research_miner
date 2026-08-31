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
- Checkpoints atomiques, reprise du `nonce_next` durable et états `PENDING`, `IN_PROGRESS`, `COMPLETE`, `STALE`.
- Sauvegarde prioritaire d'un candidat réseau avant sa soumission, puis mise à jour atomique avec la réponse CKPool.
- Modes `historical_test`, `research` et `mock_stratum`, sans connexion ni soumission CKPool dans les modes hors ligne.
- Télémétrie agrégée une fois par seconde et événements critiques immédiats.
- Tests Genesis, vecteurs SHA, Merkle, cibles, endianness, parser Stratum, checkpoint, allocateur et chaîne mock complète.
- Validation OpenCL/CPU bit à bit sur 4 096 headers lorsque OpenCL est disponible.

## Prérequis Windows 11

1. Installer **Visual Studio 2022 Build Tools** avec la charge de travail « Développement Desktop en C++ », le SDK Windows 11 et CMake; Visual Studio Community convient aussi.
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
- `config/research.json`: scan historique Genesis court et reproductible.
- `config/reduced_rounds.json`: laboratoire N=1..64.
- `config/mock.json`: test Stratum local; aucune connexion à CKPool.

Le mode live refuse de démarrer tant que `ckpool.username` vaut `CHANGE_ME`. Remplacer cette valeur par `ADRESSE_BITCOIN[.worker]`. Le password par défaut est `x`.

Les champs `historical` ne sont jamais consultés en live. Les modes `historical_test` et `research` ne créent aucun client réseau. `mock_stratum` utilise uniquement l'endpoint explicitement configuré, ici `127.0.0.1:3334`.

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

## Test Stratum bout en bout

Le test automatisé lance le serveur local, s'abonne, autorise le worker, envoie une difficulté facile, mine, sauvegarde le JSON, soumet, reçoit `accepted`, puis remplace le job avec `clean_jobs=true`:

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

Endpoint par défaut: `stratum.ckpool.org:3333`. À chaque solution, seuls les cinq paramètres Stratum standards sont envoyés: username, job_id, extranonce2, ntime et nonce. CKPool reste responsable de la validation et de la propagation.

## Checkpoints et reprise

Les fichiers sont dans `state/`:

```text
state/live_state.json
state/research_state.json
state/gpu_profile.json
```

Une sauvegarde écrit `state.json.tmp`, ferme et flush le flux, puis utilise un remplacement atomique avec write-through sous Windows. Il n'y a aucune écriture par hash. Les workers publient leur curseur en mémoire par lots; le thread de checkpoint le rend durable périodiquement et lors d'un arrêt propre.

- Un arrêt propre reprend exactement au `nonce_next` sauvegardé.
- Après une coupure brutale, le dernier checkpoint atomique valide est repris; seul le travail postérieur non durable du batch courant peut être rejoué.
- Une unité `COMPLETE` n'est jamais réattribuée.
- Après reconnexion live, `job_id`, `prevhash`, `extranonce1` et `extranonce2_size` doivent tous correspondre pour autoriser la reprise.
- Un job incompatible devient `STALE`; un `clean_jobs=true` invalide immédiatement toutes les unités actives.
- Quand un espace 2^32 est terminé, l'allocateur réserve atomiquement un nouvel extranonce2 sans duplication CPU/GPU.

Cette distinction est nécessaire: garantir zéro rejeu après une perte de courant exigerait une écriture durable par nonce, ce qui contredirait l'interdiction d'écrire à chaque hash.

## Résultats et arrêt

Les candidats sont écrits dans `results/block_candidate_YYYYMMDD_HHMMSS_mmm.json`. Les noms sont sérialisés pour éviter toute collision entre workers. Le fichier initial est durable avant `mining.submit`; la réponse, la latence et le statut sont ensuite ajoutés par remplacement atomique.

Arrêter avec `Ctrl+C`. Le contrôleur invalide la génération, rejoint CPU/GPU et écrit un dernier checkpoint.

## Structure

```text
include/     interfaces modulaires
src/         implémentations C++20
kernels/     SHA256d et agrégats reduced-round OpenCL
config/      modes JSON
state/       checkpoints locaux
tests/       références, mock Stratum et intégration
results/     journaux et candidats (ignorés par Git)
```

La CI GitHub compile et exécute les tests CPU + mock sur `windows-latest`. Le test GPU s'active automatiquement sur une machine possédant le SDK et un périphérique OpenCL.

