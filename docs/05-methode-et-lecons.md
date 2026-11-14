# Méthode et leçons

## Démarche

| Étape | Outil | Résultat |
| --- | --- | --- |
| 1. Inventaire | `AnalysePC.ps1` | 8 constats « élevé », 19 « moyen », aucun « critique » |
| 2. Tri | Lecture du rapport | 6 des 8 constats « élevé » sont des faux positifs ; l'infection se trouve dans des lignes « moyen » et « pour information » |
| 3. Collecte ciblée | `Collecte_Preuves_AnalysePC.ps1` | Empreintes, tâche, processus, modules, connexions ; second serveur découvert |
| 4. Première neutralisation | option `-Neutraliser` | Tâche désactivée, processus arrêtés, fichiers en quarantaine |
| 5. Recherche de la persistance | `Recherche_Declencheur_AnalysePC.ps1` | Clé Run et faux protocole identifiés ; fichier d'origine et installeurs retrouvés |
| 6. Seconde neutralisation | option `-Neutraliser`, puis commandes manuelles | Reste des fichiers en quarantaine, clés de registre exportées puis supprimées |

Règles suivies : ne rien supprimer avant d'avoir collecté, exporter avant d'effacer, déplacer plutôt que détruire, noter chaque action avec son heure.

## Ce que l'inventaire a mal classé

Faux positifs notés « élevé » :

| Constat | Explication |
| --- | --- |
| `pagefile.sys`, `swapfile.sys`, `hiberfil.sys` « exécutables non signés et cachés » | Fichiers système de Windows |
| Entrée de démarrage Teams « non signée dans un dossier utilisateur » | Alias d'application du Store, signature illisible |
| `UIHost.exe` « imitant sihost » | Composant signé d'une extension de sécurité, dans `Program Files` |
| 25 scripts PowerShell « suspects » | Modules Storage de Microsoft |

Vrais positifs sous-classés :

| Élément | Classement | Pourquoi |
| --- | --- | --- |
| Tâche lançant `C:\intel\TexturePackerGUI.exe` chaque minute | Moyen | Exécutable signé |
| `wuacult.wsf`, `Cloud.ocx`, `Fire.ocx`, `Swap.dll` | Pour information | Listés comme « fichiers récents non signés » |
| Clé Run `SearchDirectory` | Aucun constat | Cible `explorer.exe`, signée Microsoft |
| Connexion vers une adresse IP brute sur un port non standard | Aucun constat | Listée sans alerte |

## Pistes d'amélioration pour `AnalysePC.ps1`

- **Ne pas faire de la signature le critère principal.** Le chargement de DLL détournée repose justement sur un exécutable signé. L'emplacement (`C:\intel`, `%APPDATA%`) et la fréquence (chaque minute) pèsent davantage.
- **Corréler.** Tâche récente, DLL non signée dans le même dossier, connexion vers une IP brute et plantages répétés décrivent une infection quand on les réunit.
- **Analyser les arguments des clés Run.** Un protocole (`xxx://`) passé à `explorer.exe` doit être résolu dans `HKCU\Software\Classes`.
- **Lister les classes COM et protocoles déclarés dans `HKCU`** dont la cible est hors de Windows ou non signée.
- **Alerter sur les scripts et bibliothèques récents dans `%APPDATA%`** (`.wsf`, `.vbs`, `.ocx`) et sur les noms proches d'un binaire Windows.
- **Exclure le bruit connu** : fichiers système à la racine, alias `WindowsApps`, modules PowerShell de Microsoft.
- **Exploiter le journal Shell-Core** (9707, 9708) et le Prefetch, qui ont donné ici le déclencheur et le fichier d'origine.

## Erreurs commises pendant l'intervention

- Le premier script de neutralisation ne bloquait qu'une des deux adresses : la seconde n'était pas encore connue.
- Il ne regardait que les tâches à action « Exec » et les clés Run classiques, et a donc manqué le déclencheur.
- La clé COM a d'abord été supprimée dans sa vue 64 bits seulement, alors que `rundll32` de `SysWOW64` lit la vue 32 bits (`WOW6432Node`).
- Les dossiers de quarantaine ont été placés sur un Bureau synchronisé dans le cloud. Les échantillons doivent rester hors de tout dossier synchronisé.
- Les scripts ont été transmis à la victime par une messagerie dont le compte faisait partie des comptes exposés.

## Limites

- Un seul poste, des journaux limités à quatorze jours, aucune analyse des échantillons en laboratoire.
- Le nettoyage couvre ce qui a été trouvé, pas forcément tout ce qui existe. Avec deux portes dérobées actives plus de trois jours sur un compte administrateur, seule une réinstallation apporte une garantie.
