# Chronologie

Durée d'exposition : de J 21h08 à J+4 10h59, soit environ trois jours et demi. J désigne le jour de l'infection ; les dates réelles ont été retirées. Les heures viennent des journaux Windows, du Prefetch et des dates de création des fichiers.

| Jour et heure | Événement | Source |
| --- | --- | --- |
| J 21:08:29 | Exécution de `IMAGE_JJMMAAAA.PIF` (le nom contient la date du jour), un programme déguisé en image | Prefetch |
| J 21:09:03 | Création de `test.png` (10 Mo) et `image.png` dans `%APPDATA%` | Système de fichiers |
| J 21:09:04 | Windows Installer installe `test.png`, en réalité un paquet MSI nommé « Safe® Softwares » | Journal Application, 1040 |
| J 21:09:07 | Création de `%APPDATA%\NonceChange` : implant 1 installé | Système de fichiers |
| J 21:09:41 | Première exécution : `rundll32.exe` plante sur `Cloud.ocx` | Journal Application, 1000 |
| J 21:09:47 | L'installation MSI se termine en erreur 1603, charge déjà déposée | Journal Application, 1033 |
| J+1 17:09:54 | Création de `C:\hp\install.vbs`, installeur de l'implant 2 | Système de fichiers |
| J+1 17:09:58 | Création de `C:\intel` | Système de fichiers |
| J+1 17:10:01 | Création de la tâche `GPUZLogAutoSave`, répétée chaque minute | Fichier de tâche |
| J+2 09:19:13 | Ouverture de session : la clé Run lance `explorer.exe "SearchDirectory://Newest"` | Shell-Core, 9707 |
| J+2 09:20:10 | Implant 1 relancé | Journal Application |
| J+2 10:02 | Brave et Edge lancés sur des profils temporaires `dotnet_perf_*` | Système de fichiers |
| J+2 20:22:22 | Ouverture de session : même commande, implant 1 relancé à 20:23:01 | Shell-Core, 9707 |
| J+2 22:35:03 | Ouverture de session : même commande ; `clspack.exe` démarre à 22:35:38 et reste actif | Shell-Core, processus |
| J+3 12:03 | Premier rapport d'inventaire (`AnalysePC.ps1`) | |
| J+4 10:58:15 | `clspack.exe` tente encore de joindre son serveur | Connexions TCP |
| J+4 10:59 | Première neutralisation | |
| J+4 12:03 | Seconde neutralisation | |

Chaque exécution de l'implant 1 laisse la même trace : un plantage de `rundll32.exe` sur `Cloud.ocx` et, à la même seconde, un nouveau fichier `VS12-KB2961101 (N).exe` signé Microsoft dans `%TEMP%`.
