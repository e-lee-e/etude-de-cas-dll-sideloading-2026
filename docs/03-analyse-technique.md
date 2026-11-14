# Analyse technique

Deux implants distincts, installés à vingt heures d'écart. Tous deux font exécuter du code malveillant par un programme légitime, ce qui explique l'absence de détection par Microsoft Defender (actif, à jour, sans exclusion).

| | Implant 1 | Implant 2 |
| --- | --- | --- |
| Installé | J à 21:09:07 | J+1 à 17:09:58 |
| Emplacement | `%APPDATA%\NonceChange` | `C:\intel`, copie cachée dans `%APPDATA%\GPU-Z\Logs` |
| Installeur | `IMAGE_JJMMAAAA.PIF`, puis `test.png` (MSI) | `C:\hp\install.vbs` |
| Persistance | Clé Run `SearchDirectory` et faux protocole `SearchDirectory://` | Tâche planifiée `GPUZLogAutoSave`, chaque minute |
| Exécution | `rundll32 /sta {CLSID}` charge `Fire.ocx` | `TexturePackerGUI.exe` (signé) charge `TexturePackerLib.dll` (non signée) |
| Processus final | `clspack.exe` dans `%APPDATA%\Microsoft` | `TexturePackerGUI.exe` |
| Serveur contacté | `pdf-viewer.top` (144.48.61.40), port 6700 | 67.43.50.11, port 12584 |

## Implant 1

### Installation

`IMAGE_JJMMAAAA.PIF` dépose `test.png` dans `%APPDATA%` et le fait installer par Windows Installer. Le fichier est un paquet MSI, pas une image. Il crée le dossier `NonceChange` :

| Fichier | Nature |
| --- | --- |
| `wuacult.wsf` | Script d'installation. Le nom imite `wuauclt`, le client Windows Update |
| `filetext.txt` | Modèle de fichier `.reg` déclarant une classe COM « Pure.Fire » |
| `Fire.ocx`, `Cloud.ocx`, `Swap.dll` | Bibliothèques non signées |
| `clspack.exe`, `newdev.exe` | Exécutables non signés, datés de 1998 et 2021 |
| `certificate.cer` | 23 Mo. Pas un certificat : en-tête d'exécutable Windows masqué par un encodage simple |

Le script `wuacult.wsf` :

1. copie les fichiers dans `%APPDATA%\NonceChange` et `clspack.exe` dans `%APPDATA%\Microsoft` ;
2. réécrit le fichier `.reg` avec le chemin complet de `Fire.ocx` ;
3. importe ce fichier dans le registre de l'utilisateur ;
4. lance `C:\Windows\SysWOW64\rundll32.exe /sta {7F222C4E-56B0-4E46-8359-E24FE3A4B975}`.

### Persistance

C'est le point le plus instructif de l'incident.

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
    SearchDirectory = explorer.exe "SearchDirectory://Newest"

HKCU\Software\Classes\SearchDirectory\shell\open\command
    (défaut) = C:\Windows\SysWOW64\rundll32.exe /sta {7F222C4E-56B0-4E46-8359-E24FE3A4B975}

HKCU\Software\Classes\WOW6432Node\CLSID\{7F222C4E-56B0-4E46-8359-E24FE3A4B975}\InprocServer32
    (défaut) = %APPDATA%\NonceChange\Fire.ocx
```

À l'ouverture de session, la clé Run appelle `explorer.exe`, qui ouvre un protocole inventé pour l'occasion, dont le gestionnaire lance `rundll32` sur une classe COM déclarée au niveau de l'utilisateur. Aucun de ces trois maillons ne nomme un fichier suspect :

- un outil qui vérifie la signature de la cible de la clé Run voit `explorer.exe`, signé Microsoft ;
- `rundll32` lancé avec un CLSID ne montre aucun chemin de DLL dans sa ligne de commande ;
- tout se passe dans `HKCU`, sans droits administrateur.

Le journal `Microsoft-Windows-Shell-Core/Operational` (événements 9707 et 9708) enregistre chaque commande lancée par les clés Run. C'est lui qui a permis de relier la clé aux exécutions.

### Charge utile

Le processus final, `clspack.exe`, ne charge aucun module hors de Windows et tente de joindre `pdf-viewer.top` sur le port 6700. À chaque exécution, un fichier `VS12-KB2961101 (N).exe` signé Microsoft apparaît dans `%TEMP%` à la même seconde, probablement comme hôte d'injection. Cette hypothèse n'a pas été vérifiée.

## Implant 2

`C:\intel` contient `TexturePackerGUI.exe`, signé par son éditeur légitime, entouré de bibliothèques signées (`rtl370.bpl`, `cc64370mt.dll`, `borlndmm.dll`, `vcruntime140*.dll`) et d'une `TexturePackerLib.dll` non signée. La liste des modules chargés par le processus confirme que cette DLL est bien chargée.

La tâche `GPUZLogAutoSave`, dont l'auteur déclaré est « TechPowerUp », relance l'exécutable toutes les minutes. Un second jeu de fichiers, aux attributs caché et système, se trouve dans `%APPDATA%\GPU-Z\Logs`, où l'exécutable est renommé `GPU-Z.exe`.

Le couple TexturePacker signé et `TexturePackerLib.dll` malveillante est décrit dans une [analyse publique de CyCraft](https://www.cycraft.com/en/post/cpe-manipulation-en-20251104). Le lien avec cet incident n'est pas établi.

## Vol de données

À J+2, à 10:02 et 10:03, quarante minutes après une exécution de l'implant 1, Brave et Edge ont été lancés sur des profils créés dans `%TEMP%` sous le nom `dotnet_perf_<nombre>`. Plusieurs profils de ce type ont été retrouvés.

Lancer un navigateur sur un profil jetable au nom trompeur est un procédé connu d'extraction des cookies et des mots de passe. Aucune preuve directe d'exfiltration n'a été relevée. Elle doit être tenue pour acquise.

## Ce qui n'a pas été établi

- La famille du logiciel malveillant et la fonction exacte de chaque fichier.
- L'expéditeur et le canal de livraison du fichier `.pif`. Aucun navigateur n'en garde trace, ce qui oriente vers une messagerie.
- Le contenu de `C:\hp\install.vbs`.
- La raison du réenregistrement de la tâche à J+2, 22:32:05.
