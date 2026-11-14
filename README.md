# Étude de cas : deux portes dérobées invisibles pour l'antivirus sur un PC Windows 11

Cas d'étude inspiré d'une situation vécue avec mon colocataire. Sur son PC portable, un script d'inventaire en lecture seule a fait remonter des anomalies. L'analyse a révélé deux implants installés à vingt heures d'écart, actifs pendant trois jours et demi, et qu'aucune analyse antivirus n'avait signalés.

Ce dépôt contient les scripts utilisés, la méthode suivie, la chronologie reconstituée et les indicateurs de compromission.

> **Anonymisation.** Le nom de la personne, de son ordinateur et de son compte, ses identifiants système, ses adresses réseau locales et ses fichiers personnels ont été retirés. Les dates sont remplacées par J (jour de l'infection), J+1, J+2, etc. Aucun échantillon malveillant ni aucune collecte brute n'est publié ici.

## En deux minutes

À J, 21h08, l'utilisateur ouvre un fichier reçu comme une image. C'est un programme (`.pif`). En quarante secondes, il installe un premier implant qui se relance à chaque ouverture de session. Le lendemain, un second implant est installé par un autre script.

Les deux font exécuter leur code par des programmes légitimes et signés (chargement de DLL détournée). Microsoft Defender, actif et à jour, ne détecte rien.

À J+2, des navigateurs sont lancés en arrière-plan sur des profils temporaires au nom trompeur, procédé connu de vol de cookies et de mots de passe.

À J+4, les deux implants sont arrêtés, mis en quarantaine et coupés de leurs serveurs. Le mécanisme de relance est identifié : une clé `Run` qui appelle `explorer.exe` avec un faux protocole, donc affichée comme « signée Microsoft » par les outils d'inventaire.

## Contenu

| Fichier | Rôle |
| --- | --- |
| [docs/01-explication-simple.md](docs/01-explication-simple.md) | L'incident expliqué sans vocabulaire technique |
| [docs/02-chronologie.md](docs/02-chronologie.md) | Chronologie reconstituée, à la seconde |
| [docs/03-analyse-technique.md](docs/03-analyse-technique.md) | Les deux implants, la persistance, le vol de données |
| [docs/04-indicateurs.md](docs/04-indicateurs.md) | Empreintes, adresses, chemins, clés de registre |
| [docs/05-methode-et-lecons.md](docs/05-methode-et-lecons.md) | Démarche, faux positifs, limites des scripts |
| [scripts/AnalysePC.ps1](scripts/AnalysePC.ps1) | Inventaire de sécurité en lecture seule (rapport texte et HTML) |
| [scripts/Collecte_Preuves_AnalysePC.ps1](scripts/Collecte_Preuves_AnalysePC.ps1) | Collecte de preuves ciblée, neutralisation optionnelle |
| [scripts/Recherche_Declencheur_AnalysePC.ps1](scripts/Recherche_Declencheur_AnalysePC.ps1) | Recherche de la persistance et de l'origine |

## Les scripts

Tous se lancent dans une console PowerShell 5.1 ouverte en administrateur.

```powershell
# 1. Inventaire général (lecture seule)
powershell -ExecutionPolicy Bypass -File .\scripts\AnalysePC.ps1 -ScanDefender -VerifSysteme -Anonymiser

# 2. Collecte ciblée (lecture seule par défaut)
powershell -ExecutionPolicy Bypass -File .\scripts\Collecte_Preuves_AnalysePC.ps1

# 3. Recherche de la persistance et de l'origine (lecture seule par défaut)
powershell -ExecutionPolicy Bypass -File .\scripts\Recherche_Declencheur_AnalysePC.ps1
```

`AnalysePC.ps1` est générique. Les deux autres ont été écrits pendant l'incident : leurs indicateurs (chemins, empreintes, adresses, horaires) sont codés en dur en tête de fichier et doivent être adaptés à un autre cas. Dans la version publiée, les dates réelles sont remplacées par des dates d'exemple (J = 2026-01-01).

Avec `-Neutraliser`, les scripts 2 et 3 désactivent la tâche planifiée, arrêtent les processus, bloquent les adresses dans le pare-feu et déplacent les fichiers en quarantaine après confirmation. Rien n'est supprimé, sauf une clé de registre exportée au préalable.

## Avertissements

- Ces scripts ont servi sur un seul poste. Ils ne remplacent ni un EDR ni une analyse forensique.
- La neutralisation limite les dégâts mais ne garantit pas une machine saine. Après une compromission de ce type, la réinstallation du système et le changement de tous les mots de passe depuis un autre appareil restent nécessaires.
- La famille du logiciel malveillant n'a pas été identifiée et les échantillons n'ont pas été analysés en laboratoire.

## Licence

Code et documentation sous licence MIT. Voir [LICENSE](LICENSE).
