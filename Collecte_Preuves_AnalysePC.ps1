<#
.SYNOPSIS
    Collecte de preuves sur le poste suite au rapport AnalysePC.

.DESCRIPTION
    Par défaut le script est en LECTURE SEULE : il ne modifie rien sur la machine,
    il écrit uniquement dans le dossier de sortie (C:\AnalysePC_Collecte_<date>).

    Avec -Neutraliser, il effectue en plus, après confirmation :
      - désactivation de la tâche planifiée GPUZLogAutoSave
      - arrêt des processus suspects
      - blocage sortant de l'adresse 67.43.50.11 dans le pare-feu
      - déplacement des fichiers suspects en quarantaine (rien n'est supprimé)

.PARAMETER Profil
    Dossier du profil utilisateur à examiner (par défaut celui de la session).
    À préciser si la console admin tourne sous un autre compte :
    -Profil C:\Users\NomDuClient

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Collecte_Preuves_AnalysePC.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Collecte_Preuves_AnalysePC.ps1 -Neutraliser
#>
[CmdletBinding()]
param(
    [switch]$Neutraliser,
    [string]$Profil = $env:USERPROFILE,
    [string]$Sortie,
    [int]$Jours = 14
)

$ErrorActionPreference = 'Continue'
$DebutScript = Get-Date

# --------------------------------------------------------------------------
# 0. Préparation
# --------------------------------------------------------------------------
$identite = [Security.Principal.WindowsIdentity]::GetCurrent()
$estAdmin = ([Security.Principal.WindowsPrincipal]$identite).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $estAdmin) {
    Write-Warning "Ce script doit être lancé dans une console PowerShell 'Exécuter en tant qu'administrateur'."
    exit 1
}

$Horodatage = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $Sortie) { $Sortie = "C:\AnalysePC_Collecte_$Horodatage" }
New-Item -ItemType Directory -Path $Sortie -Force | Out-Null
Start-Transcript -Path (Join-Path $Sortie '00_journal_execution.txt') | Out-Null

$Roaming = Join-Path $Profil 'AppData\Roaming'
$Local   = Join-Path $Profil 'AppData\Local'

# Indicateurs relevés dans le rapport
$DossiersSuspects = @(
    (Join-Path $Roaming 'NonceChange'),
    (Join-Path $Roaming 'GPU-Z'),
    'C:\intel'
)
$FichiersSuspects = @(
    (Join-Path $Roaming 'Microsoft\clspack.exe')
)
$NomTache = 'GPUZLogAutoSave'
$IpC2     = '67.43.50.11'
$Motif    = 'NonceChange|clspack|TexturePacker|wuacult|GPU-Z\\Logs|GPUZLogAutoSave|Cloud\.ocx|Fire\.ocx|Swap\.dll|C:\\intel\\'
$NomsProcessus = @('TexturePackerGUI.exe', 'clspack.exe')
$DebutJournaux = (Get-Date).AddDays(-$Jours)

function Etape([string]$Titre) {
    Write-Host ''
    Write-Host "=== $Titre ===" -ForegroundColor Cyan
}

function Sauver([string]$Nom, [scriptblock]$Bloc) {
    $chemin = Join-Path $Sortie $Nom
    try {
        $resultat = & $Bloc
        if ($null -eq $resultat -or @($resultat).Count -eq 0) {
            '(aucun résultat)' | Out-File -FilePath $chemin -Encoding UTF8
        } else {
            $resultat | Out-String -Width 4096 | Out-File -FilePath $chemin -Encoding UTF8
        }
    } catch {
        "ERREUR : $($_.Exception.Message)" | Out-File -FilePath $chemin -Encoding UTF8
    }
    Write-Host "  -> $Nom"
}

function SauverCsv([string]$Nom, [scriptblock]$Bloc) {
    $chemin = Join-Path $Sortie $Nom
    try {
        $resultat = @(& $Bloc)
        if ($resultat.Count -eq 0) {
            '(aucun résultat)' | Out-File -FilePath $chemin -Encoding UTF8
        } else {
            $resultat | Export-Csv -Path $chemin -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        }
    } catch {
        "ERREUR : $($_.Exception.Message)" | Out-File -FilePath $chemin -Encoding UTF8
    }
    Write-Host "  -> $Nom"
}

function Get-InfoFichier($Fichier, [switch]$SansHash) {
    $sig  = Get-AuthenticodeSignature -LiteralPath $Fichier.FullName -ErrorAction SilentlyContinue
    $zone = Get-Content -LiteralPath $Fichier.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
    $hash = $null
    if (-not $SansHash) {
        $hash = (Get-FileHash -LiteralPath $Fichier.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    }
    $signataire = $null
    if ($sig -and $sig.SignerCertificate) { $signataire = $sig.SignerCertificate.Subject }
    [pscustomobject]@{
        Chemin       = $Fichier.FullName
        TailleOctets = $Fichier.Length
        Cree         = $Fichier.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
        Modifie      = $Fichier.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        Attributs    = $Fichier.Attributes
        SHA256       = $hash
        Signature    = if ($sig) { $sig.Status } else { $null }
        Signataire   = $signataire
        Origine      = (@($zone) -match 'HostUrl|ReferrerUrl|ZoneId') -join ' | '
    }
}

function Get-ProcessusSuspects {
    Get-CimInstance Win32_Process | Where-Object {
        ($_.ExecutablePath -match $Motif) -or
        ($_.CommandLine    -match $Motif) -or
        ($NomsProcessus -contains $_.Name)
    }
}

Sauver '01_contexte.txt' {
    "Collecte lancée le : $DebutScript"
    "Ordinateur         : $env:COMPUTERNAME"
    "Compte d'exécution : $($identite.Name)"
    "Profil examiné     : $Profil"
    "Neutralisation     : $Neutraliser"
    "Dernier démarrage  : $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)"
}

# --------------------------------------------------------------------------
# 1. Fichiers suspects : inventaire, empreintes, signatures, origine
# --------------------------------------------------------------------------
Etape '1. Fichiers suspects'

$Inventaire = @()
foreach ($d in $DossiersSuspects) {
    if (Test-Path -LiteralPath $d) {
        Get-ChildItem -LiteralPath $d -Recurse -Force -File -ErrorAction SilentlyContinue |
            ForEach-Object { $Inventaire += Get-InfoFichier $_ }
    } else {
        Write-Host "  (absent : $d)" -ForegroundColor DarkGray
    }
}
foreach ($f in $FichiersSuspects) {
    if (Test-Path -LiteralPath $f) {
        $Inventaire += Get-InfoFichier (Get-Item -LiteralPath $f -Force)
    } else {
        Write-Host "  (absent : $f)" -ForegroundColor DarkGray
    }
}
SauverCsv '10_fichiers_suspects.csv' { $Inventaire }
Sauver '11_empreintes_SHA256_pour_VirusTotal.txt' {
    $Inventaire | Where-Object { $_.SHA256 } | ForEach-Object { "$($_.SHA256)  $($_.Chemin)" }
}
Sauver '12_dossiers_suspects_dates.txt' {
    foreach ($d in $DossiersSuspects) {
        if (Test-Path -LiteralPath $d) {
            Get-Item -LiteralPath $d -Force | Select-Object FullName, CreationTime, LastWriteTime, Attributes
        }
    }
}

# Copie des scripts texte (jamais exécutés), renommés en .txt pour lecture sans risque
$DossierScripts = Join-Path $Sortie 'scripts_copies'
New-Item -ItemType Directory -Path $DossierScripts -Force | Out-Null
foreach ($d in $DossiersSuspects) {
    if (Test-Path -LiteralPath $d) {
        Get-ChildItem -LiteralPath $d -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -match '^\.(wsf|vbs|vbe|js|jse|bat|cmd|ps1|hta|ini|cfg|json|xml|txt)$' -and $_.Length -lt 5MB } |
            ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $DossierScripts ($_.Name + '.txt')) -Force
                Write-Host "  -> scripts_copies\$($_.Name).txt"
            }
    }
}

# --------------------------------------------------------------------------
# 2. Tâches planifiées
# --------------------------------------------------------------------------
Etape '2. Tâches planifiées'

try {
    Export-ScheduledTask -TaskName $NomTache -TaskPath '\' -ErrorAction Stop |
        Out-File -FilePath (Join-Path $Sortie "20_tache_$NomTache.xml") -Encoding UTF8
    Write-Host "  -> 20_tache_$NomTache.xml"
} catch {
    Write-Host "  (tâche $NomTache introuvable : $($_.Exception.Message))" -ForegroundColor DarkGray
}
Sauver '21_tache_infos.txt' {
    Get-ScheduledTask -TaskName $NomTache -ErrorAction SilentlyContinue | Format-List *
    Get-ScheduledTaskInfo -TaskName $NomTache -TaskPath '\' -ErrorAction SilentlyContinue | Format-List *
    # La date de création du fichier de tâche donne la date d'installation de la persistance
    Get-Item -LiteralPath "C:\Windows\System32\Tasks\$NomTache" -Force -ErrorAction SilentlyContinue |
        Format-List FullName, CreationTime, LastWriteTime
}
SauverCsv '22_taches_a_examiner.csv' {
    Get-ScheduledTask | ForEach-Object {
        $t = $_
        foreach ($a in $t.Actions) {
            $cmd = "$($a.Execute) $($a.Arguments)"
            if ($cmd -match $Motif -or $cmd -match 'AppData|\\Temp\\|ProgramData|Users\\Public|wscript|cscript|rundll32|mshta|regsvr32|powershell|cmd\.exe') {
                [pscustomobject]@{
                    Chemin   = $t.TaskPath
                    Nom      = $t.TaskName
                    Etat     = $t.State
                    Auteur   = $t.Author
                    Compte   = $t.Principal.UserId
                    Commande = $cmd
                    Indicateur = ($cmd -match $Motif)
                }
            }
        }
    }
}

# --------------------------------------------------------------------------
# 3. Processus en cours
# --------------------------------------------------------------------------
Etape '3. Processus'

$TousProcessus = Get-CimInstance Win32_Process
$Suspects = @(Get-ProcessusSuspects)
SauverCsv '30_processus_suspects.csv' {
    foreach ($p in $Suspects) {
        $parent = $TousProcessus | Where-Object { $_.ProcessId -eq $p.ParentProcessId } | Select-Object -First 1
        [pscustomobject]@{
            PID           = $p.ProcessId
            Nom           = $p.Name
            Chemin        = $p.ExecutablePath
            LigneCommande = $p.CommandLine
            Demarre       = $p.CreationDate
            PIDParent     = $p.ParentProcessId
            Parent        = if ($parent) { $parent.Name } else { '(terminé)' }
            CheminParent  = if ($parent) { $parent.ExecutablePath } else { $null }
        }
    }
}
SauverCsv '31_hotes_de_scripts_en_cours.csv' {
    $TousProcessus |
        Where-Object { $_.Name -match '^(rundll32|wscript|cscript|mshta|regsvr32|powershell|pwsh|cmd)\.exe$' } |
        Select-Object ProcessId, Name, CommandLine, CreationDate, ParentProcessId
}
Sauver '32_modules_charges_hors_Windows.txt' {
    foreach ($p in $Suspects) {
        "--- PID $($p.ProcessId) $($p.Name) ---"
        try {
            (Get-Process -Id $p.ProcessId -ErrorAction Stop).Modules |
                Where-Object { $_.FileName -notmatch '^C:\\Windows\\' } |
                Select-Object -ExpandProperty FileName
        } catch { "  (modules illisibles : $($_.Exception.Message))" }
    }
}

# --------------------------------------------------------------------------
# 4. Réseau
# --------------------------------------------------------------------------
Etape '4. Réseau'

$PidsSuspects = @($Suspects | ForEach-Object { $_.ProcessId })
SauverCsv '40_connexions_suspectes.csv' {
    Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { ($PidsSuspects -contains $_.OwningProcess) -or ($_.RemoteAddress -eq $IpC2) } |
        Select-Object CreationTime, State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess
}
SauverCsv '41_toutes_connexions.csv' {
    Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | ForEach-Object {
        $c = $_
        $p = $TousProcessus | Where-Object { $_.ProcessId -eq $c.OwningProcess } | Select-Object -First 1
        [pscustomobject]@{
            RemoteAddress = $c.RemoteAddress
            RemotePort    = $c.RemotePort
            LocalPort     = $c.LocalPort
            PID           = $c.OwningProcess
            Processus     = if ($p) { $p.Name } else { $null }
            Chemin        = if ($p) { $p.ExecutablePath } else { $null }
        }
    }
}
SauverCsv '42_cache_dns.csv' {
    Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object Entry, RecordName, RecordType, Data, TimeToLive
}
Sauver '43_regles_parefeu_indicateurs.txt' {
    Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue |
        Where-Object { $_.Program -match $Motif } |
        ForEach-Object {
            $regle = $_ | Get-NetFirewallRule
            [pscustomobject]@{ Regle = $regle.DisplayName; Sens = $regle.Direction; Action = $regle.Action; Programme = $_.Program }
        } | Format-List
}

# --------------------------------------------------------------------------
# 5. Autres mécanismes de persistance
# --------------------------------------------------------------------------
Etape '5. Persistance'

Sauver '50_cles_Run.txt' {
    $cles = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($c in $cles) {
        "--- $c ---"
        $proprietes = Get-ItemProperty -Path $c -ErrorAction SilentlyContinue
        if ($proprietes) {
            $proprietes.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object {
                $marque = if ("$($_.Value)" -match $Motif) { '  <== INDICATEUR' } else { '' }
                "{0} = {1}{2}" -f $_.Name, $_.Value, $marque
            }
        }
    }
    '--- Dossiers Démarrage ---'
    $demarrages = @(
        (Join-Path $Roaming 'Microsoft\Windows\Start Menu\Programs\Startup'),
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'
    )
    foreach ($d in $demarrages) {
        Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue |
            Select-Object FullName, CreationTime, LastWriteTime
    }
}
Sauver '51_services_indicateurs.txt' {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -match $Motif } |
        Format-List Name, DisplayName, State, StartMode, StartName, PathName
}
Sauver '52_abonnements_WMI.txt' {
    '--- Filtres ---'
    Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue |
        Format-List Name, Query, EventNamespace
    '--- Consommateurs ---'
    Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue |
        Format-List *
    '--- Liaisons ---'
    Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue |
        Format-List Filter, Consumer
    ''
    "Note : une seule liaison 'SCM Event Log Filter' -> 'SCM Event Log Consumer' est la valeur par défaut de Windows."
}
SauverCsv '53_raccourcis_navigateurs_modifies.csv' {
    # Un raccourci de navigateur avec --load-extension charge une extension hors boutique
    $shell = New-Object -ComObject WScript.Shell
    $emplacements = @(
        (Join-Path $Profil 'Desktop'),
        (Join-Path $Profil 'OneDrive\Desktop'),
        (Join-Path $Profil 'OneDrive\Bureau'),
        (Join-Path $Roaming 'Microsoft\Windows\Start Menu'),
        (Join-Path $Roaming 'Microsoft\Internet Explorer\Quick Launch'),
        'C:\ProgramData\Microsoft\Windows\Start Menu',
        'C:\Users\Public\Desktop'
    )
    foreach ($e in $emplacements) {
        Get-ChildItem -LiteralPath $e -Recurse -Force -Filter *.lnk -ErrorAction SilentlyContinue | ForEach-Object {
            $lnk = $shell.CreateShortcut($_.FullName)
            if ("$($lnk.TargetPath) $($lnk.Arguments)" -match 'load-extension|remote-debugging|proxy-server|AppData\\Roaming|\\Temp\\' -or
                "$($lnk.TargetPath) $($lnk.Arguments)" -match $Motif) {
                [pscustomobject]@{ Raccourci = $_.FullName; Cible = $lnk.TargetPath; Arguments = $lnk.Arguments; Modifie = $_.LastWriteTime }
            }
        }
    }
}

# --------------------------------------------------------------------------
# 6. Windows Defender
# --------------------------------------------------------------------------
Etape '6. Windows Defender'

Sauver '60_defender_configuration.txt' {
    Get-MpPreference | Format-List ExclusionPath, ExclusionProcess, ExclusionExtension, ExclusionIpAddress,
        DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, DisableScriptScanning,
        MAPSReporting, SubmitSamplesConsent, PUAProtection, EnableControlledFolderAccess
    Get-MpComputerStatus | Format-List AMRunningMode, RealTimeProtectionEnabled, IsTamperProtected,
        AntivirusSignatureLastUpdated, QuickScanEndTime, FullScanEndTime
}
Sauver '61_defender_detections.txt' {
    Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Format-List InitialDetectionTime, ProcessName, Resources, ThreatID, ActionSuccess
    Get-MpThreat -ErrorAction SilentlyContinue | Format-List ThreatName, SeverityID, IsActive, Resources
}
SauverCsv '62_defender_evenements_complets.csv' {
    # 5007 = configuration modifiée (texte complet, non tronqué), 5001/5010/5012 = protections désactivées,
    # 1116/1117 = détection et action, 1006/1007 = détection lors d'une analyse
    Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Windows Defender/Operational'
        Id        = 5007, 5001, 5004, 5010, 5012, 5013, 1116, 1117, 1006, 1007
        StartTime = $DebutJournaux
    } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, @{ n = 'Message'; e = { $_.Message -replace '\s+', ' ' } }
}

# --------------------------------------------------------------------------
# 7. Journaux d'événements
# --------------------------------------------------------------------------
Etape '7. Journaux'

SauverCsv '70_plantages_lies.csv' {
    Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Id = 1000, 1001, 1002; StartTime = $DebutJournaux } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'rundll32|TexturePacker|clspack|\.ocx|wscript|cscript' } |
        Select-Object TimeCreated, Id, ProviderName, @{ n = 'Message'; e = { $_.Message -replace '\s+', ' ' } }
}
SauverCsv '71_planificateur_evenements.csv' {
    # Journal parfois désactivé par défaut : un résultat vide ne prouve rien
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; StartTime = $DebutJournaux } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match $Motif } |
        Select-Object TimeCreated, Id, @{ n = 'Message'; e = { $_.Message -replace '\s+', ' ' } }
}
SauverCsv '72_securite_creation_taches.csv' {
    # 4698 = tâche créée, 4702 = tâche modifiée (uniquement si l'audit est activé)
    Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4698, 4702; StartTime = $DebutJournaux } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, Id, @{ n = 'Message'; e = { $_.Message -replace '\s+', ' ' } }
}
SauverCsv '73_powershell_scripts_lies.csv' {
    Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; StartTime = $DebutJournaux } -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -lt $DebutScript -and
                       $_.Message -match "$Motif|Add-MpPreference|Set-MpPreference|DownloadString|DownloadFile|FromBase64String|Invoke-WebRequest|schtasks|Register-ScheduledTask" -and
                       $_.Message -notmatch 'AnalysePC' } |
        Select-Object TimeCreated, @{ n = 'Message'; e = { ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(4000, ($_.Message -replace '\s+', ' ').Length)) } }
}
SauverCsv '74_prefetch_premiere_et_derniere_execution.csv' {
    # Cree = première exécution connue, Modifie = dernière exécution
    Get-ChildItem -LiteralPath 'C:\Windows\Prefetch' -Filter *.pf -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match 'TEXTUREPACKER|CLSPACK|GPU-Z|NEWDEV|WSCRIPT|CSCRIPT|RUNDLL32|MSHTA|REGSVR32|SCHTASKS' } |
        Select-Object Name, @{ n = 'Cree'; e = { $_.CreationTime } }, @{ n = 'Modifie'; e = { $_.LastWriteTime } } |
        Sort-Object Cree
}

# --------------------------------------------------------------------------
# 8. Recherche de l'origine : téléchargements récents
# --------------------------------------------------------------------------
Etape '8. Origine (téléchargements des 30 derniers jours)'

SauverCsv '80_telechargements_recents.csv' {
    $limite = (Get-Date).AddDays(-30)
    $dossiers = @((Join-Path $Profil 'Downloads'), (Join-Path $Profil 'Desktop'), (Join-Path $Local 'Temp'))
    foreach ($d in $dossiers) {
        Get-ChildItem -LiteralPath $d -Recurse -Depth 2 -Force -File -ErrorAction SilentlyContinue |
            Where-Object { ($_.CreationTime -ge $limite) -and
                           ($_.Extension -match '^\.(exe|msi|msix|zip|rar|7z|iso|img|lnk|js|vbs|wsf|bat|cmd|ps1|hta|scr|dll)$') } |
            ForEach-Object {
                if ($_.Length -lt 300MB) { Get-InfoFichier $_ } else { Get-InfoFichier $_ -SansHash }
            }
    }
}

# --------------------------------------------------------------------------
# 9. Points à vérifier (EdgeCypher, dossiers dotnet_perf)
# --------------------------------------------------------------------------
Etape '9. Points à vérifier'

Sauver '90_EdgeCypher.txt' {
    $cles = @(
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    Get-ItemProperty -Path $cles -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -match 'EdgeCypher' } |
        Format-List DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, UninstallString, DisplayIcon, PSPath
}
Sauver '91_dotnet_perf_contenu.txt' {
    $dossiers = Get-ChildItem -LiteralPath (Join-Path $Local 'Temp') -Directory -Filter 'dotnet_perf_*' -Force -ErrorAction SilentlyContinue
    foreach ($d in $dossiers) {
        "=== $($d.FullName) (créé $($d.CreationTime), modifié $($d.LastWriteTime)) ==="
        Get-ChildItem -LiteralPath $d.FullName -Recurse -Force -File -ErrorAction SilentlyContinue |
            Select-Object @{ n = 'Fichier'; e = { $_.FullName.Substring($d.FullName.Length) } }, Length, LastWriteTime |
            Format-Table -AutoSize
        Get-ChildItem -LiteralPath $d.FullName -Recurse -Force -Filter manifest.json -ErrorAction SilentlyContinue | ForEach-Object {
            "--- $($_.FullName) ---"
            Get-Content -LiteralPath $_.FullName -Raw
        }
    }
}
Sauver '92_navigateurs_lances_avec_extension.txt' {
    # Un navigateur en cours avec --load-extension indique une extension chargée hors boutique
    $TousProcessus |
        Where-Object { $_.Name -match '^(chrome|msedge|brave|opera)\.exe$' -and $_.CommandLine -match 'load-extension|remote-debugging' } |
        Format-List ProcessId, Name, CommandLine
}

# --------------------------------------------------------------------------
# 10. Neutralisation (uniquement avec -Neutraliser)
# --------------------------------------------------------------------------
if ($Neutraliser) {
    Etape '10. Neutralisation'
    Write-Host 'Actions prévues : désactiver la tâche, arrêter les processus suspects,' -ForegroundColor Yellow
    Write-Host "bloquer $IpC2 en sortie, déplacer les fichiers suspects en quarantaine." -ForegroundColor Yellow
    Write-Host 'Rien ne sera supprimé.' -ForegroundColor Yellow
    $reponse = Read-Host 'Tapez OUI (en majuscules) pour continuer'

    if ($reponse -ceq 'OUI') {
        $Quarantaine = "C:\AnalysePC_Quarantaine_$Horodatage"
        New-Item -ItemType Directory -Path $Quarantaine -Force | Out-Null
        $JournalActions = Join-Path $Sortie '99_neutralisation.txt'
        function Noter([string]$Texte) {
            $ligne = "{0}  {1}" -f (Get-Date -Format 'HH:mm:ss'), $Texte
            Write-Host "  $ligne"
            Add-Content -Path $JournalActions -Value $ligne -Encoding UTF8
        }

        # a) Tâche planifiée : désactivée, pas supprimée
        try {
            Stop-ScheduledTask -TaskName $NomTache -TaskPath '\' -ErrorAction SilentlyContinue
            Disable-ScheduledTask -TaskName $NomTache -TaskPath '\' -ErrorAction Stop | Out-Null
            Noter "Tâche $NomTache désactivée"
        } catch { Noter "ECHEC désactivation tâche $NomTache : $($_.Exception.Message)" }

        # b) Processus suspects (liste recalculée)
        foreach ($p in @(Get-ProcessusSuspects)) {
            if ($p.ProcessId -eq $PID) { continue }
            try {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
                Noter "Processus arrêté : PID $($p.ProcessId) $($p.Name) [$($p.ExecutablePath)]"
            } catch { Noter "ECHEC arrêt PID $($p.ProcessId) $($p.Name) : $($_.Exception.Message)" }
        }

        # c) Blocage réseau de l'adresse contactée
        try {
            New-NetFirewallRule -DisplayName "AnalysePC - blocage $IpC2" -Direction Outbound -Action Block `
                -RemoteAddress $IpC2 -Profile Any -ErrorAction Stop | Out-Null
            Noter "Règle de pare-feu créée : blocage sortant vers $IpC2"
        } catch { Noter "ECHEC règle pare-feu : $($_.Exception.Message)" }

        # d) Quarantaine par déplacement
        Start-Sleep -Seconds 2
        $aDeplacer = @(
            (Join-Path $Roaming 'NonceChange'),
            (Join-Path $Roaming 'GPU-Z'),
            (Join-Path $Roaming 'Microsoft\clspack.exe')
        )
        # C:\intel peut contenir des fichiers Intel légitimes : seuls les fichiers TexturePacker* sont déplacés
        if (Test-Path -LiteralPath 'C:\intel') {
            $aDeplacer += @(Get-ChildItem -LiteralPath 'C:\intel' -Force -Filter 'TexturePacker*' -ErrorAction SilentlyContinue |
                ForEach-Object { $_.FullName })
        }
        $n = 0
        foreach ($source in $aDeplacer) {
            if (-not (Test-Path -LiteralPath $source)) { continue }
            $n++
            $destination = Join-Path $Quarantaine ("{0:D2}_{1}" -f $n, (Split-Path -Path $source -Leaf))
            try {
                Move-Item -LiteralPath $source -Destination $destination -Force -ErrorAction Stop
                Noter "Déplacé : $source  ->  $destination"
            } catch { Noter "ECHEC déplacement $source : $($_.Exception.Message)" }
        }
        if (Test-Path -LiteralPath 'C:\intel') {
            $restants = @(Get-ChildItem -LiteralPath 'C:\intel' -Recurse -Force -File -ErrorAction SilentlyContinue)
            Noter "C:\intel : $($restants.Count) fichier(s) laissé(s) en place, à examiner à la main (voir 10_fichiers_suspects.csv)"
        }
        Noter "Quarantaine : $Quarantaine"
    } else {
        Write-Host '  Neutralisation annulée.' -ForegroundColor Yellow
    }
}

# --------------------------------------------------------------------------
# Fin : archive
# --------------------------------------------------------------------------
Stop-Transcript | Out-Null
$Archive = "$Sortie.zip"
try {
    Compress-Archive -Path (Join-Path $Sortie '*') -DestinationPath $Archive -Force -ErrorAction Stop
    $empreinte = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash
    Write-Host ''
    Write-Host "Collecte terminée." -ForegroundColor Green
    Write-Host "Dossier : $Sortie"
    Write-Host "Archive : $Archive"
    Write-Host "SHA256  : $empreinte"
} catch {
    Write-Host "Collecte terminée (archive non créée : $($_.Exception.Message))." -ForegroundColor Yellow
    Write-Host "Dossier : $Sortie"
}
