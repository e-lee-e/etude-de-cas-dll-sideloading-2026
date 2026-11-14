<#
.SYNOPSIS
    Suite de Collecte_Preuves_AnalysePC.ps1 : recherche du mécanisme qui relance
    l'infection à l'ouverture de session, recherche de l'origine, fin de la quarantaine.

.DESCRIPTION
    Par défaut le script est en LECTURE SEULE : il écrit uniquement dans le dossier
    de sortie (C:\AnalysePC_Recherche_<date>).

    Avec -Neutraliser, il effectue en plus, après confirmation :
      - blocage sortant de 144.48.61.40 et 67.43.50.11 dans le pare-feu
      - arrêt des processus suspects encore présents
      - export puis suppression de la clé COM "Pure.Fire" de l'utilisateur
      - déplacement en quarantaine de C:\intel, des fichiers réapparus,
        des VS12-KB2961101*.exe de Temp et des profils dotnet_perf_*
    Les déclencheurs éventuellement trouvés ne sont PAS supprimés automatiquement :
    ils sont listés dans 00_SYNTHESE.txt pour décision.

    Durée : 5 à 15 minutes (parcours du disque et du registre).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Recherche_Declencheur_AnalysePC.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Recherche_Declencheur_AnalysePC.ps1 -Neutraliser
#>
[CmdletBinding()]
param(
    [switch]$Neutraliser,
    [string]$Profil = $env:USERPROFILE,
    [string]$Sortie,
    [datetime]$DateInfection = '2025-12-31'
)

$ErrorActionPreference = 'Continue'
$DebutScript = Get-Date

$identite = [Security.Principal.WindowsIdentity]::GetCurrent()
$estAdmin = ([Security.Principal.WindowsPrincipal]$identite).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $estAdmin) {
    Write-Warning "Ce script doit être lancé dans une console PowerShell 'Exécuter en tant qu'administrateur'."
    exit 1
}

$Horodatage = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $Sortie) { $Sortie = "C:\AnalysePC_Recherche_$Horodatage" }
New-Item -ItemType Directory -Path $Sortie -Force | Out-Null
Start-Transcript -Path (Join-Path $Sortie '00_journal_execution.txt') | Out-Null

$Roaming = Join-Path $Profil 'AppData\Roaming'
$Local   = Join-Path $Profil 'AppData\Local'

# --------------------------------------------------------------------------
# Indicateurs connus (issus de la première collecte)
# --------------------------------------------------------------------------
$Clsid    = '{7F222C4E-56B0-4E46-8359-E24FE3A4B975}'
$TypeLib  = '{8F1576C0-BB08-4F05-87A6-268C0D548794}'
$IpsC2    = @('144.48.61.40', '67.43.50.11')
$Motif    = 'NonceChange|clspack|TexturePacker|wuacult|GPU-Z\\Logs|GPUZLogAutoSave|Cloud\.ocx|Fire\.ocx|Swap\.dll|C:\\intel\\|7F222C4E|8F1576C0|Pure\.Fire|pdf-viewer|144\.48\.61\.40|67\.43\.50\.11|certificate\.cer'
$NomsProcessus = @('TexturePackerGUI.exe', 'clspack.exe')

# Taille en octets -> SHA256 des fichiers de l'infection
$Connus = @{}
$Connus[22984343] = '8F470248E1A0093D3512E6D86B80BE7D2CE4272F295EC4C1B4351E04FAA07658'  # certificate.cer
$Connus[1257472]  = '35882420A2ABB9A857E2B93DA48A0FF661763179D0277D2CA1743A45F7BE9834'  # Cloud.ocx
$Connus[49424]    = '2915EFECF2A01CE0B3EF49C47666EC43C326E7804DF10E5859DB5F08EECA8A37'  # clspack.exe
$Connus[964]      = '1D0D0BCAF0F7FEA73C5EE4E239D6F5FD4A9AC2EC0B5E0094E468BED384E34A8C'  # filetext.txt
$Connus[45056]    = '5F5D2BA63FC9F9332DC5EF10274ABE9C39FD655F1E177C1C0139371F2B2E2702'  # Fire.ocx
$Connus[68096]    = '1675B87BE879B45739C08D9098EF754526CE032EA054AD754B2FEF3EFAFF6AB1'  # newdev.exe
$Connus[122880]   = '5F8336EF7F7537823F3DCB01A97D63EB81B1C0CBAF97FA0B7B469EF60DABCFD9'  # Swap.dll
$Connus[19106]    = '4357824F0CE1C40863866C2C1B072C5362B988DFC787BBFA5B24A33D1C7095F9'  # wuacult.wsf
$Connus[5097885]  = 'BAFE53985387A31603B3E094845CAD9D705BB56B9F90EFF426C3440FFD6FB456'  # backup.zip
$Connus[329216]   = 'FA73D8368C1DB36FB3FA898C0FB5E2C902947F4D5AD4ED0709FF16A33A75FD2A'  # TexturePackerLib.dll
$Connus[152632]   = '338A972EC08EBE07B793804B20A4B38E47B5477378C00473DFC02878E29CAEAF'  # TexturePackerGUI.exe / GPU-Z.exe
$NomsConnus = '^(wuacult\.wsf|clspack\.exe|Fire\.ocx|Cloud\.ocx|Swap\.dll|certificate\.cer|filetext2?\.txt|TexturePacker.*|rtl370\.bpl|cc64370mt\.dll|borlndmm\.dll|VS12-KB2961101.*\.exe)$'

# Moments où l'infection s'est installée ou exécutée.
# DATES D'EXEMPLE (J = 2026-01-01) : à remplacer, ainsi que -DateInfection, par celles du cas traité
$Moments = @(
    '2026-01-01 21:09', '2026-01-02 17:10', '2026-01-03 09:20',
    '2026-01-03 10:02', '2026-01-03 20:23', '2026-01-03 22:33'
) | ForEach-Object { [datetime]::ParseExact($_, 'yyyy-MM-dd HH:mm', [Globalization.CultureInfo]::InvariantCulture) }

$Synthese = New-Object System.Collections.Generic.List[string]
function Signaler([string]$Texte) {
    $Synthese.Add($Texte)
    Write-Host "  [!] $Texte" -ForegroundColor Yellow
}

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

# Écrit un CSV et renvoie le nombre de lignes
function SauverCsv([string]$Nom, [scriptblock]$Bloc) {
    $chemin = Join-Path $Sortie $Nom
    $resultat = @()
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
    Write-Host "  -> $Nom ($($resultat.Count) ligne(s))"
    return $resultat.Count
}

function Get-CibleCommande([string]$Commande) {
    # Extrait le chemin du fichier d'une ligne de commande ou d'une valeur de registre
    if (-not $Commande) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Commande).Trim()
    if ($c -match '^"([^"]+)"') { return $Matches[1] }
    if ($c -match '^(.+?\.(exe|dll|ocx|cpl|scr|bat|cmd|vbs|js|wsf|ps1))(\s|,|$)') { return $Matches[1] }
    return $c
}

function Get-EtatSignature([string]$Chemin) {
    if (-not $Chemin) { return '' }
    if (-not (Test-Path -LiteralPath $Chemin -PathType Leaf)) { return 'FICHIER ABSENT' }
    $sig = Get-AuthenticodeSignature -LiteralPath $Chemin -ErrorAction SilentlyContinue
    if ($sig) { return "$($sig.Status)" }
    return 'Inconnu'
}

function Test-EmplacementUtilisateur([string]$Chemin) {
    return ($Chemin -match '\\AppData\\|\\Temp\\|\\ProgramData\\|\\Users\\Public\\|^C:\\intel\\|\\Downloads\\|\\Desktop\\')
}

$Surveilles = @(
    (Join-Path $Roaming 'NonceChange'),
    (Join-Path $Roaming 'GPU-Z'),
    (Join-Path $Roaming 'Microsoft\clspack.exe'),
    'C:\intel\TexturePackerGUI.exe'
)
Sauver '01_contexte.txt' {
    "Recherche lancée le : $DebutScript"
    "Ordinateur          : $env:COMPUTERNAME"
    "Compte d'exécution  : $($identite.Name)"
    "Profil examiné      : $Profil"
    "Neutralisation      : $Neutraliser"
    "Dernier démarrage   : $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime)"
    ''
    'Réapparition depuis la première neutralisation :'
    foreach ($p in $Surveilles) {
        $etat = 'absent'
        if (Test-Path -LiteralPath $p) { $etat = 'PRESENT' }
        "  $p : $etat"
    }
}
foreach ($p in $Surveilles) {
    if (Test-Path -LiteralPath $p) { Signaler "REAPPARU depuis la première neutralisation : $p" }
}

# --------------------------------------------------------------------------
# 1. Tâches planifiées : toutes les actions, y compris les actions COM
# --------------------------------------------------------------------------
Etape '1. Tâches planifiées (actions Exec et COM)'

$Taches = @()
foreach ($t in Get-ScheduledTask) {
    $fichier = Join-Path 'C:\Windows\System32\Tasks' ($t.TaskPath.TrimStart('\') + $t.TaskName)
    $fi = Get-Item -LiteralPath $fichier -Force -ErrorAction SilentlyContinue
    $declencheurs = (@($t.Triggers) | ForEach-Object { $_.CimClass.CimClassName -replace 'MSFT_Task|Trigger', '' }) -join ','
    foreach ($a in @($t.Actions)) {
        $type = $a.CimClass.CimClassName
        $comUtilisateur = $false
        if ($type -match 'ComHandler') {
            $detail = "COM $($a.ClassId) $($a.Data)"
            $comUtilisateur = Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\$($a.ClassId)"
        } else {
            $detail = "$($a.Execute) $($a.Arguments)"
        }
        $recent = $false
        $cree = ''
        $modifie = ''
        if ($fi) {
            $recent  = (($fi.CreationTime -ge $DateInfection) -or ($fi.LastWriteTime -ge $DateInfection))
            $cree    = $fi.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
            $modifie = $fi.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        }
        $Taches += [pscustomobject]@{
            Indicateur        = ($detail -match $Motif)
            ComParUtilisateur = $comUtilisateur
            Recent            = $recent
            Chemin            = $t.TaskPath
            Nom               = $t.TaskName
            Etat              = $t.State
            Auteur            = $t.Author
            Compte            = $t.Principal.UserId
            Declencheurs      = $declencheurs
            Action            = $detail
            FichierCree       = $cree
            FichierModifie    = $modifie
        }
    }
}
[void](SauverCsv '10_taches_toutes_actions.csv' {
    $Taches | Sort-Object -Property @{ Expression = 'Indicateur'; Descending = $true },
                                    @{ Expression = 'ComParUtilisateur'; Descending = $true },
                                    @{ Expression = 'Recent'; Descending = $true }, Chemin, Nom
})
foreach ($t in ($Taches | Where-Object { $_.Indicateur -and $_.Nom -ne 'GPUZLogAutoSave' })) {
    Signaler "Tâche avec indicateur : $($t.Chemin)$($t.Nom) -> $($t.Action)"
}
foreach ($t in ($Taches | Where-Object { $_.ComParUtilisateur })) {
    Signaler "Tâche à action COM redéfinie dans le registre utilisateur : $($t.Chemin)$($t.Nom) -> $($t.Action)"
}
foreach ($t in ($Taches | Where-Object { $_.Recent -and $_.Chemin -notlike '\Microsoft\*' -and $_.Nom -ne 'GPUZLogAutoSave' })) {
    Write-Host "  (tâche hors Microsoft créée ou modifiée depuis le $($DateInfection.ToString('dd/MM')) : $($t.Chemin)$($t.Nom))" -ForegroundColor DarkGray
}

Sauver '11_fichiers_taches_avec_indicateur.txt' {
    # Recherche brute dans les fichiers XML des tâches (couvre ce que l'API ne montrerait pas)
    Get-ChildItem -LiteralPath 'C:\Windows\System32\Tasks' -Recurse -Force -File -ErrorAction SilentlyContinue |
        Select-String -Pattern $Motif -ErrorAction SilentlyContinue |
        ForEach-Object { "{0} : {1}" -f $_.Path, $_.Line.Trim() }
    '--- Anciennes tâches (C:\Windows\Tasks\*.job) ---'
    Get-ChildItem -LiteralPath 'C:\Windows\Tasks' -Force -ErrorAction SilentlyContinue | Select-Object FullName, CreationTime, LastWriteTime
}

# --------------------------------------------------------------------------
# 2. Classes COM définies au niveau de l'utilisateur (détournement COM)
# --------------------------------------------------------------------------
Etape '2. Classes COM utilisateur'

$Com = @()
foreach ($racine in @('HKCU:\Software\Classes\CLSID', 'HKCU:\Software\Classes\WOW6432Node\CLSID')) {
    foreach ($k in @(Get-ChildItem -LiteralPath $racine -ErrorAction SilentlyContinue)) {
        foreach ($sous in @('InprocServer32', 'LocalServer32', 'TreatAs', 'ScriptletURL')) {
            $sk = $k.OpenSubKey($sous)
            if (-not $sk) { continue }
            $valeur = "$($sk.GetValue(''))"
            $sk.Close()
            $estServeur = ($sous -match 'Server32')
            $sig = ''
            if ($estServeur) { $sig = Get-EtatSignature (Get-CibleCommande $valeur) }
            $suspect = ($valeur -match $Motif) -or ($k.PSChildName -eq $Clsid) -or (-not $estServeur) -or ($sig -ne 'Valid')
            $Com += [pscustomobject]@{
                Suspect   = $suspect
                CLSID     = $k.PSChildName
                Nom       = "$($k.GetValue(''))"
                Type      = $sous
                Valeur    = $valeur
                Signature = $sig
                MasqueUneClasseSysteme = (Test-Path -LiteralPath ("HKLM:\SOFTWARE\Classes\CLSID\" + $k.PSChildName))
                Racine    = $racine
            }
        }
    }
}
[void](SauverCsv '20_classes_COM_utilisateur.csv' {
    $Com | Sort-Object -Property @{ Expression = 'Suspect'; Descending = $true }, CLSID
})
foreach ($c in ($Com | Where-Object { $_.Suspect })) {
    Signaler "Classe COM utilisateur à examiner : $($c.CLSID) [$($c.Nom)] $($c.Type) = $($c.Valeur) (signature : $($c.Signature))"
}

Sauver '21_cle_PureFire.txt' {
    foreach ($cle in @("HKCU\Software\Classes\CLSID\$Clsid", "HKCU\Software\Classes\TypeLib\$TypeLib", 'HKCU\Software\Classes\Pure.Fire')) {
        "--- $cle ---"
        & reg.exe query $cle /s 2>&1 | ForEach-Object { "$_" }
    }
}

[void](SauverCsv '22_commandes_shell_utilisateur.csv' {
    # Associations de fichiers et protocoles redéfinis par l'utilisateur (ms-settings, exefile, etc.)
    foreach ($k in @(Get-ChildItem -LiteralPath 'HKCU:\Software\Classes' -ErrorAction SilentlyContinue)) {
        foreach ($verbe in @('shell\open\command', 'shell\runas\command')) {
            $sk = $k.OpenSubKey($verbe)
            if (-not $sk) { continue }
            $valeur = "$($sk.GetValue(''))"
            $delegue = "$($sk.GetValue('DelegateExecute'))"
            $sk.Close()
            [pscustomobject]@{
                Suspect         = (($valeur -match $Motif) -or ($k.PSChildName -match '^(ms-settings|exefile|mscfile|Folder|\.exe)$'))
                Classe          = $k.PSChildName
                Verbe           = $verbe
                Commande        = $valeur
                DelegateExecute = $delegue
                Signature       = Get-EtatSignature (Get-CibleCommande $valeur)
            }
        }
    }
})

# --------------------------------------------------------------------------
# 3. Mécanismes d'ouverture de session moins courants
# --------------------------------------------------------------------------
Etape '3. Mécanismes d''ouverture de session'

function Lire-Valeurs([string]$Cle, [string[]]$Noms) {
    "--- $Cle ---"
    $p = Get-ItemProperty -Path $Cle -ErrorAction SilentlyContinue
    if (-not $p) { '  (clé absente)'; return }
    foreach ($prop in $p.PSObject.Properties) {
        if ($prop.Name -like 'PS*') { continue }
        if ($Noms -and ($Noms -notcontains $prop.Name)) { continue }
        $texte = (@($prop.Value) -join ' | ')
        if (-not $texte) { continue }
        $marque = ''
        if ($texte -match $Motif) { $marque = '   <== INDICATEUR' }
        "  VALEUR {0} = {1}{2}" -f $prop.Name, $texte, $marque
    }
}

Sauver '30_mecanismes_session.txt' {
    '### Valeurs normalement absentes : toute ligne VALEUR ci-dessous est à examiner'
    Lire-Valeurs 'HKCU:\Environment' @('UserInitMprLogonScript')
    Lire-Valeurs 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon' @('Shell', 'Userinit', 'Taskman')
    Lire-Valeurs 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows' @('Load', 'Run')
    Lire-Valeurs 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' $null
    Lire-Valeurs 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run' $null
    Lire-Valeurs 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices' $null
    Lire-Valeurs 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnceEx' $null
    Lire-Valeurs 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx' $null
    Lire-Valeurs 'HKCU:\Software\Microsoft\Command Processor' @('AutoRun')
    Lire-Valeurs 'HKLM:\SOFTWARE\Microsoft\Command Processor' @('AutoRun')
    Lire-Valeurs 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' @('AppInit_DLLs')
    '### FIN'
    ''
    '### Valeurs normalement présentes : vérifier le contenu'
    Lire-Valeurs 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' @('Shell', 'Userinit', 'Taskman', 'AppSetup', 'VmApplet')
    Lire-Valeurs 'HKCU:\Control Panel\Desktop' @('SCRNSAVE.EXE')
    Lire-Valeurs 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' @('Startup')
    Lire-Valeurs 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders' @('Startup')
    ''
    '--- Active Setup (StubPath exécuté à l''ouverture de session) ---'
    foreach ($racine in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKCU:\SOFTWARE\Microsoft\Active Setup\Installed Components')) {
        foreach ($k in @(Get-ChildItem -LiteralPath $racine -ErrorAction SilentlyContinue)) {
            $stub = "$($k.GetValue('StubPath'))"
            if ($stub) {
                $marque = ''
                if (($stub -match $Motif) -or (Test-EmplacementUtilisateur $stub)) { $marque = '   <== A EXAMINER' }
                "  {0} [{1}] = {2}{3}" -f $k.PSChildName, $k.GetValue(''), $stub, $marque
            }
        }
    }
    ''
    '--- Scripts de stratégie de groupe ---'
    foreach ($d in @('C:\Windows\System32\GroupPolicy\User\Scripts', 'C:\Windows\System32\GroupPolicy\Machine\Scripts')) {
        Get-ChildItem -LiteralPath $d -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.FullName)  ($($_.LastWriteTime))" }
    }
    ''
    '--- Profils PowerShell ---'
    $profilsPS = @(
        (Join-Path $Profil 'Documents\WindowsPowerShell\profile.ps1'),
        (Join-Path $Profil 'Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1'),
        (Join-Path $Profil 'Documents\PowerShell\profile.ps1'),
        (Join-Path $Profil 'Documents\PowerShell\Microsoft.PowerShell_profile.ps1'),
        'C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1'
    )
    foreach ($f in $profilsPS) {
        if (Test-Path -LiteralPath $f) {
            "  PRESENT : $f"
            Get-Content -LiteralPath $f -TotalCount 60 | ForEach-Object { "      $_" }
        }
    }
    ''
    '--- Dossiers Démarrage ---'
    foreach ($d in @((Join-Path $Roaming 'Microsoft\Windows\Start Menu\Programs\Startup'), 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup')) {
        Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | ForEach-Object { "  $($_.FullName)  (créé $($_.CreationTime))" }
    }
}
# Signalement : toute VALEUR de la première partie, tout indicateur, tout StubPath dans un dossier utilisateur
$dansPartie1 = $true
foreach ($l in @(Get-Content -LiteralPath (Join-Path $Sortie '30_mecanismes_session.txt') -ErrorAction SilentlyContinue)) {
    if ($l -match '^### FIN') { $dansPartie1 = $false }
    if (($dansPartie1 -and $l -match '^\s+VALEUR ') -or ($l -match 'INDICATEUR|A EXAMINER')) {
        Signaler "Mécanisme de session : $($l.Trim())"
    }
}

Sauver '31_transferts_BITS.txt' {
    Import-Module BitsTransfer -ErrorAction SilentlyContinue
    Get-BitsTransfer -AllUsers -ErrorAction SilentlyContinue | ForEach-Object {
        "--- $($_.DisplayName) | $($_.JobState) | créé $($_.CreationTime) | $($_.OwnerAccount) ---"
        foreach ($f in $_.FileList) { "    $($f.RemoteName)  ->  $($f.LocalName)" }
        if ($_.NotifyCmdLine) { "    NotifyCmdLine : $($_.NotifyCmdLine)" }
    }
}

# --------------------------------------------------------------------------
# 4. Recherche des indicateurs dans le registre
# --------------------------------------------------------------------------
Etape '4. Recherche dans le registre (plusieurs minutes)'

Sauver '40_registre_indicateurs.txt' {
    $termesHKCU = @('7F222C4E', '8F1576C0', 'NonceChange', 'clspack', 'wuacult', 'TexturePacker', 'Pure.Fire', 'pdf-viewer', 'C:\intel\')
    foreach ($terme in $termesHKCU) {
        Write-Host "     HKCU : $terme" -ForegroundColor DarkGray
        "=== HKCU : $terme ==="
        & reg.exe query HKCU /f $terme /s 2>$null | Where-Object { $_ -and ($_ -notmatch '^(Fin de la recherche|End of search)') }
    }
    $termesHKLM = @('7F222C4E', 'NonceChange', 'clspack', 'wuacult', 'TexturePackerGUI')
    foreach ($terme in $termesHKLM) {
        Write-Host "     HKLM\SOFTWARE : $terme" -ForegroundColor DarkGray
        "=== HKLM\SOFTWARE : $terme ==="
        & reg.exe query 'HKLM\SOFTWARE' /f $terme /s 2>$null | Where-Object { $_ -and ($_ -notmatch '^(Fin de la recherche|End of search)') }
    }
}

# --------------------------------------------------------------------------
# 5. Parcours du disque : copies des fichiers connus + fichiers créés aux moments clés
# --------------------------------------------------------------------------
Etape '5. Parcours du disque (plusieurs minutes)'

$Racines = @()
$Racines += @(Get-ChildItem -LiteralPath 'C:\' -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '^(Windows|Program Files|Program Files \(x86\)|AnalysePC_.*|\$Recycle\.Bin|System Volume Information)$' } |
    ForEach-Object { $_.FullName })
$Racines += @('C:\Windows\Temp', 'C:\Windows\Tasks')

$Copies = New-Object System.Collections.Generic.List[object]
$Crees  = New-Object System.Collections.Generic.List[object]
$MotifCaches = '\\(Cache|Code Cache|GPUCache|Service Worker|CacheStorage|DawnCache|GrShaderCache|IndexedDB|Session Storage|Local Storage)\\'
$nbFichiers = 0
foreach ($r in $Racines) {
    Write-Host "     $r" -ForegroundColor DarkGray
    Get-ChildItem -LiteralPath $r -Recurse -Force -File -ErrorAction SilentlyContinue | ForEach-Object {
        $f = $_
        $nbFichiers++
        if ($f.FullName -match '\\AnalysePC_') { return }

        # a) copie d'un fichier connu (même taille puis même empreinte) ou nom connu
        $parHash = $false
        if ($f.Length -le 2147483647) {
            $taille = [int]$f.Length
            if ($Connus.ContainsKey($taille)) {
                $h = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
                if ($h -and ($h -eq $Connus[$taille])) { $parHash = $true }
            }
        }
        if ($parHash -or ($f.Name -match $NomsConnus)) {
            $Copies.Add([pscustomobject]@{
                EmpreinteIdentique = $parHash
                Chemin    = $f.FullName
                Taille    = $f.Length
                Cree      = $f.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                Modifie   = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                Attributs = "$($f.Attributes)"
            })
        }

        # b) fichier créé dans les 40 minutes précédant (ou les 6 minutes suivant) un moment clé
        if (($f.CreationTime -ge $DateInfection) -and ($Crees.Count -lt 5000) -and ($f.FullName -notmatch $MotifCaches)) {
            foreach ($m in $Moments) {
                if (($f.CreationTime -ge $m.AddMinutes(-40)) -and ($f.CreationTime -le $m.AddMinutes(6))) {
                    $Crees.Add([pscustomobject]@{
                        Cree    = $f.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                        Moment  = $m.ToString('dd/MM HH:mm')
                        Chemin  = $f.FullName
                        Taille  = $f.Length
                        Modifie = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                    })
                    break
                }
            }
        }
    }
}
Write-Host "     $nbFichiers fichiers parcourus" -ForegroundColor DarkGray
[void](SauverCsv '50_copies_des_fichiers_connus.csv' { $Copies | Sort-Object Chemin })
[void](SauverCsv '51_fichiers_crees_aux_moments_cles.csv' { $Crees | Sort-Object Cree })
foreach ($c in ($Copies | Where-Object { $_.EmpreinteIdentique })) {
    Signaler "Copie d'un fichier de l'infection : $($c.Chemin) (créé $($c.Cree))"
}

$FinFenetreOrigine = $Moments[1].AddHours(1)
[void](SauverCsv '52_archives_et_installeurs_recents.csv' {
    # Archives, installeurs, raccourcis et scripts créés dans le profil entre la date d'infection et le soir de J+1
    Get-ChildItem -LiteralPath $Profil -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object { ($_.CreationTime -ge $DateInfection) -and ($_.CreationTime -le $FinFenetreOrigine) -and
                       ($_.Extension -match '^\.(zip|rar|7z|iso|img|msi|msix|exe|lnk|js|vbs|wsf|hta|bat|cmd|ps1|scr|pdf)$') -and
                       ($_.FullName -notmatch $MotifCaches) } |
        ForEach-Object {
            $zone = Get-Content -LiteralPath $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue
            [pscustomobject]@{
                Cree    = $_.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                Chemin  = $_.FullName
                Taille  = $_.Length
                Origine = (@($zone) -match 'HostUrl|ReferrerUrl') -join ' | '
            }
        } | Sort-Object Cree
})

[void](SauverCsv '53_documents_recents_ouverts.csv' {
    # Raccourcis "Récents" : ce que l'utilisateur a ouvert autour de J
    $shell = New-Object -ComObject WScript.Shell
    Get-ChildItem -LiteralPath (Join-Path $Roaming 'Microsoft\Windows\Recent') -Filter *.lnk -Force -ErrorAction SilentlyContinue |
        Where-Object { ($_.LastWriteTime -ge $DateInfection) -and ($_.LastWriteTime -le $FinFenetreOrigine) } |
        ForEach-Object {
            [pscustomobject]@{
                Ouvert = $_.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
                Nom    = $_.BaseName
                Cible  = $shell.CreateShortcut($_.FullName).TargetPath
            }
        } | Sort-Object Ouvert
})

# --------------------------------------------------------------------------
# 6. Historique des navigateurs : uniquement les adresses liées à l'incident
# --------------------------------------------------------------------------
Etape '6. Historique des navigateurs (indicateurs et téléchargements)'

Sauver '60_historique_navigateurs.txt' {
    $historiques = @()
    $historiques += @(Get-ChildItem -Path (Join-Path $Local 'Google\Chrome\User Data\*\History') -Force -ErrorAction SilentlyContinue)
    $historiques += @(Get-ChildItem -Path (Join-Path $Local 'Microsoft\Edge\User Data\*\History') -Force -ErrorAction SilentlyContinue)
    $historiques += @(Get-ChildItem -Path (Join-Path $Local 'BraveSoftware\Brave-Browser\User Data\*\History') -Force -ErrorAction SilentlyContinue)
    $historiques += @(Get-ChildItem -Path (Join-Path $Roaming 'Opera Software\Opera GX Stable\History') -Force -ErrorAction SilentlyContinue)
    $historiques += @(Get-ChildItem -Path (Join-Path $Roaming 'Opera Software\Opera GX Stable\*\History') -Force -ErrorAction SilentlyContinue)
    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $partage = ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    foreach ($h in $historiques) {
        "=== $($h.FullName) (modifié $($h.LastWriteTime)) ==="
        try {
            $flux = [IO.File]::Open($h.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, $partage)
            $octets = New-Object byte[] $flux.Length
            [void]$flux.Read($octets, 0, $octets.Length)
            $flux.Close()
            $texte = $latin1.GetString($octets)
            $urls = [regex]::Matches($texte, 'https?://[\x21-\x7E]{4,400}') | ForEach-Object { $_.Value } | Sort-Object -Unique
            '  -- Adresses contenant un indicateur --'
            $urls | Where-Object { $_ -match 'pdf-viewer|144\.48\.61\.40|67\.43\.50\.11|texturepacker|gpu-?z' } | ForEach-Object { "  $_" }
            '  -- Adresses de fichiers téléchargeables (archives, installeurs, scripts) --'
            $urls | Where-Object { $_ -match '\.(zip|rar|7z|iso|img|msi|msix|exe|scr|js|vbs|wsf|hta|bat|cmd|ps1|lnk)(\?|$)' } | ForEach-Object { "  $_" }
        } catch {
            "  (lecture impossible : $($_.Exception.Message))"
        }
    }
}

# --------------------------------------------------------------------------
# 7. Journaux autour des moments clés
# --------------------------------------------------------------------------
Etape '7. Journaux autour des moments clés'

function Get-EvenementsFenetre([string]$Journal, [int[]]$Ids) {
    foreach ($m in $Moments) {
        $filtre = @{ LogName = $Journal; StartTime = $m.AddMinutes(-6); EndTime = $m.AddMinutes(6) }
        if ($Ids) { $filtre['Id'] = $Ids }
        Get-WinEvent -FilterHashtable $filtre -ErrorAction SilentlyContinue |
            Where-Object { "$($_.Message)" -notmatch 'AnalysePC' } |
            ForEach-Object {
                $msg = "$($_.Message)" -replace '\s+', ' '
                [pscustomobject]@{
                    Date    = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    Journal = $Journal
                    Id      = $_.Id
                    Message = $msg.Substring(0, [Math]::Min(1500, $msg.Length))
                }
            }
    }
}

[void](SauverCsv '70_evenements_moments_cles.csv' {
    $tout = @()
    # Ouvertures de session, création de processus (si audit actif), création ou modification de tâches
    $tout += @(Get-EvenementsFenetre 'Security' @(4624, 4648, 4688, 4698, 4699, 4700, 4701, 4702))
    # Services installés, démarrage et arrêt, ouverture de session Winlogon
    $tout += @(Get-EvenementsFenetre 'System' @(7045, 7040, 1074, 6005, 6006, 7001, 7002))
    # Planificateur : enregistrement (106), mise à jour (140), lancement d'action (129, 200, 201)
    $tout += @(Get-EvenementsFenetre 'Microsoft-Windows-TaskScheduler/Operational' @(106, 140, 141, 129, 200, 201, 110, 119))
    # Commandes lancées par les clés Run et le dossier Démarrage
    $tout += @(Get-EvenementsFenetre 'Microsoft-Windows-Shell-Core/Operational' @(9705, 9706, 9707, 9708))
    # Téléchargements BITS (adresses complètes)
    $tout += @(Get-EvenementsFenetre 'Microsoft-Windows-Bits-Client/Operational' $null)
    # Abonnements WMI
    $tout += @(Get-EvenementsFenetre 'Microsoft-Windows-WMI-Activity/Operational' @(5859, 5860, 5861))
    # PowerShell : démarrage du moteur (ligne de commande de l'hôte) et blocs de script
    $tout += @(Get-EvenementsFenetre 'Windows PowerShell' @(400, 403, 600))
    $tout += @(Get-EvenementsFenetre 'Microsoft-Windows-PowerShell/Operational' @(4103, 4104))
    # Plantages et installations MSI
    $tout += @(Get-EvenementsFenetre 'Application' @(1000, 1001, 1033, 1040, 11707, 11724))
    $tout | Sort-Object Date, Journal
})

[void](SauverCsv '71_prefetch_depuis_infection.csv' {
    # Cree = première exécution connue, Modifie = dernière exécution
    Get-ChildItem -LiteralPath 'C:\Windows\Prefetch' -Filter *.pf -Force -ErrorAction SilentlyContinue |
        Where-Object { ($_.CreationTime -ge $DateInfection) -or ($_.LastWriteTime -ge $DateInfection) } |
        ForEach-Object {
            $pf = $_
            $proche = $false
            foreach ($m in $Moments) {
                if ((($pf.CreationTime -ge $m.AddMinutes(-40)) -and ($pf.CreationTime -le $m.AddMinutes(6))) -or
                    (($pf.LastWriteTime -ge $m.AddMinutes(-6)) -and ($pf.LastWriteTime -le $m.AddMinutes(6)))) { $proche = $true }
            }
            [pscustomobject]@{
                ProcheMomentCle = $proche
                Nom     = $pf.Name
                Cree    = $pf.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
                Modifie = $pf.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            }
        } | Sort-Object Cree
})

[void](SauverCsv '72_services_installes_depuis_infection.csv' {
    Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 7045; StartTime = $DateInfection } -ErrorAction SilentlyContinue |
        Select-Object TimeCreated, @{ Name = 'Message'; Expression = { $_.Message -replace '\s+', ' ' } }
})

# --------------------------------------------------------------------------
# 8. État actuel : processus et réseau
# --------------------------------------------------------------------------
Etape '8. Processus et réseau'

function Get-ProcessusSuspects {
    Get-CimInstance Win32_Process | Where-Object {
        (($_.ExecutablePath -match $Motif) -or ($_.CommandLine -match $Motif) -or ($NomsProcessus -contains $_.Name)) -and
        ($_.ProcessId -ne $PID) -and ("$($_.CommandLine)" -notmatch 'AnalysePC')
    }
}
$Suspects = @(Get-ProcessusSuspects)
[void](SauverCsv '80_processus_suspects.csv' {
    $Suspects | Select-Object ProcessId, Name, ExecutablePath, CommandLine, CreationDate, ParentProcessId
})
foreach ($p in $Suspects) { Signaler "Processus suspect en cours : PID $($p.ProcessId) $($p.Name) $($p.CommandLine)" }

[void](SauverCsv '81_processus_non_signes_dossiers_utilisateur.csv' {
    # Processus dont l'exécutable est dans le profil ou ProgramData et n'est pas signé
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and (Test-EmplacementUtilisateur $_.ExecutablePath) } | ForEach-Object {
        $sig = Get-EtatSignature $_.ExecutablePath
        if ($sig -ne 'Valid') {
            [pscustomobject]@{ PID = $_.ProcessId; Nom = $_.Name; Signature = $sig; Chemin = $_.ExecutablePath; LigneCommande = $_.CommandLine; Demarre = $_.CreationDate }
        }
    }
})

$nbConnexions = SauverCsv '82_connexions_vers_serveurs_connus.csv' {
    Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $IpsC2 -contains $_.RemoteAddress } |
        Select-Object CreationTime, State, RemoteAddress, RemotePort, OwningProcess,
            @{ Name = 'Processus'; Expression = { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path } }
}
if ($nbConnexions -gt 0) { Signaler "$nbConnexions connexion(s) vers un serveur de contrôle connu (voir 82_connexions_vers_serveurs_connus.csv)" }

Sauver '83_dns_et_parefeu.txt' {
    '--- Cache DNS : entrées liées ---'
    Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { ($_.Entry -match 'pdf-viewer') -or ($IpsC2 -contains $_.Data) } |
        ForEach-Object { "  $($_.Entry) -> $($_.Data)" }
    '--- Règles de pare-feu AnalysePC ---'
    Get-NetFirewallRule -DisplayName 'AnalysePC*' -ErrorAction SilentlyContinue | ForEach-Object {
        "  {0} | {1} | {2} | activée : {3} | {4}" -f $_.DisplayName, $_.Direction, $_.Action, $_.Enabled, (($_ | Get-NetFirewallAddressFilter).RemoteAddress -join ',')
    }
}

# --------------------------------------------------------------------------
# 9. Neutralisation complémentaire (uniquement avec -Neutraliser)
# --------------------------------------------------------------------------
if ($Neutraliser) {
    Etape '9. Neutralisation complémentaire'
    Write-Host 'Actions prévues : bloquer 144.48.61.40 et 67.43.50.11, arrêter les processus suspects,' -ForegroundColor Yellow
    Write-Host 'exporter puis supprimer la clé COM Pure.Fire, déplacer en quarantaine C:\intel,' -ForegroundColor Yellow
    Write-Host 'les fichiers réapparus, les VS12-KB2961101*.exe de Temp et les profils dotnet_perf_*.' -ForegroundColor Yellow
    $reponse = Read-Host 'Tapez OUI (en majuscules) pour continuer'

    if ($reponse -ceq 'OUI') {
        $Quarantaine = "C:\AnalysePC_Quarantaine2_$Horodatage"
        New-Item -ItemType Directory -Path $Quarantaine -Force | Out-Null
        $JournalActions = Join-Path $Sortie '99_neutralisation.txt'
        function Noter([string]$Texte) {
            $ligne = "{0}  {1}" -f (Get-Date -Format 'HH:mm:ss'), $Texte
            Write-Host "  $ligne"
            Add-Content -Path $JournalActions -Value $ligne -Encoding UTF8
        }

        # a) Pare-feu
        foreach ($ip in $IpsC2) {
            $nomRegle = "AnalysePC - blocage $ip"
            if (Get-NetFirewallRule -DisplayName $nomRegle -ErrorAction SilentlyContinue) {
                Noter "Règle de pare-feu déjà présente : $nomRegle"
            } else {
                try {
                    New-NetFirewallRule -DisplayName $nomRegle -Direction Outbound -Action Block -RemoteAddress $ip -Profile Any -ErrorAction Stop | Out-Null
                    Noter "Règle de pare-feu créée : blocage sortant vers $ip"
                } catch { Noter "ECHEC règle pare-feu $ip : $($_.Exception.Message)" }
            }
        }

        # b) Processus
        foreach ($p in @(Get-ProcessusSuspects)) {
            try {
                Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop
                Noter "Processus arrêté : PID $($p.ProcessId) $($p.Name) [$($p.CommandLine)]"
            } catch { Noter "ECHEC arrêt PID $($p.ProcessId) $($p.Name) : $($_.Exception.Message)" }
        }

        # c) Clé COM Pure.Fire : export puis suppression
        $n = 0
        foreach ($cle in @("HKCU\Software\Classes\CLSID\$Clsid", "HKCU\Software\Classes\TypeLib\$TypeLib", 'HKCU\Software\Classes\Pure.Fire')) {
            & reg.exe query $cle 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { Noter "Clé absente : $cle"; continue }
            $n++
            $export = Join-Path $Quarantaine ("registre_{0:D2}.reg" -f $n)
            & reg.exe export $cle $export /y 2>&1 | Out-Null
            if ((Test-Path -LiteralPath $export) -and ((Get-Item -LiteralPath $export).Length -gt 0)) {
                & reg.exe delete $cle /f 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) { Noter "Clé exportée ($export) puis supprimée : $cle" }
                else { Noter "ECHEC suppression de la clé : $cle" }
            } else {
                Noter "ECHEC export, clé conservée : $cle"
            }
        }

        # d) Quarantaine par déplacement
        Start-Sleep -Seconds 2
        $aDeplacer = @(
            'C:\intel',
            (Join-Path $Roaming 'NonceChange'),
            (Join-Path $Roaming 'GPU-Z'),
            (Join-Path $Roaming 'Microsoft\clspack.exe')
        )
        $temp = Join-Path $Local 'Temp'
        $aDeplacer += @(Get-ChildItem -LiteralPath $temp -Force -File -Filter 'VS12-KB2961101*.exe' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        $aDeplacer += @(Get-ChildItem -LiteralPath $temp -Force -Directory -Filter 'dotnet_perf_*' -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
        $aDeplacer += @($Copies | Where-Object { $_.EmpreinteIdentique } | ForEach-Object { $_.Chemin })
        $i = 0
        foreach ($source in ($aDeplacer | Select-Object -Unique)) {
            if (-not (Test-Path -LiteralPath $source)) { continue }
            $i++
            $destination = Join-Path $Quarantaine ("{0:D2}_{1}" -f $i, (Split-Path -Path $source -Leaf))
            try {
                Move-Item -LiteralPath $source -Destination $destination -Force -ErrorAction Stop
                Noter "Déplacé : $source  ->  $destination"
            } catch { Noter "ECHEC déplacement $source : $($_.Exception.Message)" }
        }
        Noter "Quarantaine : $Quarantaine"
        Noter 'Les déclencheurs listés dans 00_SYNTHESE.txt ne sont pas supprimés : à traiter après examen.'
    } else {
        Write-Host '  Neutralisation annulée.' -ForegroundColor Yellow
    }
}

# --------------------------------------------------------------------------
# Synthèse et archive
# --------------------------------------------------------------------------
$lignes = @("Synthèse de la recherche du $($DebutScript.ToString('dd/MM/yyyy HH:mm'))", '')
if ($Synthese.Count -eq 0) {
    $lignes += 'Aucun élément signalé automatiquement.'
    $lignes += 'Cela ne prouve pas l''absence de déclencheur : examiner les fichiers 10, 20, 30, 51 et 70.'
} else {
    $lignes += "$($Synthese.Count) élément(s) signalé(s) :"
    foreach ($s in $Synthese) { $lignes += " - $s" }
}
$lignes | Out-File -FilePath (Join-Path $Sortie '00_SYNTHESE.txt') -Encoding UTF8

Write-Host ''
Write-Host '=== SYNTHESE ===' -ForegroundColor Green
foreach ($l in $lignes) { Write-Host $l }

Stop-Transcript | Out-Null
$Archive = "$Sortie.zip"
try {
    Compress-Archive -Path (Join-Path $Sortie '*') -DestinationPath $Archive -Force -ErrorAction Stop
    Write-Host ''
    Write-Host "Dossier : $Sortie"
    Write-Host "Archive : $Archive"
    Write-Host "SHA256  : $((Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash)"
} catch {
    Write-Host "Archive non créée : $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host "Dossier : $Sortie"
}
