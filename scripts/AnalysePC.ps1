#Requires -RunAsAdministrator
#Requires -Version 5.1
<#
.SYNOPSIS
    AnalysePC : diagnostic de sécurité et de santé d'un PC Windows (LECTURE SEULE).

.DESCRIPTION
    Ce script ne supprime, ne déplace et ne modifie rien. Il examine :
      - les processus (mémoire, processeur, activité disque/réseau, faux processus système)
      - les connexions réseau, ports ouverts, DNS, proxy, fichier hosts
      - tout ce qui se lance automatiquement : registre, dossier Démarrage, services,
        pilotes, tâches planifiées (y compris cachées), abonnements WMI,
        détournements d'applications (IFEO, qui peuvent fermer/bloquer des programmes)
      - les fichiers récents, cachés ou déguisés dans les dossiers sensibles
      - Windows Defender (état, menaces, exclusions)
      - les journaux d'événements (plantages, manque de mémoire, erreurs disque...)
      - la configuration de sécurité, la santé des disques et l'intégrité de Windows

    Résultat : un dossier AnalysePC_<date> sur le Bureau contenant
      - rapport.html : version lisible en couleurs
      - rapport.txt  : version texte complète, à transmettre pour analyse

.PARAMETER JoursFichiers
    Fichiers créés ou modifiés depuis combien de jours (défaut 30).
.PARAMETER JoursEvenements
    Période couverte par les journaux d'événements, en jours (défaut 14).
.PARAMETER VerifSysteme
    Lance aussi "sfc /verifyonly" (vérification des fichiers Windows, 10 à 20 min).
.PARAMETER ScanDefender
    Lance une analyse rapide Windows Defender avant le rapport.
.PARAMETER Anonymiser
    Remplace le nom d'utilisateur et le nom du PC dans les rapports.
.PARAMETER PasOuvrir
    N'ouvre pas le rapport HTML à la fin.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\AnalysePC.ps1
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\AnalysePC.ps1 -ScanDefender -VerifSysteme -Anonymiser
#>
[CmdletBinding()]
param(
    [int]$JoursFichiers = 30,
    [int]$JoursEvenements = 14,
    [switch]$VerifSysteme,
    [switch]$ScanDefender,
    [switch]$Anonymiser,
    [switch]$PasOuvrir
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
$debut          = Get-Date
$dateFichiers   = $debut.AddDays(-$JoursFichiers)
$dateEvenements = $debut.AddDays(-$JoursEvenements)
$nbCoeurs       = [Environment]::ProcessorCount

# =============================================================================
#  Dossier de sortie
# =============================================================================
$bureau = [Environment]::GetFolderPath('Desktop')
if (-not $bureau -or -not (Test-Path -LiteralPath $bureau)) { $bureau = $env:USERPROFILE }
$dossierSortie = Join-Path $bureau ('AnalysePC_' + $debut.ToString('yyyyMMdd_HHmm'))
New-Item -ItemType Directory -Path $dossierSortie -Force | Out-Null
$fichierTxt  = Join-Path $dossierSortie 'rapport.txt'
$fichierHtml = Join-Path $dossierSortie 'rapport.html'

# =============================================================================
#  Fonctions d'infrastructure (rapport)
# =============================================================================
$script:Constats        = New-Object System.Collections.Generic.List[object]
$script:Sections        = New-Object System.Collections.Generic.List[object]
$script:SectionCourante = $null
$ordreGravite = @{ 'CRITIQUE' = 0; 'ELEVE' = 1; 'MOYEN' = 2; 'INFO' = 3 }

function Start-Section([string]$Titre) {
    $s = [pscustomobject]@{ Titre = $Titre; Lignes = (New-Object System.Collections.Generic.List[string]) }
    $script:Sections.Add($s)
    $script:SectionCourante = $s
    Write-Host ''
    Write-Host ('[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Titre) -ForegroundColor Cyan
}

function Add-Ligne([string]$Texte = '') { $script:SectionCourante.Lignes.Add($Texte) }

function Add-Table($Objets, [object[]]$Proprietes = $null) {
    $liste = @($Objets | Where-Object { $_ })
    if ($liste.Count -eq 0) { Add-Ligne '  (rien à signaler)'; return }
    if ($Proprietes) { $txt = $liste | Format-Table -Property $Proprietes -AutoSize -Wrap | Out-String -Width 400 }
    else             { $txt = $liste | Format-Table -AutoSize -Wrap | Out-String -Width 400 }
    foreach ($l in ($txt -split "`r?`n")) { if ($l.Trim()) { Add-Ligne ('  ' + $l.TrimEnd()) } }
}

function Add-Constat {
    param(
        [ValidateSet('CRITIQUE','ELEVE','MOYEN','INFO')][string]$Gravite,
        [string]$Categorie,
        [string]$Description,
        [string]$Element = '',
        [string]$Conseil = ''
    )
    $script:Constats.Add([pscustomobject]@{
        Gravite = $Gravite; Ordre = $ordreGravite[$Gravite]; Categorie = $Categorie
        Description = $Description; Element = $Element; Conseil = $Conseil
    })
    $couleur = switch ($Gravite) { 'CRITIQUE' { 'Magenta' } 'ELEVE' { 'Red' } 'MOYEN' { 'Yellow' } default { 'Gray' } }
    if ($Gravite -ne 'INFO') { Write-Host ('   [{0}] {1} : {2}' -f $Gravite, $Categorie, $Description) -ForegroundColor $couleur }
}

function Get-PireGravite([string]$A, [string]$B) {
    if (-not $A) { return $B }
    if (-not $B) { return $A }
    if ($ordreGravite[$A] -le $ordreGravite[$B]) { return $A } else { return $B }
}

function OuiNon($Valeur) { if ($Valeur) { 'Oui' } else { 'Non' } }

function Couper([string]$Texte, [int]$Max = 300) {
    if (-not $Texte) { return '' }
    $t = ($Texte -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { return $t.Substring(0, $Max) + '...' }
    return $t
}

# =============================================================================
#  Fonctions d'analyse
# =============================================================================
$regexCheminSuspect   = '(?i)\\AppData\\|\\Temp\\|\\Tmp\\|\\Users\\Public\\|\\Downloads\\|\\ProgramData\\(?!Microsoft\\|Package Cache\\)|\\Windows\\Tasks\\|\\Windows\\Fonts\\|\\Windows\\debug\\|\\\$Recycle\.Bin\\|\\PerfLogs\\'
$regexLanceurs        = '(?i)\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32|msiexec|certutil|bitsadmin|forfiles|conhost|wmic|curl)\.exe$'
$regexCmdForte        = '(?i)(-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{30,}|frombase64string|invoke-expression|\biex\b|downloadstring|downloadfile|downloaddata|net\.webclient|start-bitstransfer|bitsadmin\s+/transfer|certutil.*(urlcache|-decode)|mshta\s+(https?|javascript|vbscript)|regsvr32.*/i:\s*http|rundll32.*javascript|vssadmin.*delete|shadowcopy\s+delete|add-mppreference|set-mppreference|-exclusionpath)'
$regexCmdFaible       = '(?i)(https?://|taskkill|stop-process|reg(\.exe)?\s+add|schtasks(\.exe)?\s+/create|bcdedit|wscript|cscript|executionpolicy\s+bypass|-ep\s+bypass|-w(indowstyle)?\s+h(idden)?\b|\.vbs\b|\.hta\b)'
$regexNomsMalveillants = '(?i)\b(xmrig|xmr-stak|nicehash|minerd|cpuminer|ethminer|phoenixminer|nbminer|t-rex|lolminer|cgminer|bfgminer|njrat|darkcomet|quasar|asyncrat|remcos|nanocore|kmspico|kmsauto)\b'
$regexOutilsDistance  = '(?i)\b(anydesk|teamviewer|rustdesk|ammyy|supremo|screenconnect|connectwise|splashtop|ultraviewer|ngrok|plink|radmin|atera|netsupport|client32|remoteutilities|rutserv|dwagent|tightvnc|ultravnc|realvnc|winvnc)\b'
$regexPUP             = '(?i)(onelaunch|wave browser|webnavigator|shift browser|segurazo|santivirus|pc accelerate|driver support|driver booster|driver easy|advanced systemcare|reimage|restoro|fortect|bytefence|web companion|webcompanion|pc app store|pc optimizer|total pc cleaner|systweak|advanced system optimizer|searchprotect|mindspark|\bchromium\b|kmspico|kms ?auto)'

$cacheSignatures = @{}
function Get-InfoSignature([string]$Chemin) {
    if ([string]::IsNullOrWhiteSpace($Chemin)) { return [pscustomobject]@{ Statut = 'Inconnu'; Editeur = '' } }
    if ($cacheSignatures.ContainsKey($Chemin)) { return $cacheSignatures[$Chemin] }
    $res = [pscustomobject]@{ Statut = 'Introuvable'; Editeur = '' }
    if (Test-Path -LiteralPath $Chemin -PathType Leaf) {
        try {
            $sig = Get-AuthenticodeSignature -LiteralPath $Chemin -ErrorAction Stop
            $editeur = ''
            if ($sig.SignerCertificate) { $editeur = ($sig.SignerCertificate.Subject -replace '^CN="?([^,"]+).*$', '$1') }
            $res = [pscustomobject]@{ Statut = [string]$sig.Status; Editeur = $editeur }
        } catch { $res = [pscustomobject]@{ Statut = 'Erreur'; Editeur = '' } }
    }
    $cacheSignatures[$Chemin] = $res
    return $res
}

function Get-CheminExe([string]$Commande) {
    if ([string]::IsNullOrWhiteSpace($Commande)) { return $null }
    $c = [Environment]::ExpandEnvironmentVariables($Commande.Trim())
    $c = $c -replace '^\\\?\?\\', ''
    if ($c -match '^(?i)\\SystemRoot\\') { $c = $env:SystemRoot + $c.Substring(11) }
    if ($c.StartsWith('"')) {
        $fin = $c.IndexOf('"', 1)
        if ($fin -gt 1) { $c = $c.Substring(1, $fin - 1) } else { $c = $c.Trim('"') }
    } elseif ($c -match '^(?i)(.+?\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|dll|cpl|msc|jar|sys))(\s|,|$)') {
        $c = $Matches[1]
    } else {
        $c = ($c -split '\s+')[0]
    }
    if ($c -match '^(?i)system32\\') { $c = Join-Path $env:SystemRoot $c }
    try { $racine = [System.IO.Path]::IsPathRooted($c) } catch { return $c }
    if (-not $racine) {
        foreach ($d in @("$env:SystemRoot\System32", $env:SystemRoot, "$env:SystemRoot\SysWOW64")) {
            $essai = Join-Path $d $c
            if (Test-Path -LiteralPath $essai -PathType Leaf) { return $essai }
            if (Test-Path -LiteralPath "$essai.exe" -PathType Leaf) { return "$essai.exe" }
        }
    }
    return $c
}

# Analyse une commande lancée automatiquement (registre, tâche, service...)
function Test-ElementLancement {
    param([string]$Commande, [string]$Categorie = '', [string]$Libelle = '', [switch]$SansConstat)
    $chemin  = Get-CheminExe $Commande
    $sig     = Get-InfoSignature $chemin
    $grav    = $null
    $raisons = New-Object System.Collections.Generic.List[string]

    if ($Commande -match $regexNomsMalveillants) { $grav = 'CRITIQUE'; $raisons.Add('nom d''outil malveillant ou de minage connu') }
    if ($sig.Statut -eq 'HashMismatch') { $grav = Get-PireGravite $grav 'CRITIQUE'; $raisons.Add('signature numérique invalide (fichier modifié)') }

    if ($chemin -match $regexLanceurs) {
        if ($Commande -match $regexCmdForte)          { $grav = Get-PireGravite $grav 'ELEVE'; $raisons.Add('commande système avec instructions suspectes (téléchargement, encodage, antivirus...)') }
        elseif ($Commande -match $regexCheminSuspect) { $grav = Get-PireGravite $grav 'ELEVE'; $raisons.Add('lance un fichier situé dans un dossier utilisateur/temporaire') }
        elseif ($Commande -match $regexCmdFaible)     { $grav = Get-PireGravite $grav 'MOYEN'; $raisons.Add('commande système avec arguments à vérifier') }
        else                                          { $grav = Get-PireGravite $grav 'INFO';  $raisons.Add('passe par un interpréteur de commandes') }
    } else {
        if ($chemin -and $chemin -match $regexCheminSuspect -and $sig.Statut -notin 'Valid','Introuvable') {
            $grav = Get-PireGravite $grav 'ELEVE'; $raisons.Add('exécutable non signé dans un dossier utilisateur/temporaire')
        } elseif ($sig.Statut -notin 'Valid','Introuvable','Inconnu') {
            $grav = Get-PireGravite $grav 'INFO'; $raisons.Add('non signé')
        }
        if ($Commande -match $regexCmdForte) { $grav = Get-PireGravite $grav 'MOYEN'; $raisons.Add('arguments suspects') }
    }
    if ($Commande -match $regexOutilsDistance) { $grav = Get-PireGravite $grav 'MOYEN'; $raisons.Add('outil de prise en main à distance') }
    if ($sig.Statut -eq 'Introuvable' -and $chemin) { $grav = Get-PireGravite $grav 'INFO'; $raisons.Add('fichier cible introuvable (reste de désinstallation ?)') }

    if (-not $SansConstat -and $grav -and $grav -ne 'INFO') {
        Add-Constat $grav $Categorie ('{0} : {1}' -f $Libelle, ($raisons -join ', ')) $Commande 'Vérifier l''éditeur et l''emplacement. Ne rien supprimer avant analyse du rapport.'
    }
    return [pscustomobject]@{ Chemin = $chemin; Signature = $sig.Statut; Editeur = $sig.Editeur; Gravite = $grav; Raisons = ($raisons -join ', ') }
}

# Distance entre deux noms (détection des imitations type "scvhost")
function Get-Distance([string]$A, [string]$B) {
    $n = $A.Length
    $m = $B.Length
    $l = $m + 1
    $d = New-Object 'int[]' (($n + 1) * $l)
    for ($i = 0; $i -le $n; $i++) { $d[$i * $l] = $i }
    for ($j = 0; $j -le $m; $j++) { $d[$j] = $j }
    for ($i = 1; $i -le $n; $i++) {
        for ($j = 1; $j -le $m; $j++) {
            $cout = 1
            if ($A[$i - 1] -ceq $B[$j - 1]) { $cout = 0 }
            $haut   = $d[($i - 1) * $l + $j] + 1
            $gauche = $d[$i * $l + $j - 1] + 1
            $diag   = $d[($i - 1) * $l + $j - 1] + $cout
            $v = $haut
            if ($gauche -lt $v) { $v = $gauche }
            if ($diag -lt $v)   { $v = $diag }
            if ($i -gt 1 -and $j -gt 1 -and $A[$i - 1] -ceq $B[$j - 2] -and $A[$i - 2] -ceq $B[$j - 1]) {
                $trans = $d[($i - 2) * $l + $j - 2] + 1
                if ($trans -lt $v) { $v = $trans }
            }
            $d[$i * $l + $j] = $v
        }
    }
    return $d[$n * $l + $m]
}

function Test-EnteteMZ([string]$Chemin) {
    try {
        $fs = [System.IO.File]::Open($Chemin, 'Open', 'Read', 'ReadWrite')
        try {
            $b = New-Object byte[] 2
            $n = $fs.Read($b, 0, 2)
            return ($n -eq 2 -and $b[0] -eq 0x4D -and $b[1] -eq 0x5A)
        } finally { $fs.Close() }
    } catch { return $null }
}

function New-EnsembleTexte([string[]]$Valeurs) {
    $h = New-Object 'System.Collections.Generic.HashSet[string]' -ArgumentList ([StringComparer]::OrdinalIgnoreCase)
    foreach ($v in $Valeurs) { [void]$h.Add($v) }
    return ,$h
}

# Parcours rapide de dossiers avec profondeur limitée et exclusions
function Get-FichiersRapide {
    param([string]$Racine, [int]$ProfondeurMax, [string[]]$Exclure, $Extensions)
    $resultat = New-Object System.Collections.Generic.List[object]
    $pile = New-Object System.Collections.Generic.Stack[object]
    $pile.Push([pscustomobject]@{ D = $Racine; P = 0 })
    while ($pile.Count -gt 0) {
        $e = $pile.Pop()
        try {
            foreach ($f in [System.IO.Directory]::EnumerateFiles($e.D)) {
                try { $x = [System.IO.Path]::GetExtension($f) } catch { continue }
                if ($x -and $Extensions.Contains($x)) { $resultat.Add([pscustomobject]@{ Chemin = $f; Profondeur = $e.P }) }
            }
        } catch {}
        if ($e.P -lt $ProfondeurMax) {
            try {
                foreach ($d in [System.IO.Directory]::EnumerateDirectories($e.D)) {
                    $n = [System.IO.Path]::GetFileName($d)
                    if ($Exclure -contains $n) { continue }
                    try { if ([System.IO.File]::GetAttributes($d) -band [System.IO.FileAttributes]::ReparsePoint) { continue } } catch { continue }
                    $pile.Push([pscustomobject]@{ D = $d; P = $e.P + 1 })
                }
            } catch {}
        }
    }
    return ,$resultat
}

function Get-ValeursRegistre([string]$Cle) {
    $item = Get-Item -LiteralPath $Cle
    if (-not $item) { return }
    foreach ($nom in $item.GetValueNames()) {
        $val = [string]$item.GetValue($nom)
        if (-not $val) { continue }
        if ($nom -eq '') { $nom = '(par défaut)' }
        [pscustomobject]@{ Cle = $Cle; Nom = $nom; Valeur = $val }
    }
}

function Format-Duree([TimeSpan]$D) {
    if ($D.TotalDays -ge 1)    { return ('{0:0.#} j' -f $D.TotalDays) }
    if ($D.TotalHours -ge 1)   { return ('{0:0.#} h' -f $D.TotalHours) }
    if ($D.TotalMinutes -ge 1) { return ('{0:0} min' -f $D.TotalMinutes) }
    return ('{0:0} s' -f $D.TotalSeconds)
}

function Get-DescriptionDeclencheur($Trig) {
    $type  = [string]$Trig.CimClass.CimClassName
    $heure = ''
    if ($Trig.StartBoundary) { try { $heure = ([datetime]$Trig.StartBoundary).ToString('HH:mm') } catch {} }
    switch ($type) {
        'MSFT_TaskBootTrigger'         { $txt = 'Au démarrage du PC' }
        'MSFT_TaskLogonTrigger'        { if ($Trig.UserId) { $txt = "À l'ouverture de session de " + $Trig.UserId } else { $txt = "À chaque ouverture de session" } }
        'MSFT_TaskDailyTrigger'        { $txt = "Tous les $($Trig.DaysInterval) jour(s) à $heure" }
        'MSFT_TaskWeeklyTrigger'       { $txt = "Toutes les $($Trig.WeeksInterval) semaine(s) à $heure" }
        'MSFT_TaskTimeTrigger'         { $txt = "À partir du $($Trig.StartBoundary)" }
        'MSFT_TaskIdleTrigger'         { $txt = 'Quand le PC est inactif' }
        'MSFT_TaskEventTrigger'        { $txt = "Sur un événement du journal" }
        'MSFT_TaskRegistrationTrigger' { $txt = 'À la création ou modification de la tâche' }
        'MSFT_TaskSessionStateChangeTrigger' {
            $etats = @{ 1 = 'connexion console'; 2 = 'déconnexion console'; 3 = 'connexion à distance'; 4 = 'déconnexion à distance'; 7 = 'verrouillage'; 8 = 'déverrouillage' }
            $txt = 'Changement de session (' + $etats[[int]$Trig.StateChange] + ')'
        }
        default { $txt = ($type -replace '^MSFT_Task', '') }
    }
    if ($Trig.Repetition -and $Trig.Repetition.Interval) {
        try {
            $txt += ', répété toutes les ' + (Format-Duree ([System.Xml.XmlConvert]::ToTimeSpan($Trig.Repetition.Interval)))
            if ($Trig.Repetition.Duration) { $txt += ' pendant ' + (Format-Duree ([System.Xml.XmlConvert]::ToTimeSpan($Trig.Repetition.Duration))) }
            else { $txt += ' sans fin' }
        } catch {}
    }
    if ($Trig.Delay) { try { $txt += ' (délai ' + (Format-Duree ([System.Xml.XmlConvert]::ToTimeSpan($Trig.Delay))) + ')' } catch {} }
    if ($Trig.Enabled -eq $false) { $txt += ' [désactivé]' }
    return $txt
}

function Get-NomExtension([string]$DossierVersion, $Manifest) {
    $nom = [string]$Manifest.name
    if ($nom -match '^__MSG_(.+)__$') {
        $cle = $Matches[1]
        $locales = @('fr', 'en', 'en_US', [string]$Manifest.default_locale) | Where-Object { $_ } | Select-Object -Unique
        foreach ($loc in $locales) {
            $f = Join-Path $DossierVersion "_locales\$loc\messages.json"
            if (Test-Path -LiteralPath $f) {
                try {
                    $msgs = Get-Content -LiteralPath $f -Raw -Encoding UTF8 | ConvertFrom-Json
                    $prop = $msgs.PSObject.Properties | Where-Object { $_.Name -ieq $cle } | Select-Object -First 1
                    if ($prop) { return [string]$prop.Value.message }
                } catch {}
            }
        }
    }
    return $nom
}

# =============================================================================
#  Démarrage
# =============================================================================
Clear-Host
Write-Host '=====================================================================' -ForegroundColor Cyan
Write-Host '  AnalysePC : diagnostic de sécurité (lecture seule, rien n''est modifié)' -ForegroundColor Cyan
Write-Host '  Durée estimée : 3 à 10 minutes selon le PC' -ForegroundColor Cyan
Write-Host '=====================================================================' -ForegroundColor Cyan

$profils = @(Get-CimInstance Win32_UserProfile | Where-Object {
    -not $_.Special -and $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) -and
    $_.LocalPath -notmatch '\\(systemprofile|LocalService|NetworkService)$' })
$nomsParSid = @{}
foreach ($pr in $profils) { $nomsParSid[$pr.SID] = Split-Path $pr.LocalPath -Leaf }
$sidsCharges = @(Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' } | ForEach-Object { $_.PSChildName })

function Get-CleCourte([string]$Cle) {
    if ($Cle -match '^Registry::HKEY_USERS\\(S-1-5-21-[\d-]+)(.*)$') {
        $u = $nomsParSid[$Matches[1]]
        if (-not $u) { $u = $Matches[1] }
        return ('HKU(' + $u + ')' + $Matches[2])
    }
    return ($Cle -replace '^HKLM:', 'HKLM')
}

# =============================================================================
#  1. Système
# =============================================================================
Start-Section '1. Informations système'
$os      = Get-CimInstance Win32_OperatingSystem
$cs      = Get-CimInstance Win32_ComputerSystem
$cpuInfo = Get-CimInstance Win32_Processor | Select-Object -First 1
$verWin  = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$ramTotMo   = [math]::Round($os.TotalVisibleMemorySize / 1KB, 0)
$ramLibreMo = [math]::Round($os.FreePhysicalMemory / 1KB, 0)
$ramPct     = [math]::Round((1 - $os.FreePhysicalMemory / $os.TotalVisibleMemorySize) * 100, 0)
$engageMo   = [math]::Round(($os.TotalVirtualMemorySize - $os.FreeVirtualMemory) / 1KB, 0)
$limiteMo   = [math]::Round($os.TotalVirtualMemorySize / 1KB, 0)
$uptime     = $debut - $os.LastBootUpTime
$memPerf    = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
$nonPagineMo  = [math]::Round($memPerf.PoolNonpagedBytes / 1MB, 0)
$paginePoolMo = [math]::Round($memPerf.PoolPagedBytes / 1MB, 0)

Add-Ligne ('Ordinateur        : {0} ({1} {2})' -f $env:COMPUTERNAME, $cs.Manufacturer, $cs.Model)
Add-Ligne ('Windows           : {0} {1} (build {2}.{3})' -f $os.Caption, $verWin.DisplayVersion, $os.BuildNumber, $verWin.UBR)
Add-Ligne ('Processeur        : {0} ({1} coeurs logiques)' -f ($cpuInfo.Name -replace '\s+', ' '), $nbCoeurs)
Add-Ligne ('Mémoire vive      : {0} Mo au total, {1} Mo libres ({2} % utilisés)' -f $ramTotMo, $ramLibreMo, $ramPct)
Add-Ligne ('Mémoire engagée   : {0} / {1} Mo (RAM + fichier d''échange)' -f $engageMo, $limiteMo)
Add-Ligne ('Pools noyau       : non paginé {0} Mo | paginé {1} Mo (mémoire des pilotes, invisible dans le Gestionnaire des tâches)' -f $nonPagineMo, $paginePoolMo)
Add-Ligne ('Dernier démarrage : {0} (allumé depuis {1} j {2} h)' -f $os.LastBootUpTime.ToString('dd/MM/yyyy HH:mm'), $uptime.Days, $uptime.Hours)
Add-Ligne ('Analyse lancée par: {0} | période fichiers {1} j | période journaux {2} j' -f $env:USERNAME, $JoursFichiers, $JoursEvenements)
Add-Ligne ''
Add-Ligne 'Disques :'
$disques = foreach ($ld in Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3') {
    $pctLibre = 0; if ($ld.Size) { $pctLibre = [math]::Round($ld.FreeSpace / $ld.Size * 100, 0) }
    if ($ld.Size -and $pctLibre -lt 10) { Add-Constat 'MOYEN' 'Système' ("Disque {0} presque plein ({1} % libre)" -f $ld.DeviceID, $pctLibre) '' 'Un disque plein provoque lenteurs, plantages et fichiers corrompus. Libérer de la place.' }
    [pscustomobject]@{ Lecteur = $ld.DeviceID; Nom = $ld.VolumeName; Taille_Go = [math]::Round($ld.Size / 1GB, 0); Libre_Go = [math]::Round($ld.FreeSpace / 1GB, 1); Libre_pct = $pctLibre; Format = $ld.FileSystem }
}
Add-Table $disques

if ($ramPct -ge 90) { Add-Constat 'MOYEN' 'Mémoire' ("Mémoire vive saturée ({0} % utilisés)" -f $ramPct) '' 'Voir la section Processus pour identifier le responsable.' }
if ($limiteMo -gt 0 -and $engageMo / $limiteMo -ge 0.9) { Add-Constat 'MOYEN' 'Mémoire' ("Mémoire engagée proche de la limite ({0}/{1} Mo) : Windows risque de fermer des applications" -f $engageMo, $limiteMo) '' 'Vérifier le fichier d''échange et les processus gourmands.' }
if ($nonPagineMo -ge 1024) { Add-Constat 'MOYEN' 'Mémoire' ("Pool non paginé très élevé ({0} Mo) : fuite mémoire probable d'un pilote" -f $nonPagineMo) '' 'Souvent un pilote réseau, antivirus ou VPN. Mettre à jour les pilotes réseau en priorité.' }
if ($uptime.TotalDays -ge 14) { Add-Constat 'INFO' 'Système' ("PC non redémarré depuis {0} jours" -f $uptime.Days) '' 'Un vrai redémarrage (pas un arrêt avec démarrage rapide) libère la mémoire.' }

# =============================================================================
#  2. Antivirus et Windows Defender
# =============================================================================
Start-Section '2. Antivirus et Windows Defender'
$tiersActif = $false
foreach ($av in Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct) {
    $hex   = '{0:X6}' -f [int]$av.productState
    $actif = $hex.Substring(2, 2) -in @('10', '11')
    $ajour = $hex.Substring(4, 2) -eq '00'
    Add-Ligne ('Antivirus déclaré : {0} | actif : {1} | à jour : {2}' -f $av.displayName, (OuiNon $actif), (OuiNon $ajour))
    if ($actif -and $av.displayName -notmatch 'Defender') { $tiersActif = $true }
}

$mp = Get-MpComputerStatus
if ($mp) {
    Add-Ligne ''
    Add-Ligne ('Defender - mode               : {0}' -f $mp.AMRunningMode)
    Add-Ligne ('Defender - antivirus actif    : {0}' -f (OuiNon $mp.AntivirusEnabled))
    Add-Ligne ('Defender - temps réel         : {0}' -f (OuiNon $mp.RealTimeProtectionEnabled))
    Add-Ligne ('Defender - comportement       : {0}' -f (OuiNon $mp.BehaviorMonitorEnabled))
    Add-Ligne ('Defender - anti-falsification : {0}' -f (OuiNon $mp.IsTamperProtected))
    Add-Ligne ('Defender - signatures du      : {0} ({1} jour(s))' -f $mp.AntivirusSignatureLastUpdated, $mp.AntivirusSignatureAge)
    Add-Ligne ('Defender - dernière analyse   : rapide {0} | complète {1}' -f $mp.QuickScanEndTime, $mp.FullScanEndTime)
    if (-not $tiersActif) {
        if (-not $mp.RealTimeProtectionEnabled) { Add-Constat 'ELEVE' 'Antivirus' 'Protection en temps réel de Windows Defender désactivée' '' 'La réactiver dans Sécurité Windows. Si elle se coupe toute seule, c''est un signe fort d''infection.' }
        if (-not $mp.AntivirusEnabled) { Add-Constat 'ELEVE' 'Antivirus' 'Antivirus Windows Defender désactivé et aucun autre antivirus actif' '' 'Réactiver Defender ou installer un antivirus.' }
        if (-not $mp.IsTamperProtected) { Add-Constat 'MOYEN' 'Antivirus' 'Protection contre les falsifications désactivée' '' 'Sécurité Windows > Protection contre les virus > Gérer les paramètres > Protection contre les falsifications.' }
        if ($mp.AntivirusSignatureAge -gt 7) { Add-Constat 'MOYEN' 'Antivirus' ("Signatures antivirus vieilles de {0} jours" -f $mp.AntivirusSignatureAge) '' 'Lancer Windows Update. Si la mise à jour échoue, un malware peut la bloquer.' }
    }
} else {
    Add-Ligne 'Impossible d''interroger Windows Defender.'
    if (-not $tiersActif) { Add-Constat 'ELEVE' 'Antivirus' 'Windows Defender ne répond pas et aucun autre antivirus actif' '' 'Vérifier le service WinDefend.' }
}

$polDef = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
$polRtp = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
if ($polDef.DisableAntiSpyware -eq 1 -or $polDef.DisableAntiVirus -eq 1) { Add-Constat 'ELEVE' 'Antivirus' 'Defender désactivé par une stratégie (registre Policies)' 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' 'Technique fréquente des malwares. Ne pas corriger soi-même avant analyse.' }
if ($polRtp.DisableRealtimeMonitoring -eq 1) { Add-Constat 'ELEVE' 'Antivirus' 'Protection temps réel désactivée par stratégie' 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' '' }

Add-Ligne ''
Add-Ligne 'Exclusions Defender (fichiers/dossiers que l''antivirus ignore) :'
$pref = Get-MpPreference
$exclusions = New-Object System.Collections.Generic.List[object]
foreach ($couple in @(@('Dossier/fichier', $pref.ExclusionPath), @('Processus', $pref.ExclusionProcess), @('Extension', $pref.ExclusionExtension), @('Adresse IP', $pref.ExclusionIpAddress))) {
    foreach ($v in $couple[1]) {
        if (-not $v -or $v -match '^N/A') { continue }
        $exclusions.Add([pscustomobject]@{ Type = $couple[0]; Valeur = $v })
        $g = 'MOYEN'
        if ($v -match $regexCheminSuspect -or $v -match '^[A-Za-z]:\\?$' -or $v -match '^\.?(exe|dll|ps1|bat|cmd|vbs|js|scr)$' -or $v -match '(?i)\\Windows\\?$|\\System32|powershell|cmd\.exe') { $g = 'ELEVE' }
        Add-Constat $g 'Antivirus' ("Exclusion Defender : {0} '{1}'" -f $couple[0], $v) $v 'Si vous n''avez pas créé cette exclusion vous-même, un malware l''a probablement ajoutée pour se cacher.'
    }
}
Add-Table $exclusions

if ($ScanDefender) {
    Write-Host '   Analyse rapide Defender en cours (quelques minutes)...' -ForegroundColor DarkGray
    Update-MpSignature | Out-Null
    Start-MpScan -ScanType QuickScan
    Add-Ligne ''
    Add-Ligne 'Une analyse rapide Defender a été lancée pendant ce diagnostic.'
}

Add-Ligne ''
Add-Ligne 'Historique des menaces détectées par Defender :'
$menaces    = @(Get-MpThreat)
$detections = @(Get-MpThreatDetection)
$severites  = @{ 0 = 'Inconnue'; 1 = 'Faible'; 2 = 'Modérée'; 4 = 'Élevée'; 5 = 'Grave' }
$tableMenaces = foreach ($m in $menaces) {
    if (-not $m) { continue }
    $det = $detections | Where-Object { $_.ThreatID -eq $m.ThreatID } | Sort-Object InitialDetectionTime -Descending | Select-Object -First 1
    $fichiers = (@($m.Resources) + @($det.Resources) | Where-Object { $_ } | Select-Object -Unique) -join ' ; '
    if ($m.IsActive) { Add-Constat 'CRITIQUE' 'Antivirus' ("Menace ACTIVE non éliminée : {0}" -f $m.ThreatName) $fichiers 'Lancer une analyse Microsoft Defender hors ligne (Sécurité Windows > Options d''analyse).' }
    else { Add-Constat 'MOYEN' 'Antivirus' ("Menace détectée par le passé : {0}" -f $m.ThreatName) $fichiers 'Vérifier qu''elle a bien été mise en quarantaine et qu''elle ne revient pas.' }
    [pscustomobject]@{
        Menace = $m.ThreatName; Gravite = $severites[[int]$m.SeverityID]; Active = (OuiNon $m.IsActive)
        Executee = (OuiNon $m.DidThreatExecute); Detectee = $det.InitialDetectionTime; Fichiers = (Couper $fichiers 250)
    }
}
Add-Table $tableMenaces

# =============================================================================
#  3. Processus
# =============================================================================
Start-Section '3. Processus en cours (mémoire, processeur, activité disque/réseau)'
Write-Host '   Mesure de l''activité pendant 3 secondes...' -ForegroundColor DarkGray
$cpuAvant = @{}
foreach ($gp in Get-Process) { try { if ($gp.TotalProcessorTime) { $cpuAvant[$gp.Id] = $gp.TotalProcessorTime.TotalMilliseconds } } catch {} }
$t0 = Get-Date
Start-Sleep -Seconds 3
$ecoule = ((Get-Date) - $t0).TotalMilliseconds
$cpuPct = @{}
foreach ($gp in Get-Process) {
    try {
        if ($gp.TotalProcessorTime -and $cpuAvant.ContainsKey($gp.Id)) {
            $cpuPct[$gp.Id] = [math]::Round(($gp.TotalProcessorTime.TotalMilliseconds - $cpuAvant[$gp.Id]) / $ecoule / $nbCoeurs * 100, 1)
        }
    } catch {}
}
$perfProc = @{}
foreach ($pp in Get-CimInstance Win32_PerfFormattedData_PerfProc_Process) { $perfProc[[int]$pp.IDProcess] = $pp }

$listeProc = foreach ($p in Get-CimInstance Win32_Process) {
    $idp = [int]$p.ProcessId
    $es = 0
    if ($perfProc.ContainsKey($idp)) { $es = [math]::Round(([double]$perfProc[$idp].IODataBytesPersec + [double]$perfProc[$idp].IOOtherBytesPersec) / 1KB, 0) }
    $cpuP = 0; if ($cpuPct.ContainsKey($idp)) { $cpuP = $cpuPct[$idp] }
    [pscustomobject]@{
        PID = $idp; Nom = [string]$p.Name
        RAM_privee_Mo = [math]::Round($p.PrivatePageCount / 1MB, 0)
        RAM_active_Mo = [math]::Round($p.WorkingSetSize / 1MB, 0)
        CPU_pct = $cpuP; ES_Ko_s = $es; Handles = [int]$p.HandleCount
        Parent = [int]$p.ParentProcessId; Chemin = [string]$p.ExecutablePath; Commande = [string]$p.CommandLine
    }
}
$procParId = @{}
foreach ($p in $listeProc) { $procParId[$p.PID] = $p }

Add-Ligne ('{0} processus en cours.' -f @($listeProc).Count)
Add-Ligne ''
Add-Ligne 'Consommation regroupée par programme (tous ses processus additionnés) :'
$parApp = $listeProc | Group-Object Nom | ForEach-Object {
    [pscustomobject]@{
        Programme = $_.Name; Processus = $_.Count
        RAM_privee_Mo = ($_.Group | Measure-Object RAM_privee_Mo -Sum).Sum
        CPU_pct = [math]::Round(($_.Group | Measure-Object CPU_pct -Sum).Sum, 1)
        ES_Ko_s = ($_.Group | Measure-Object ES_Ko_s -Sum).Sum
    }
} | Sort-Object RAM_privee_Mo -Descending | Select-Object -First 12
Add-Table $parApp

Add-Ligne ''
Add-Ligne 'Top 15 par mémoire privée :'
Add-Table ($listeProc | Sort-Object RAM_privee_Mo -Descending | Select-Object -First 15) @('PID', 'Nom', 'RAM_privee_Mo', 'RAM_active_Mo', 'CPU_pct', 'Handles', 'Chemin')
Add-Ligne ''
Add-Ligne 'Top 10 par processeur (mesuré sur 3 s, % du processeur entier) :'
Add-Table ($listeProc | Where-Object { $_.PID -gt 0 } | Sort-Object CPU_pct -Descending | Select-Object -First 10) @('PID', 'Nom', 'CPU_pct', 'RAM_privee_Mo', 'Chemin')
Add-Ligne ''
Add-Ligne 'Top 10 par activité disque + réseau (Ko/s) :'
Add-Table ($listeProc | Sort-Object ES_Ko_s -Descending | Select-Object -First 10) @('PID', 'Nom', 'ES_Ko_s', 'CPU_pct', 'Chemin')

$sys32 = ("$env:SystemRoot\System32").ToLower()
$wow64 = ("$env:SystemRoot\SysWOW64").ToLower()
$sysAttendus = @{}
foreach ($n in 'svchost', 'lsass', 'csrss', 'winlogon', 'services', 'smss', 'wininit', 'spoolsv', 'taskhostw', 'dwm', 'sihost', 'conhost', 'dllhost', 'runtimebroker', 'ctfmon', 'fontdrvhost', 'lsaiso', 'taskmgr', 'rundll32') {
    $sysAttendus[$n] = @("$sys32\$n.exe", "$wow64\$n.exe")
}
$sysAttendus['explorer'] = @(("$env:SystemRoot\explorer.exe").ToLower(), "$wow64\explorer.exe")
$exceptionsNoms = @('iexplore', 'taskhost', 'taskhostex', 'service')

$cheminsVus     = @{}
$nomsVerifies   = @{}
$nomsSignales   = @{}
$procsNonSignes = New-Object System.Collections.Generic.List[object]
foreach ($p in $listeProc) {
    if ($p.PID -eq $PID -or $p.PID -le 4) { continue }
    $nomBase = ([System.IO.Path]::GetFileNameWithoutExtension($p.Nom)).ToLower()

    # Faux processus système
    if ($sysAttendus.ContainsKey($nomBase)) {
        if ($p.Chemin -and ($sysAttendus[$nomBase] -notcontains $p.Chemin.ToLower())) {
            Add-Constat 'CRITIQUE' 'Processus' ("Faux processus système : {0} tourne depuis un emplacement anormal" -f $p.Nom) $p.Chemin 'Le vrai fichier se trouve uniquement dans C:\Windows\System32. Couper Internet et faire une analyse Defender hors ligne.'
        }
    } elseif ($nomBase.Length -ge 5 -and -not $nomsVerifies.ContainsKey($nomBase) -and $exceptionsNoms -notcontains $nomBase) {
        $nomsVerifies[$nomBase] = $true
        foreach ($ref in $sysAttendus.Keys) {
            if ($ref.Length -lt 5) { continue }
            $max = 1; if ($ref.Length -ge 8) { $max = 2 }
            $dist = Get-Distance $nomBase $ref
            if ($dist -ge 1 -and $dist -le $max) {
                Add-Constat 'ELEVE' 'Processus' ("Nom imitant le processus système '{0}' : {1}" -f $ref, $p.Nom) $p.Chemin 'Technique classique de camouflage. Vérifier ce fichier.'
                break
            }
        }
    }

    # Noms connus
    $cleNom = $p.Nom + '|' + $p.Chemin
    if (-not $nomsSignales.ContainsKey($cleNom)) {
        $nomsSignales[$cleNom] = $true
        if (("$($p.Nom) $($p.Chemin)") -match $regexNomsMalveillants) { Add-Constat 'CRITIQUE' 'Processus' ("Outil malveillant ou de minage en cours : {0}" -f $p.Nom) $p.Chemin 'Si vous ne l''avez pas installé vous-même, le PC est compromis.' }
        elseif (("$($p.Nom) $($p.Chemin)") -match $regexOutilsDistance) { Add-Constat 'MOYEN' 'Processus' ("Outil de prise en main à distance actif : {0}" -f $p.Nom) $p.Chemin 'Si vous ne l''utilisez pas, quelqu''un peut contrôler le PC à distance.' }
    }

    # Signature, fichier disparu
    if ($p.Chemin) {
        $sig = Get-InfoSignature $p.Chemin
        if (-not $cheminsVus.ContainsKey($p.Chemin)) {
            $cheminsVus[$p.Chemin] = $true
            if ($sig.Statut -eq 'Introuvable') {
                Add-Constat 'ELEVE' 'Processus' ("Le fichier du processus {0} n'existe plus sur le disque (effacé après lancement ?)" -f $p.Nom) $p.Chemin 'Comportement typique d''un malware qui efface ses traces.'
            } elseif ($sig.Statut -eq 'HashMismatch') {
                Add-Constat 'CRITIQUE' 'Processus' ("Signature invalide (fichier modifié) : {0}" -f $p.Nom) $p.Chemin 'Fichier altéré après signature.'
            } elseif ($sig.Statut -ne 'Valid') {
                $procsNonSignes.Add([pscustomobject]@{ Nom = $p.Nom; PID = $p.PID; Signature = $sig.Statut; RAM_Mo = $p.RAM_privee_Mo; Chemin = $p.Chemin })
                if ($p.Chemin -match $regexCheminSuspect) {
                    Add-Constat 'ELEVE' 'Processus' ("Processus non signé lancé depuis un dossier utilisateur/temporaire : {0}" -f $p.Nom) $p.Chemin 'Vérifier le fichier (SHA256 sur virustotal.com).'
                }
            }
        }
        if ($sig.Statut -ne 'Valid' -and ($p.CPU_pct -ge 25 -or $p.RAM_privee_Mo -ge 1500)) {
            Add-Constat 'MOYEN' 'Processus' ("Processus non signé très gourmand : {0} (CPU {1} %, RAM {2} Mo)" -f $p.Nom, $p.CPU_pct, $p.RAM_privee_Mo) $p.Chemin 'Peut être un mineur de cryptomonnaie ou un programme défectueux.'
        }
    }

    # Ligne de commande suspecte
    if ($p.Commande -and $p.Chemin -match $regexLanceurs -and $p.Commande -match $regexCmdForte) {
        Add-Constat 'ELEVE' 'Processus' ("Commande suspecte en cours d'exécution ({0}, PID {1})" -f $p.Nom, $p.PID) (Couper $p.Commande 400) 'Script caché, téléchargement ou contenu encodé.'
    }
    if ($p.Handles -ge 50000) { Add-Constat 'MOYEN' 'Processus' ("{0} détient {1} handles (fuite de ressources probable)" -f $p.Nom, $p.Handles) $p.Chemin 'Redémarrer ce programme. Si c''est un service système, mettre à jour le pilote/logiciel associé.' }
}
Add-Ligne ''
Add-Ligne 'Processus dont l''exécutable n''est pas signé numériquement (pas forcément dangereux) :'
Add-Table ($procsNonSignes | Sort-Object Nom)

# =============================================================================
#  4. Réseau
# =============================================================================
Start-Section '4. Réseau (connexions, ports ouverts, DNS, proxy, hosts)'
$regexIpPrivee = '^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|0\.0\.0\.0|::1?$|fe80:|f[cd][0-9a-f]{2}:)'
$portsSuspects = @(1337, 31337, 4444, 5555, 6666, 6667, 6697, 7777, 9001, 9030, 9050, 9150, 3333, 14444, 45700, 1604, 5552)
$navigateursNoms = '(?i)^(chrome|msedge|firefox|brave|opera|vivaldi|msedgewebview2)\.exe$'

$tcp      = @(Get-NetTCPConnection)
$etablies = @($tcp | Where-Object { [string]$_.State -eq 'Established' -and $_.RemoteAddress -notmatch '^(127\.|::1$)' })
$ecoutes  = @($tcp | Where-Object { [string]$_.State -eq 'Listen' -and $_.LocalAddress -notmatch '^(127\.|::1$)' })

Add-Ligne 'Cartes réseau actives :'
Add-Table (Get-NetAdapter | Where-Object { [string]$_.Status -eq 'Up' } | Select-Object Name, InterfaceDescription, LinkSpeed, MacAddress)
Add-Ligne 'Débit instantané par carte (Ko/s) :'
Add-Table (Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface | ForEach-Object {
    [pscustomobject]@{ Carte = $_.Name; Recu_Ko_s = [math]::Round($_.BytesReceivedPersec / 1KB, 1); Envoye_Ko_s = [math]::Round($_.BytesSentPersec / 1KB, 1) } })

Add-Ligne ''
Add-Ligne ('Connexions établies par processus ({0} au total) :' -f $etablies.Count)
$resumeConn = $etablies | Group-Object OwningProcess | ForEach-Object {
    $idc = [int]$_.Name
    $info = $procParId[$idc]
    $externes = @($_.Group | Where-Object { $_.RemoteAddress -notmatch $regexIpPrivee })
    $nomP = '?'; $chP = ''
    if ($info) { $nomP = $info.Nom; $chP = $info.Chemin }
    [pscustomobject]@{
        PID = $idc; Processus = $nomP; Connexions = $_.Count; Vers_Internet = $externes.Count
        IP_distinctes = @($externes | ForEach-Object { $_.RemoteAddress } | Select-Object -Unique).Count
        Ports_distants = ((@($_.Group | ForEach-Object { $_.RemotePort } | Select-Object -Unique | Sort-Object) | Select-Object -First 10) -join ',')
        Chemin = $chP
    }
} | Sort-Object Connexions -Descending
Add-Table $resumeConn

foreach ($rc in $resumeConn) {
    $info = $procParId[$rc.PID]
    if (-not $info) { continue }
    if ($info.Chemin -and $rc.Vers_Internet -gt 0) {
        $sig = Get-InfoSignature $info.Chemin
        if ($sig.Statut -ne 'Valid') {
            $g = 'MOYEN'; if ($info.Chemin -match $regexCheminSuspect) { $g = 'ELEVE' }
            Add-Constat $g 'Réseau' ("{0} (non signé) communique avec {1} adresse(s) Internet" -f $info.Nom, $rc.IP_distinctes) $info.Chemin 'Vérifier que ce programme est connu et voulu.'
        }
    }
    if ($rc.Vers_Internet -ge 100 -and $info.Nom -notmatch $navigateursNoms) {
        Add-Constat 'MOYEN' 'Réseau' ("{0} a {1} connexions Internet ouvertes" -f $info.Nom, $rc.Vers_Internet) $info.Chemin 'Nombre anormal hors navigateur (P2P, botnet, mineur ?).'
    }
}
foreach ($cx in $etablies) {
    if ($portsSuspects -contains [int]$cx.RemotePort) {
        $nomP = '?'; if ($procParId[[int]$cx.OwningProcess]) { $nomP = $procParId[[int]$cx.OwningProcess].Nom }
        Add-Constat 'ELEVE' 'Réseau' ("Connexion vers un port souvent utilisé par des malwares/mineurs : {0}:{1} ({2})" -f $cx.RemoteAddress, $cx.RemotePort, $nomP) '' 'À analyser.'
    }
}

Add-Ligne ''
Add-Ligne 'Adresses Internet les plus contactées (avec nom DNS inverse) :'
$ipsExt = $etablies | Where-Object { $_.RemoteAddress -notmatch $regexIpPrivee } | Group-Object RemoteAddress | Sort-Object Count -Descending | Select-Object -First 25
$tableIp = foreach ($g in $ipsExt) {
    $nomDns = ''
    try {
        $r = Resolve-DnsName -Name $g.Name -Type PTR -QuickTimeout -DnsOnly -ErrorAction Stop | Where-Object { [string]$_.Type -eq 'PTR' } | Select-Object -First 1
        if ($r) { $nomDns = $r.NameHost }
    } catch {}
    $noms = ($g.Group | ForEach-Object { $i = $procParId[[int]$_.OwningProcess]; if ($i) { $i.Nom } else { $_.OwningProcess } } | Select-Object -Unique) -join ','
    [pscustomobject]@{ IP = $g.Name; Nb = $g.Count; Ports = (($g.Group | ForEach-Object { $_.RemotePort } | Select-Object -Unique) -join ','); Processus = $noms; DNS_inverse = $nomDns }
}
Add-Table $tableIp

Add-Ligne ''
Add-Ligne 'Ports en écoute accessibles depuis le réseau :'
$tableEcoute = foreach ($grp in ($ecoutes | Group-Object { "$($_.LocalPort)|$($_.OwningProcess)" })) {
    $e = $grp.Group[0]
    $info = $procParId[[int]$e.OwningProcess]
    $nomP = '?'; $chP = ''; if ($info) { $nomP = $info.Nom; $chP = $info.Chemin }
    $sigE = Get-InfoSignature $chP
    if ($portsSuspects -contains [int]$e.LocalPort) { Add-Constat 'ELEVE' 'Réseau' ("Port suspect {0} ouvert en écoute par {1}" -f $e.LocalPort, $nomP) $chP 'Possible porte dérobée.' }
    elseif ($chP -and $sigE.Statut -ne 'Valid') {
        $g = 'MOYEN'; if ($chP -match $regexCheminSuspect) { $g = 'ELEVE' }
        Add-Constat $g 'Réseau' ("Programme non signé en écoute sur le port {0} : {1}" -f $e.LocalPort, $nomP) $chP 'Un programme qui attend des connexions entrantes doit être identifié.'
    }
    if ([int]$e.LocalPort -eq 3389) { Add-Constat 'INFO' 'Réseau' 'Bureau à distance (port 3389) en écoute' '' 'À désactiver si inutilisé.' }
    if ([int]$e.LocalPort -in 5900, 5800) { Add-Constat 'MOYEN' 'Réseau' 'Serveur VNC (prise en main à distance) en écoute' $chP 'À désinstaller si non voulu.' }
    [pscustomobject]@{ Port = $e.LocalPort; Adresse = (($grp.Group | ForEach-Object { $_.LocalAddress } | Select-Object -Unique) -join ','); PID = $e.OwningProcess; Processus = $nomP; Signature = $sigE.Statut; Chemin = $chP }
}
Add-Table ($tableEcoute | Sort-Object Port)

Add-Ligne ''
Add-Ligne 'Serveurs DNS configurés :'
Add-Table (Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | ForEach-Object { [pscustomobject]@{ Interface = $_.InterfaceAlias; DNS = ($_.ServerAddresses -join ', ') } })

Add-Ligne ''
Add-Ligne 'Proxy :'
foreach ($sid in $sidsCharges) {
    $ie = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if (-not $ie) { continue }
    $u = $nomsParSid[$sid]; if (-not $u) { $u = $sid }
    Add-Ligne ('  {0} : proxy activé = {1}, serveur = {2}, script PAC = {3}' -f $u, (OuiNon ($ie.ProxyEnable -eq 1)), $ie.ProxyServer, $ie.AutoConfigURL)
    if ($ie.ProxyEnable -eq 1 -or $ie.AutoConfigURL) { Add-Constat 'MOYEN' 'Réseau' ("Proxy configuré pour {0} : {1} {2}" -f $u, $ie.ProxyServer, $ie.AutoConfigURL) '' 'Normal en entreprise. Sinon, un proxy peut intercepter le trafic web (adware, vol de données).' }
}
$winhttp = (& netsh winhttp show proxy) -join ' '
Add-Ligne ('  WinHTTP : ' + (Couper $winhttp 200))

Add-Ligne ''
Add-Ligne 'Fichier hosts (lignes actives) :'
$cheminHosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$lignesHosts = @(Get-Content -LiteralPath $cheminHosts | Where-Object { $_.Trim() -and -not $_.Trim().StartsWith('#') })
if ($lignesHosts.Count -eq 0) { Add-Ligne '  (vide, normal)' }
else {
    foreach ($l in ($lignesHosts | Select-Object -First 40)) { Add-Ligne ('  ' + $l) }
    if ($lignesHosts.Count -gt 40) { Add-Ligne ('  ... {0} lignes au total' -f $lignesHosts.Count) }
    $bloquants = @($lignesHosts | Where-Object { $_ -match '(?i)microsoft|windowsupdate|defender|virustotal|malwarebytes|kaspersky|eset|avast|avg|bitdefender|norton|mcafee|avira|sophos|google|bank|paypal' })
    if ($bloquants.Count) { Add-Constat 'ELEVE' 'Réseau' ("Le fichier hosts redirige ou bloque {0} site(s) sensibles (sécurité, mises à jour, banques...)" -f $bloquants.Count) (($bloquants | Select-Object -First 5) -join ' | ') 'Si vous n''avez pas modifié ce fichier vous-même (anti-pub, anti-télémétrie), c''est un signe de malware.' }
    else { Add-Constat 'INFO' 'Réseau' ("Fichier hosts personnalisé ({0} lignes)" -f $lignesHosts.Count) $cheminHosts '' }
}

# =============================================================================
#  5. Démarrage automatique
# =============================================================================
Start-Section '5. Programmes lancés automatiquement (registre, dossier Démarrage, Winlogon, IFEO, WMI)'
$clesRun = New-Object System.Collections.Generic.List[string]
foreach ($base in 'HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node') {
    foreach ($s in 'Run', 'RunOnce', 'RunServices', 'RunServicesOnce', 'Policies\Explorer\Run') { $clesRun.Add("$base\Microsoft\Windows\CurrentVersion\$s") }
}
foreach ($sid in $sidsCharges) {
    foreach ($s in 'Run', 'RunOnce', 'Policies\Explorer\Run') { $clesRun.Add("Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\$s") }
}
$entreesDemarrage = New-Object System.Collections.Generic.List[object]
foreach ($cle in $clesRun) {
    foreach ($v in Get-ValeursRegistre $cle) {
        $r = Test-ElementLancement -Commande $v.Valeur -Categorie 'Démarrage' -Libelle ("Entrée de démarrage '{0}'" -f $v.Nom)
        $entreesDemarrage.Add([pscustomobject]@{ Source = (Get-CleCourte $cle); Nom = $v.Nom; Signature = $r.Signature; Editeur = $r.Editeur; Remarque = $r.Raisons; Commande = $v.Valeur })
    }
}

# Dossiers Démarrage
$dossiersStartup = @(@{ Qui = 'Tous'; Chemin = "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" })
foreach ($pr in $profils) { $dossiersStartup += @{ Qui = (Split-Path $pr.LocalPath -Leaf); Chemin = (Join-Path $pr.LocalPath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') } }
$shell = New-Object -ComObject WScript.Shell
foreach ($ds in $dossiersStartup) {
    foreach ($f in Get-ChildItem -LiteralPath $ds.Chemin -Force -File | Where-Object { $_.Name -ne 'desktop.ini' }) {
        $cmd = $f.FullName
        if ($f.Extension -eq '.lnk') {
            try { $lnk = $shell.CreateShortcut($f.FullName); if ($lnk.TargetPath) { $cmd = ('"{0}" {1}' -f $lnk.TargetPath, $lnk.Arguments).Trim() } } catch {}
        }
        $r = Test-ElementLancement -Commande $cmd -Categorie 'Démarrage' -Libelle ("Dossier Démarrage '{0}'" -f $f.Name)
        if ($f.Extension -match '^\.(vbs|vbe|js|jse|wsf|hta|bat|cmd|ps1)$') { Add-Constat 'MOYEN' 'Démarrage' ("Script dans le dossier Démarrage : {0}" -f $f.Name) $f.FullName 'Les scripts au démarrage sont un mode de persistance courant des malwares.' }
        $entreesDemarrage.Add([pscustomobject]@{ Source = ('Dossier Démarrage (' + $ds.Qui + ')'); Nom = $f.Name; Signature = $r.Signature; Editeur = $r.Editeur; Remarque = $r.Raisons; Commande = $cmd })
    }
}
Add-Ligne 'Entrées de démarrage (registre Run/RunOnce et dossiers Démarrage) :'
Add-Table $entreesDemarrage @('Source', 'Nom', 'Signature', 'Editeur', 'Remarque', 'Commande')

# Winlogon / chargements hérités
Add-Ligne ''
Add-Ligne 'Winlogon et chargements spéciaux :'
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
Add-Ligne ('  Shell    : {0}' -f $wl.Shell)
Add-Ligne ('  Userinit : {0}' -f $wl.Userinit)
if ($wl.Shell -and $wl.Shell.Trim() -notmatch '^(?i)explorer\.exe$') { Add-Constat 'ELEVE' 'Démarrage' ("Shell Winlogon modifié : {0}" -f $wl.Shell) 'HKLM\...\Winlogon\Shell' 'Doit valoir uniquement explorer.exe.' }
if ($wl.Userinit -and ($wl.Userinit.Trim().TrimEnd(',') -notmatch '^(?i)(c:\\windows\\system32\\)?userinit\.exe$')) { Add-Constat 'ELEVE' 'Démarrage' ("Userinit Winlogon modifié : {0}" -f $wl.Userinit) 'HKLM\...\Winlogon\Userinit' 'Doit valoir C:\Windows\system32\userinit.exe,' }
foreach ($sid in $sidsCharges) {
    $wlu = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    if ($wlu.Shell) { Add-Constat 'ELEVE' 'Démarrage' ("Shell personnalisé pour l'utilisateur {0} : {1}" -f $nomsParSid[$sid], $wlu.Shell) '' 'Technique de persistance.' }
    $win = Get-ItemProperty -LiteralPath "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows NT\CurrentVersion\Windows"
    foreach ($nv in 'Load', 'Run') { if ($win.$nv) { Add-Constat 'ELEVE' 'Démarrage' ("Valeur '{0}' (ancienne méthode de lancement) pour {1} : {2}" -f $nv, $nomsParSid[$sid], $win.$nv) '' 'Rarement légitime.' } }
}
$sm = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
$be = (@($sm.BootExecute) -join ' ').Trim()
Add-Ligne ('  BootExecute : {0}' -f $be)
if ($be -and $be -notmatch '^(?i)autocheck autochk \*$') { Add-Constat 'MOYEN' 'Démarrage' ("BootExecute modifié : {0}" -f $be) '' 'Valeur normale : autocheck autochk *' }
foreach ($cleW in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
    $w = Get-ItemProperty $cleW
    if ($w.AppInit_DLLs -and $w.LoadAppInit_DLLs -eq 1) { Add-Constat 'ELEVE' 'Démarrage' ("AppInit_DLLs actif (DLL injectée dans chaque programme) : {0}" -f $w.AppInit_DLLs) $cleW 'Technique d''injection ancienne, très rarement légitime.' }
}

# IFEO : détournement / blocage d'applications
Add-Ligne ''
Add-Ligne 'Détournements d''applications (Image File Execution Options) :'
$nbIfeo = 0
foreach ($baseIfeo in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
    foreach ($k in Get-ChildItem -LiteralPath $baseIfeo) {
        $dbg = $k.GetValue('Debugger')
        if ($dbg) {
            $nbIfeo++
            Add-Ligne ('  {0} -> {1}' -f $k.PSChildName, $dbg)
            Add-Constat 'ELEVE' 'Démarrage' ("Le lancement de {0} est détourné vers : {1}" -f $k.PSChildName, $dbg) $k.Name 'Peut empêcher un programme de s''ouvrir ou le fermer aussitôt. Exception connue : Process Explorer remplaçant taskmgr.exe.'
        }
        $gf = $k.GetValue('GlobalFlag')
        if ($gf -and ([int]$gf -band 0x200)) { Add-Ligne ('  {0} : surveillance de fermeture silencieuse activée (GlobalFlag)' -f $k.PSChildName) }
    }
}
foreach ($k in Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit') {
    $mon = $k.GetValue('MonitorProcess')
    if ($mon) {
        $nbIfeo++
        Add-Ligne ('  À la fermeture de {0} -> lance {1}' -f $k.PSChildName, $mon)
        Add-Constat 'ELEVE' 'Démarrage' ("Programme lancé automatiquement à la fermeture de {0} : {1}" -f $k.PSChildName, $mon) $k.Name 'Technique de persistance discrète.'
    }
}
if ($nbIfeo -eq 0) { Add-Ligne '  (aucun, normal)' }

# WMI
Add-Ligne ''
Add-Ligne 'Abonnements WMI (persistance sans fichier) :'
$wmiFiltres = @(Get-CimInstance -Namespace 'root\subscription' -ClassName __EventFilter)
$wmiCmd     = @(Get-CimInstance -Namespace 'root\subscription' -ClassName CommandLineEventConsumer)
$wmiScript  = @(Get-CimInstance -Namespace 'root\subscription' -ClassName ActiveScriptEventConsumer)
$wmiLiens   = @(Get-CimInstance -Namespace 'root\subscription' -ClassName __FilterToConsumerBinding)
foreach ($f in $wmiFiltres) { if ($f -and $f.Name -ne 'SCM Event Log Filter') { Add-Ligne ('  Filtre   : {0} | requête : {1}' -f $f.Name, (Couper $f.Query 200)) } }
foreach ($c in $wmiCmd) {
    if (-not $c) { continue }
    Add-Ligne ('  Commande : {0} | {1} {2}' -f $c.Name, $c.ExecutablePath, $c.CommandLineTemplate)
    Add-Constat 'ELEVE' 'Démarrage' ("Abonnement WMI exécutant une commande : {0}" -f $c.Name) ("{0} {1}" -f $c.ExecutablePath, $c.CommandLineTemplate) 'Persistance invisible dans les outils classiques. À analyser.'
}
foreach ($c in $wmiScript) {
    if (-not $c) { continue }
    Add-Ligne ('  Script   : {0} | {1}' -f $c.Name, (Couper $c.ScriptText 300))
    Add-Constat 'ELEVE' 'Démarrage' ("Abonnement WMI exécutant un script : {0}" -f $c.Name) (Couper $c.ScriptText 300) 'Persistance invisible dans les outils classiques. À analyser.'
}
Add-Ligne ('  {0} liaison(s) filtre/action au total' -f @($wmiLiens | Where-Object { $_ }).Count)

# =============================================================================
#  6. Services et pilotes
# =============================================================================
Start-Section '6. Services et pilotes (hors Microsoft)'
Write-Host '   Vérification des signatures des services (peut prendre une minute)...' -ForegroundColor DarkGray
$servicesTiers = New-Object System.Collections.Generic.List[object]
foreach ($s in Get-CimInstance Win32_Service) {
    $chemin = Get-CheminExe $s.PathName
    $sig    = Get-InfoSignature $chemin
    $estMs  = ($sig.Statut -eq 'Valid' -and $sig.Editeur -match 'Microsoft')
    $cible  = $s.PathName
    if ($chemin -match '(?i)\\svchost\.exe$') {
        $par = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\Parameters"
        if ($par.ServiceDll) {
            $dll = [Environment]::ExpandEnvironmentVariables([string]$par.ServiceDll)
            $sigDll = Get-InfoSignature $dll
            if (-not ($sigDll.Statut -eq 'Valid' -and $sigDll.Editeur -match 'Microsoft')) { $estMs = $false; $cible = $dll }
        }
    }
    if ($estMs) { continue }
    $r = Test-ElementLancement -Commande $cible -Categorie 'Service' -Libelle ("Service '{0}'" -f $s.Name)
    if ($r.Chemin -match $regexLanceurs) { Add-Constat 'ELEVE' 'Service' ("Le service '{0}' lance un interpréteur de commandes" -f $s.Name) $s.PathName 'Les vrais services lancent rarement cmd/powershell directement.' }
    $servicesTiers.Add([pscustomobject]@{ Nom = $s.Name; Affichage = $s.DisplayName; Etat = $s.State; Demarrage = $s.StartMode; Compte = $s.StartName; Signature = $r.Signature; Editeur = $r.Editeur; Remarque = $r.Raisons; Chemin = $cible })
}
Add-Ligne ('{0} services non Microsoft :' -f $servicesTiers.Count)
Add-Table ($servicesTiers | Sort-Object Etat, Nom) @('Nom', 'Affichage', 'Etat', 'Demarrage', 'Signature', 'Editeur', 'Remarque', 'Chemin')

$wu = Get-CimInstance Win32_Service -Filter "Name='wuauserv'"
if ($wu.StartMode -eq 'Disabled') { Add-Constat 'MOYEN' 'Service' 'Service Windows Update désactivé' '' 'Certains malwares coupent les mises à jour. À réactiver sauf choix volontaire.' }
$wd = Get-CimInstance Win32_Service -Filter "Name='WinDefend'"
if ($wd -and $wd.State -ne 'Running' -and -not $tiersActif) { Add-Constat 'ELEVE' 'Service' ("Service Windows Defender non démarré (état : {0})" -f $wd.State) '' '' }

Add-Ligne ''
Add-Ligne 'Pilotes en cours hors emplacement standard (System32\drivers / DriverStore) :'
$pilotesHS = foreach ($d in Get-CimInstance Win32_SystemDriver | Where-Object { $_.State -eq 'Running' }) {
    $ch = Get-CheminExe $d.PathName
    if ($ch -match '(?i)\\System32\\(drivers|DriverStore)\\') { continue }
    $sig = Get-InfoSignature $ch
    if ($sig.Statut -ne 'Valid') { Add-Constat 'ELEVE' 'Pilote' ("Pilote non signé ou invalide en cours : {0}" -f $d.Name) $ch 'Un pilote a un accès total au système (rootkit possible).' }
    [pscustomobject]@{ Nom = $d.Name; Affichage = $d.DisplayName; Signature = $sig.Statut; Editeur = $sig.Editeur; Chemin = $ch }
}
Add-Table $pilotesHS

# =============================================================================
#  7. Tâches planifiées
# =============================================================================
Start-Section '7. Tâches planifiées'
$taches = @(Get-ScheduledTask)
$cheminsTaches = @{}
foreach ($t in $taches) { $cheminsTaches[($t.TaskPath + $t.TaskName).ToLower()] = $true }
Add-Ligne ('{0} tâches au total, dont {1} hors du dossier \Microsoft\ (détaillées ci-dessous, les plus suspectes en premier).' -f $taches.Count, @($taches | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }).Count)
Add-Ligne 'Les tâches Microsoft ne sont affichées que si elles présentent une anomalie.'
Add-Ligne ''

$blocsTaches = New-Object System.Collections.Generic.List[object]
foreach ($t in $taches) {
    $nomComplet = $t.TaskPath + $t.TaskName
    $dossierMs  = $t.TaskPath -like '\Microsoft\*'
    $grav = $null
    $raisons = New-Object System.Collections.Generic.List[string]
    $lignesActions = New-Object System.Collections.Generic.List[string]
    $premiereAction = ''
    $toutesSignees = $true

    foreach ($a in $t.Actions) {
        if ($a.Execute) {
            $brut = ($a.Execute + ' ' + $a.Arguments).Trim()
            if (-not $premiereAction) { $premiereAction = $brut }
            $cmd = ('"{0}" {1}' -f $a.Execute.Trim().Trim('"'), $a.Arguments).Trim()
            $r = Test-ElementLancement -Commande $cmd -SansConstat
            if ($r.Signature -ne 'Valid') { $toutesSignees = $false }
            if ($dossierMs) {
                if ($r.Signature -notin 'Valid', 'Introuvable', 'Inconnu') { $grav = Get-PireGravite $grav 'ELEVE'; $raisons.Add('rangée parmi les tâches Microsoft mais lance un programme non signé') }
                if ($r.Gravite -in 'CRITIQUE', 'ELEVE') { $grav = Get-PireGravite $grav $r.Gravite; $raisons.Add($r.Raisons) }
            } else {
                if ($r.Gravite -and $r.Gravite -ne 'INFO') { $grav = Get-PireGravite $grav $r.Gravite }
                if ($r.Raisons) { $raisons.Add($r.Raisons) }
            }
            $lignesActions.Add(('      Action      : {0}' -f $brut))
            $lignesActions.Add(('                    -> {0} | signature : {1} {2}' -f $r.Chemin, $r.Signature, $r.Editeur))
        } elseif ($a.ClassId) {
            $lignesActions.Add(('      Action      : gestionnaire COM {0}' -f $a.ClassId))
        }
    }
    if ($dossierMs -and -not $grav) { continue }

    $intervalleMin = $null
    $descTrig = @()
    foreach ($tr in $t.Triggers) {
        if (-not $tr) { continue }
        $descTrig += Get-DescriptionDeclencheur $tr
        if ($tr.Repetition -and $tr.Repetition.Interval) {
            try {
                $m = ([System.Xml.XmlConvert]::ToTimeSpan($tr.Repetition.Interval)).TotalMinutes
                if ($null -eq $intervalleMin -or $m -lt $intervalleMin) { $intervalleMin = $m }
            } catch {}
        }
    }
    $compte = $t.Principal.UserId; if (-not $compte) { $compte = $t.Principal.GroupId }
    $dateCreation = $null
    if ($t.Date) { try { $dateCreation = [datetime]::Parse($t.Date) } catch {} }

    if (-not $dossierMs) {
        if ($t.Settings.Hidden) { $grav = Get-PireGravite $grav 'MOYEN'; $raisons.Add('tâche marquée comme cachée') }
        if ($null -ne $intervalleMin -and $intervalleMin -le 15) { $grav = Get-PireGravite $grav 'MOYEN'; $raisons.Add(('relancée toutes les {0} min' -f $intervalleMin)) }
        if (-not $toutesSignees -and $compte -match 'SYSTEM|S-1-5-18') { $grav = Get-PireGravite $grav 'MOYEN'; $raisons.Add('programme non signé exécuté avec le compte SYSTEM') }
        if (-not $toutesSignees -and $dateCreation -and $dateCreation -ge $dateFichiers) { $grav = Get-PireGravite $grav 'MOYEN'; $raisons.Add('créée récemment') }
    }

    $info = $t | Get-ScheduledTaskInfo
    $derniere = 'jamais'; $prochaine = '-'
    if ($info) {
        if ($info.LastRunTime -and $info.LastRunTime.Year -gt 2000) { $derniere = $info.LastRunTime.ToString('dd/MM/yyyy HH:mm') + (' (code 0x{0:X})' -f [int64]$info.LastTaskResult) }
        if ($info.NextRunTime -and $info.NextRunTime.Year -gt 2000) { $prochaine = $info.NextRunTime.ToString('dd/MM/yyyy HH:mm') }
    }

    $etiquette = 'ok'; if ($grav -and $grav -ne 'INFO') { $etiquette = $grav }
    $dateTxt = '?'; if ($dateCreation) { $dateTxt = $dateCreation.ToString('dd/MM/yyyy') }
    $raisonsUniques = @($raisons | Where-Object { $_ } | Select-Object -Unique)
    $lignes = New-Object System.Collections.Generic.List[string]
    $lignes.Add(('  [{0}] {1}' -f $etiquette, $nomComplet))
    $lignes.Add(('      État        : {0} | cachée : {1} | compte : {2} ({3}) | auteur : {4} | créée le : {5}' -f $t.State, (OuiNon $t.Settings.Hidden), $compte, $t.Principal.RunLevel, $t.Author, $dateTxt))
    foreach ($la in $lignesActions) { $lignes.Add($la) }
    if ($descTrig.Count) { $lignes.Add('      Déclencheur : ' + ($descTrig -join ' ; ')) } else { $lignes.Add('      Déclencheur : aucun (lancée manuellement ou par un programme)') }
    $lignes.Add(('      Exécution   : dernière {0} | prochaine {1}' -f $derniere, $prochaine))
    if ($raisonsUniques.Count) { $lignes.Add('      Remarques   : ' + ($raisonsUniques -join ' ; ')) }
    $ordre = 9; if ($grav) { $ordre = $ordreGravite[$grav] }
    $blocsTaches.Add([pscustomobject]@{ Ordre = $ordre; Nom = $nomComplet; Lignes = $lignes })

    if ($grav -and $grav -ne 'INFO') {
        Add-Constat $grav 'Tâche planifiée' ('{0} : {1}' -f $nomComplet, ($raisonsUniques -join ' ; ')) $premiereAction ("Pour la désactiver sans la supprimer : Disable-ScheduledTask -TaskPath '{0}' -TaskName '{1}'" -f $t.TaskPath, $t.TaskName)
    }
}
foreach ($b in ($blocsTaches | Sort-Object Ordre, Nom)) {
    foreach ($l in $b.Lignes) { Add-Ligne $l }
    Add-Ligne ''
}

# Tâches cachées dans le registre (suppression du descripteur de sécurité)
Add-Ligne 'Contrôle des tâches dissimulées dans le registre :'
$racineCache = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache'
$invisibles = New-Object System.Collections.Generic.List[string]
$sansSD = 0
foreach ($k in Get-ChildItem -LiteralPath "$racineCache\Tree" -Recurse) {
    $id = $k.GetValue('Id')
    if (-not $id) { continue }
    $rel = $k.Name -replace '^.*?\\TaskCache\\Tree', ''
    $actionTxt = ''
    $kt = Get-Item -LiteralPath "$racineCache\Tasks\$id"
    if ($kt) {
        $octets = $kt.GetValue('Actions')
        if ($octets) {
            $s = [System.Text.Encoding]::Unicode.GetString([byte[]]$octets)
            $actionTxt = (([regex]::Matches($s, '[\x20-\x7E\u00C0-\u00FF]{4,}') | ForEach-Object { $_.Value }) -join ' ')
        }
    }
    if (-not $k.GetValue('SD')) {
        $sansSD++
        Add-Ligne ('  [CRITIQUE] {0} : tâche sans descripteur de sécurité | action : {1}' -f $rel, (Couper $actionTxt 250))
        Add-Constat 'CRITIQUE' 'Tâche planifiée' ("Tâche volontairement rendue invisible : {0}" -f $rel) (Couper $actionTxt 250) 'Technique de dissimulation avancée (type Tarrask). Faire analyser avant toute action.'
    } elseif (-not $cheminsTaches.ContainsKey($rel.ToLower())) {
        $invisibles.Add(('{0} | action : {1}' -f $rel, (Couper $actionTxt 200)))
    }
}
foreach ($i in $invisibles) { Add-Ligne ('  [invisible] ' + $i) }
if ($invisibles.Count -gt 0) { Add-Constat 'MOYEN' 'Tâche planifiée' ("{0} tâche(s) présentes dans le registre mais non visibles via le Planificateur" -f $invisibles.Count) ($invisibles[0]) 'Peut être dû à des droits d''accès, ou à une dissimulation. Voir la section 7.' }
if ($sansSD -eq 0 -and $invisibles.Count -eq 0) { Add-Ligne '  (aucune tâche dissimulée détectée)' }

# =============================================================================
#  8. Fichiers suspects
# =============================================================================
Start-Section ('8. Fichiers suspects (récents depuis {0} jours, cachés, déguisés, corrompus)' -f $JoursFichiers)
$extPE      = @('.exe', '.dll', '.scr', '.com', '.pif', '.cpl', '.sys', '.ocx')
$extScripts = @('.ps1', '.psm1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.bat', '.cmd', '.jar')
$extLeurres = @('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.jpg', '.jpeg', '.png', '.gif', '.txt', '.mp3', '.mp4', '.avi', '.mkv', '.zip', '.rar', '.7z')
$hsExec = New-EnsembleTexte ($extPE + $extScripts)
$hsTout = New-EnsembleTexte ($extPE + $extScripts + $extLeurres)
$regexDoubleExt = '(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|avi|mkv|zip|rar)\s*\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|hta|wsf|ps1|jar)$|\s{4,}\.(exe|scr|com|pif|bat|cmd|vbs|js)$'
$exclBase = @('node_modules', '.git', 'Cache', 'Code Cache', 'GPUCache', 'cache2', 'Service Worker', 'CacheStorage', 'IndexedDB', 'site-packages', '__pycache__', 'Packages', 'Package Cache', 'WinSxS', 'assembly', 'User Data', 'Profiles', 'Windows Defender', 'WER', 'Diagnosis', 'Crypto', 'WindowsApps')

$cibles = New-Object System.Collections.Generic.List[object]
function Add-Cible([string]$Racine, [int]$Prof, [string]$Type, [string[]]$Excl) {
    if ($Racine -and (Test-Path -LiteralPath $Racine)) { $cibles.Add([pscustomobject]@{ Racine = $Racine; Prof = $Prof; Type = $Type; Excl = $Excl }) }
}
foreach ($pr in $profils) {
    $u = $pr.LocalPath
    Add-Cible "$u\AppData\Roaming"    4 'Utilisateur' $exclBase
    Add-Cible "$u\AppData\Local"      4 'Utilisateur' ($exclBase + 'Temp')
    Add-Cible "$u\AppData\LocalLow"   3 'Utilisateur' $exclBase
    Add-Cible "$u\AppData\Local\Temp" 5 'Temp'        $exclBase
    Add-Cible "$u\Downloads"          2 'Leurres'     $exclBase
    Add-Cible "$u\Desktop"            1 'Leurres'     $exclBase
    Add-Cible "$u\Documents"          1 'Leurres'     $exclBase
}
Add-Cible $env:PUBLIC                 4 'Utilisateur' $exclBase
Add-Cible $env:ProgramData            3 'Utilisateur' $exclBase
Add-Cible "$env:SystemRoot\Temp"      4 'Temp'        $exclBase
Add-Cible "$env:SystemRoot\System32"  0 'Systeme'     @()
Add-Cible "$env:SystemRoot\SysWOW64"  0 'Systeme'     @()
Add-Cible "$env:SystemRoot\System32\drivers" 0 'Systeme' @()
Add-Cible $env:SystemRoot             0 'Systeme'     @()
Add-Cible "$env:SystemDrive\"         0 'Racine'      @()

$vus = New-EnsembleTexte @()
if ($PSCommandPath) { [void]$vus.Add($PSCommandPath) }
$candidats = New-Object System.Collections.Generic.List[object]
$nbExamines = 0
foreach ($c in $cibles) {
    Write-Host ('   - ' + $c.Racine) -ForegroundColor DarkGray
    $hs = $hsExec; if ($c.Type -in 'Leurres', 'Temp') { $hs = $hsTout }
    foreach ($f in (Get-FichiersRapide -Racine $c.Racine -ProfondeurMax $c.Prof -Exclure $c.Excl -Extensions $hs)) {
        if (-not $vus.Add($f.Chemin)) { continue }
        $nbExamines++
        try { $fi = New-Object System.IO.FileInfo -ArgumentList $f.Chemin; $null = $fi.Length } catch { continue }
        $nom = $fi.Name
        $ext = $fi.Extension.ToLower()
        $recent = ($fi.LastWriteTime -ge $dateFichiers -or $fi.CreationTime -ge $dateFichiers)
        $cache = [bool]($fi.Attributes -band ([System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System))
        $grav = $null
        $raisons = New-Object System.Collections.Generic.List[string]
        $sig = $null

        if ($nom.IndexOf([char]0x202E) -ge 0) { $grav = 'CRITIQUE'; $raisons.Add('nom inversé par un caractère invisible (camouflage)') }
        if ($nom -match $regexDoubleExt) { $grav = Get-PireGravite $grav 'ELEVE'; $raisons.Add('double extension (ex. facture.pdf.exe)') }

        if ($extLeurres -contains $ext) {
            if (-not $grav) {
                if (-not $recent -or $fi.Length -lt 1KB -or $fi.Length -gt 300MB) { continue }
                if ((Test-EnteteMZ $fi.FullName) -eq $true) { $grav = 'ELEVE'; $raisons.Add('programme déguisé : extension de document/image mais contenu exécutable') }
                else { continue }
            }
        }
        elseif ($extPE -contains $ext) {
            $racineSensible = ($f.Profondeur -eq 0 -and $c.Type -in 'Utilisateur', 'Racine')
            $dllProfonde = ($ext -in '.dll', '.ocx', '.sys' -and $f.Profondeur -gt 1 -and $c.Type -ne 'Temp')
            if (-not ($grav -or $cache -or $racineSensible -or ($recent -and -not $dllProfonde))) { continue }
            $sig = Get-InfoSignature $fi.FullName
            if ($sig.Statut -eq 'HashMismatch') { $grav = Get-PireGravite $grav 'CRITIQUE'; $raisons.Add('signature invalide : fichier modifié après signature') }
            elseif ($sig.Statut -ne 'Valid') {
                if ($cache)                     { $grav = Get-PireGravite $grav 'ELEVE'; $raisons.Add('exécutable non signé et caché') }
                elseif ($c.Type -eq 'Systeme')  { $grav = Get-PireGravite $grav 'ELEVE'; $raisons.Add('fichier récent non signé dans le dossier Windows') }
                elseif ($racineSensible)        { $grav = Get-PireGravite $grav 'MOYEN'; $raisons.Add('exécutable non signé à la racine d''un dossier sensible') }
                else                            { $grav = Get-PireGravite $grav 'INFO';  $raisons.Add('non signé') }
            } else {
                if (-not ($grav -or $cache -or $racineSensible)) { continue }
                if ($cache) { $grav = Get-PireGravite $grav 'INFO'; $raisons.Add('caché (mais signé)') }
                if ($racineSensible) { $grav = Get-PireGravite $grav 'INFO'; $raisons.Add('à la racine d''un dossier sensible (signé)') }
            }
            if ($ext -in '.exe', '.dll', '.scr', '.sys') {
                $mz = Test-EnteteMZ $fi.FullName
                if ($mz -eq $false) {
                    if ($fi.Length -eq 0) { $grav = Get-PireGravite $grav 'INFO'; $raisons.Add('fichier vide') }
                    else { $grav = Get-PireGravite $grav 'MOYEN'; $raisons.Add('pas d''en-tête exécutable valide (corrompu ou déguisé)') }
                }
            }
        }
        elseif ($extScripts -contains $ext) {
            if (-not ($grav -or $cache -or ($recent -and ($c.Type -eq 'Temp' -or $f.Profondeur -le 1)))) { continue }
            if ($cache) { $grav = Get-PireGravite $grav 'ELEVE'; $raisons.Add('script caché') }
            if ($ext -ne '.jar' -and $fi.Length -lt 2MB) {
                $contenu = ''
                try { $contenu = [System.IO.File]::ReadAllText($fi.FullName) } catch {}
                if ($contenu -notmatch 'AnalysePC') {
                    if ($contenu -match $regexNomsMalveillants) { $grav = Get-PireGravite $grav 'CRITIQUE'; $raisons.Add('mentionne un outil malveillant/minage connu') }
                    elseif ($contenu -match $regexCmdForte) { $grav = Get-PireGravite $grav 'ELEVE'; $raisons.Add('contient des commandes de téléchargement, d''obfuscation ou visant l''antivirus') }
                }
            }
            if (-not $grav) { $grav = 'INFO'; $raisons.Add('script récent') }
        }
        else { continue }

        # Origine (téléchargé depuis), flux cachés, empreinte
        $origine = ''
        try {
            $zi = Get-Content -LiteralPath $fi.FullName -Stream Zone.Identifier -ErrorAction Stop
            $hu = $zi | Where-Object { $_ -match '^HostUrl=' } | Select-Object -First 1
            if ($hu) { $origine = $hu -replace '^HostUrl=', '' }
        } catch {}
        try {
            foreach ($st in Get-Item -LiteralPath $fi.FullName -Stream * -ErrorAction Stop) {
                if ($st.Stream -notin ':$DATA', 'Zone.Identifier', 'SmartScreen' -and $st.Length -gt 1KB) {
                    $grav = Get-PireGravite $grav 'ELEVE'; $raisons.Add(("données cachées dans un flux alternatif '{0}' ({1} Ko)" -f $st.Stream, [math]::Round($st.Length / 1KB)))
                }
            }
        } catch {}
        if (-not $grav) { $grav = 'INFO' }
        $hash = ''
        if ($grav -in 'CRITIQUE', 'ELEVE', 'MOYEN') {
            try { $hash = (Get-FileHash -LiteralPath $fi.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch {}
            Add-Constat $grav 'Fichier' ('{0} : {1}' -f $fi.Name, ($raisons -join ', ')) ('{0}  [SHA256 {1}]' -f $fi.FullName, $hash) 'Ne pas ouvrir. Vérifier l''empreinte SHA256 sur virustotal.com.'
        }
        $statutSig = '-'; if ($sig) { $statutSig = $sig.Statut }
        $candidats.Add([pscustomobject]@{
            Gravite = $grav; Ordre = $ordreGravite[$grav]; Modifie = $fi.LastWriteTime.ToString('yyyy-MM-dd'); Ko = [math]::Round($fi.Length / 1KB)
            Signature = $statutSig; Remarques = ($raisons -join ', '); Chemin = $fi.FullName; Origine = $origine; SHA256 = $hash
        })
    }
}
Add-Ligne ('{0} fichiers exécutables/scripts/documents examinés dans {1} emplacements, {2} retenus.' -f $nbExamines, $cibles.Count, $candidats.Count)
$importants = @($candidats | Where-Object { $_.Ordre -le 2 } | Sort-Object Ordre, Modifie)
$infos      = @($candidats | Where-Object { $_.Ordre -gt 2 } | Sort-Object Modifie -Descending | Select-Object -First 80)
Add-Ligne ''
Add-Ligne 'Fichiers à examiner en priorité :'
Add-Table $importants @('Gravite', 'Modifie', 'Ko', 'Signature', 'Remarques', 'Chemin')
if ($importants.Count) {
    Add-Ligne 'Empreintes SHA256 et origine (à vérifier sur virustotal.com) :'
    foreach ($i in $importants) {
        $orig = ''; if ($i.Origine) { $orig = '<- ' + $i.Origine }
        Add-Ligne ('  {0}  {1}  {2}' -f $i.SHA256, $i.Chemin, $orig)
    }
}
Add-Ligne ''
Add-Ligne 'Autres fichiers récents non signés ou scripts (pour information, 80 max) :'
Add-Table $infos @('Modifie', 'Ko', 'Signature', 'Remarques', 'Chemin', 'Origine')

# =============================================================================
#  9. Programmes installés et extensions de navigateur
# =============================================================================
Start-Section '9. Programmes installés et extensions de navigateur'
$clesDesinst = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
foreach ($sid in $sidsCharges) { $clesDesinst += "Registry::HKEY_USERS\$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall" }
$programmes = foreach ($cle in $clesDesinst) {
    foreach ($k in Get-ChildItem -LiteralPath $cle) {
        $n = [string]$k.GetValue('DisplayName')
        if (-not $n -or $k.GetValue('SystemComponent') -eq 1) { continue }
        $dateInst = $null
        $di = [string]$k.GetValue('InstallDate')
        if ($di -match '^\d{8}$') { try { $dateInst = [datetime]::ParseExact($di, 'yyyyMMdd', $null) } catch {} }
        [pscustomobject]@{ Nom = $n; Version = $k.GetValue('DisplayVersion'); Editeur = $k.GetValue('Publisher'); Installe = $dateInst; Emplacement = $k.GetValue('InstallLocation') }
    }
}
$programmes = @($programmes | Sort-Object Nom -Unique)
Add-Ligne ('{0} programmes installés.' -f $programmes.Count)
Add-Ligne ''
Add-Ligne ('Installés ou mis à jour depuis {0} jours :' -f $JoursFichiers)
Add-Table ($programmes | Where-Object { $_.Installe -and $_.Installe -ge $dateFichiers } | Sort-Object Installe -Descending) @('Installe', 'Nom', 'Version', 'Editeur')
foreach ($pg in $programmes) {
    if ($pg.Nom -match $regexPUP) { Add-Constat 'MOYEN' 'Programme' ("Logiciel potentiellement indésirable : {0}" -f $pg.Nom) $pg.Editeur 'Souvent installé à votre insu avec d''autres logiciels. Désinstaller si non voulu.' }
    elseif ($pg.Nom -match $regexOutilsDistance) { Add-Constat 'INFO' 'Programme' ("Outil de prise en main à distance installé : {0}" -f $pg.Nom) $pg.Editeur 'À désinstaller si vous ne l''utilisez pas.' }
}
Add-Ligne ''
Add-Ligne 'Liste complète des programmes :'
Add-Table $programmes @('Nom', 'Version', 'Editeur', 'Installe')

Add-Ligne ''
Add-Ligne 'Extensions de navigateur :'
$navs = @(
    @{ Nom = 'Chrome'; Rel = 'Google\Chrome\User Data' },
    @{ Nom = 'Edge';   Rel = 'Microsoft\Edge\User Data' },
    @{ Nom = 'Brave';  Rel = 'BraveSoftware\Brave-Browser\User Data' }
)
$regexPermSensibles = '^(<all_urls>|\*://\*/\*|https?://\*/\*|proxy|webRequest|webRequestBlocking|nativeMessaging|debugger|management|cookies|declarativeNetRequest)$'
$extensionsNav = New-Object System.Collections.Generic.List[object]
foreach ($pr in $profils) {
    foreach ($nv in $navs) {
        $ud = Join-Path $pr.LocalPath ('AppData\Local\' + $nv.Rel)
        if (-not (Test-Path -LiteralPath $ud)) { continue }
        foreach ($pd in Get-ChildItem -LiteralPath $ud -Directory | Where-Object { $_.Name -match '^(Default|Profile \d+)$' }) {
            foreach ($idDir in Get-ChildItem -LiteralPath (Join-Path $pd.FullName 'Extensions') -Directory) {
                $verDir = Get-ChildItem -LiteralPath $idDir.FullName -Directory | Sort-Object Name -Descending | Select-Object -First 1
                if (-not $verDir) { continue }
                try { $m = Get-Content -LiteralPath (Join-Path $verDir.FullName 'manifest.json') -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
                if (-not $m) { continue }
                $nomExt = Get-NomExtension $verDir.FullName $m
                $perms = @(@($m.permissions) + @($m.host_permissions) | Where-Object { $_ -is [string] })
                $sensibles = @($perms | Where-Object { $_ -match $regexPermSensibles }) -join ','
                $store = ([string]$m.update_url -match 'google\.com|microsoft\.com|brave')
                if (-not $store) { Add-Constat 'MOYEN' 'Navigateur' ("Extension {0} installée hors boutique officielle : {1}" -f $nv.Nom, $nomExt) $idDir.FullName 'Les extensions hors boutique sont une source fréquente de publicités et de vol de données.' }
                $extensionsNav.Add([pscustomobject]@{ Navigateur = $nv.Nom; Profil = $pd.Name; Utilisateur = (Split-Path $pr.LocalPath -Leaf); Nom = $nomExt; Version = $m.version; Boutique = (OuiNon $store); Permissions_sensibles = $sensibles; ID = $idDir.Name })
            }
        }
    }
    $ffProfils = Join-Path $pr.LocalPath 'AppData\Roaming\Mozilla\Firefox\Profiles'
    foreach ($fp in Get-ChildItem -LiteralPath $ffProfils -Directory) {
        try { $j = Get-Content -LiteralPath (Join-Path $fp.FullName 'extensions.json') -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        foreach ($ad in $j.addons) {
            if ($ad.location -ne 'app-profile' -or $ad.type -ne 'extension') { continue }
            $store = ([string]$ad.sourceURI -match 'mozilla')
            $extensionsNav.Add([pscustomobject]@{ Navigateur = 'Firefox'; Profil = $fp.Name; Utilisateur = (Split-Path $pr.LocalPath -Leaf); Nom = $ad.defaultLocale.name; Version = $ad.version; Boutique = (OuiNon $store); Permissions_sensibles = ''; ID = $ad.id })
        }
    }
}
Add-Table $extensionsNav @('Navigateur', 'Profil', 'Nom', 'Version', 'Boutique', 'Permissions_sensibles', 'ID')

# =============================================================================
#  10. Journaux d'événements
# =============================================================================
Start-Section ("10. Journaux d'événements ({0} derniers jours)" -f $JoursEvenements)
function Get-Evts($Filtre, [int]$Max = 500) { try { @(Get-WinEvent -FilterHashtable $Filtre -MaxEvents $Max -ErrorAction Stop) } catch { @() } }

# Plantages et blocages d'applications
$crash = Get-Evts @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $dateEvenements } 1500
$hang  = Get-Evts @{ LogName = 'Application'; ProviderName = 'Application Hang'; Id = 1002; StartTime = $dateEvenements } 500
Add-Ligne ('Plantages d''applications : {0} | Blocages (ne répond pas) : {1}' -f $crash.Count, $hang.Count)
$resCrash = $crash | Group-Object { $_.Properties[0].Value } | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
    $modules = ($_.Group | Group-Object { $_.Properties[3].Value } | Sort-Object Count -Descending | Select-Object -First 2 | ForEach-Object { $_.Name }) -join ', '
    $codes = ($_.Group | ForEach-Object { [string]$_.Properties[6].Value } | Select-Object -Unique | Select-Object -First 3) -join ', '
    [pscustomobject]@{ Application = $_.Name; Plantages = $_.Count; Dernier = $_.Group[0].TimeCreated.ToString('dd/MM HH:mm'); Module_fautif = $modules; Codes = $codes }
}
Add-Table $resCrash
foreach ($rc in $resCrash) {
    if ($rc.Plantages -ge 5) { Add-Constat 'MOYEN' 'Stabilité' ("{0} a planté {1} fois (module : {2})" -f $rc.Application, $rc.Plantages, $rc.Module_fautif) ("codes : " + $rc.Codes) 'Si le module fautif n''appartient pas à l''application, un logiciel tiers s''y injecte (antivirus, overlay, malware).' }
}
if ($hang.Count) {
    Add-Ligne 'Applications qui ne répondent plus :'
    Add-Table ($hang | Group-Object { $_.Properties[0].Value } | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { [pscustomobject]@{ Application = $_.Name; Blocages = $_.Count; Dernier = $_.Group[0].TimeCreated.ToString('dd/MM HH:mm') } })
}

# Manque de mémoire (Windows ferme alors des applications)
$memEvt = Get-Evts @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'; StartTime = $dateEvenements } 50
Add-Ligne ''
Add-Ligne ('Alertes "mémoire insuffisante" de Windows : {0}' -f $memEvt.Count)
if ($memEvt.Count) {
    Add-Ligne ('  Dernière : {0} : {1}' -f $memEvt[0].TimeCreated.ToString('dd/MM HH:mm'), (Couper $memEvt[0].Message 600))
    Add-Constat 'ELEVE' 'Mémoire' ("Windows a manqué de mémoire {0} fois : il ferme alors des applications" -f $memEvt.Count) (Couper $memEvt[0].Message 300) 'Le message indique les processus qui consommaient le plus.'
}

# Services
$svcNouv = Get-Evts @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7045; StartTime = $dateFichiers } 200
Add-Ligne ''
Add-Ligne ('Services installés depuis {0} jours : {1}' -f $JoursFichiers, $svcNouv.Count)
$tableSvc = foreach ($e in $svcNouv) {
    $nomS = [string]$e.Properties[0].Value; $chS = [string]$e.Properties[1].Value
    $r = Test-ElementLancement -Commande $chS -SansConstat
    if ($r.Gravite -in 'CRITIQUE', 'ELEVE' -or $r.Chemin -match $regexLanceurs) { Add-Constat 'ELEVE' 'Service' ("Service installé récemment et suspect : {0}" -f $nomS) $chS 'Méthode classique d''installation de malware ou de prise de contrôle à distance.' }
    [pscustomobject]@{ Date = $e.TimeCreated.ToString('dd/MM/yyyy HH:mm'); Service = $nomS; Demarrage = $e.Properties[3].Value; Compte = $e.Properties[4].Value; Signature = $r.Signature; Fichier = $chS }
}
Add-Table $tableSvc
$svcCrash = Get-Evts @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7031, 7034; StartTime = $dateEvenements } 300
if ($svcCrash.Count) {
    Add-Ligne 'Services arrêtés de manière inattendue :'
    Add-Table ($svcCrash | Group-Object { $_.Properties[0].Value } | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { [pscustomobject]@{ Service = $_.Name; Arrets = $_.Count; Dernier = $_.Group[0].TimeCreated.ToString('dd/MM HH:mm') } })
}

# Arrêts brutaux, écrans bleus, matériel, disque
$arrets = Get-Evts @{ LogName = 'System'; Id = 41, 6008; StartTime = $dateEvenements } 100
$bsod   = Get-Evts @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; StartTime = $dateEvenements } 50
$whea   = Get-Evts @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $dateEvenements } 100
$disk   = Get-Evts @{ LogName = 'System'; ProviderName = 'disk', 'Ntfs', 'stornvme', 'storahci', 'volmgr'; Level = 1, 2, 3; StartTime = $dateEvenements } 200
Add-Ligne ''
Add-Ligne ('Arrêts brutaux : {0} | Écrans bleus : {1} | Erreurs matérielles (WHEA) : {2} | Erreurs disque/NTFS : {3}' -f $arrets.Count, $bsod.Count, $whea.Count, $disk.Count)
foreach ($e in ($bsod | Select-Object -First 5)) { Add-Ligne ('  Écran bleu {0} : {1}' -f $e.TimeCreated.ToString('dd/MM HH:mm'), (Couper $e.Message 250)) }
foreach ($e in ($disk | Select-Object -First 8)) { Add-Ligne ('  Disque {0} [{1} {2}] : {3}' -f $e.TimeCreated.ToString('dd/MM HH:mm'), $e.ProviderName, $e.Id, (Couper $e.Message 200)) }
if ($arrets.Count -ge 3) { Add-Constat 'MOYEN' 'Stabilité' ("{0} arrêts brutaux du PC" -f $arrets.Count) '' 'Alimentation, surchauffe ou plantage système.' }
if ($bsod.Count) { Add-Constat 'MOYEN' 'Stabilité' ("{0} écran(s) bleu(s)" -f $bsod.Count) (Couper $bsod[0].Message 200) 'Le code d''arrêt aide à trouver le pilote en cause.' }
if ($whea.Count) { Add-Constat 'MOYEN' 'Matériel' ("{0} erreur(s) matérielle(s) WHEA" -f $whea.Count) (Couper $whea[0].Message 200) 'Instabilité RAM/processeur (overclocking, surchauffe) : cause fréquente de fichiers corrompus.' }
if ($disk.Count) { Add-Constat 'MOYEN' 'Disque' ("{0} erreur(s) ou avertissement(s) disque/NTFS" -f $disk.Count) (Couper $disk[0].Message 200) 'Risque de fichiers corrompus. Voir la section 12.' }

# Effacement de journaux
$effaces = @(Get-Evts @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Eventlog'; Id = 104; StartTime = $dateFichiers } 20) + @(Get-Evts @{ LogName = 'Security'; Id = 1102; StartTime = $dateFichiers } 20)
if ($effaces.Count) {
    Add-Ligne ('Journaux effacés : {0} fois (dernier le {1})' -f $effaces.Count, ($effaces | Sort-Object TimeCreated -Descending | Select-Object -First 1).TimeCreated)
    Add-Constat 'ELEVE' 'Journaux' ("Journaux d'événements effacés {0} fois" -f $effaces.Count) '' 'Les attaquants effacent souvent les journaux pour cacher leurs traces. Normal seulement si vous l''avez fait vous-même.'
}

# Sécurité : comptes, groupes, connexions échouées
$secComptes = Get-Evts @{ LogName = 'Security'; Id = 4720, 4732; StartTime = $dateFichiers } 50
foreach ($e in $secComptes) {
    if ($e.Id -eq 4720) {
        Add-Ligne ('  Compte créé le {0} : {1}' -f $e.TimeCreated.ToString('dd/MM HH:mm'), $e.Properties[0].Value)
        Add-Constat 'MOYEN' 'Comptes' ("Compte utilisateur créé le {0} : {1}" -f $e.TimeCreated.ToString('dd/MM/yyyy'), $e.Properties[0].Value) '' 'Vérifier que vous l''avez créé.'
    } else {
        $membre = [string]$e.Properties[1].Value
        try { $membre = (New-Object System.Security.Principal.SecurityIdentifier($membre)).Translate([System.Security.Principal.NTAccount]).Value } catch {}
        Add-Ligne ('  Ajout au groupe {0} le {1} : {2}' -f $e.Properties[2].Value, $e.TimeCreated.ToString('dd/MM HH:mm'), $membre)
        if ([string]$e.Properties[4].Value -eq 'S-1-5-32-544') { Add-Constat 'MOYEN' 'Comptes' ("{0} ajouté aux administrateurs le {1}" -f $membre, $e.TimeCreated.ToString('dd/MM/yyyy')) '' 'Vérifier que c''est voulu.' }
    }
}
$echecs = Get-Evts @{ LogName = 'Security'; Id = 4625; StartTime = $dateEvenements } 2000
Add-Ligne ('Tentatives de connexion échouées : {0}' -f $echecs.Count)
if ($echecs.Count -ge 50) { Add-Constat 'MOYEN' 'Comptes' ("{0} tentatives de connexion échouées" -f $echecs.Count) '' 'Possible attaque par force brute (Bureau à distance exposé ?).' }
$tachesCreees = Get-Evts @{ LogName = 'Security'; Id = 4698; StartTime = $dateFichiers } 50
foreach ($e in $tachesCreees) { Add-Ligne ('  Tâche planifiée créée le {0} : {1} (par {2})' -f $e.TimeCreated.ToString('dd/MM HH:mm'), $e.Properties[4].Value, $e.Properties[1].Value) }

# Defender
$descDef = @{ 1116 = 'Menace détectée'; 1117 = 'Action sur menace'; 1118 = 'Échec de l''action'; 1119 = 'Échec critique'; 5001 = 'Temps réel désactivé'; 5007 = 'Configuration modifiée'; 5010 = 'Anti-espion désactivé'; 5012 = 'Antivirus désactivé'; 1121 = 'Blocage règle ASR'; 1122 = 'Audit règle ASR'; 1123 = 'Blocage accès aux dossiers'; 1124 = 'Audit accès aux dossiers'; 1127 = 'Blocage écriture protégée' }
$def = Get-Evts @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = 1116, 1117, 1118, 1119, 5001, 5007, 5010, 5012, 1121, 1122, 1123, 1124, 1127; StartTime = $dateEvenements } 300
Add-Ligne ''
Add-Ligne ('Événements Windows Defender importants : {0}' -f $def.Count)
Add-Table ($def | Select-Object -First 25 | ForEach-Object { [pscustomobject]@{ Date = $_.TimeCreated.ToString('dd/MM HH:mm'); Id = $_.Id; Type = $descDef[$_.Id]; Detail = (Couper $_.Message 220) } })
$vus5007 = @{}
foreach ($e in $def) {
    if ($e.Id -eq 5007 -and $e.Message -match 'Exclusions' -and -not $vus5007.ContainsKey($e.Message)) {
        $vus5007[$e.Message] = $true
        Add-Constat 'ELEVE' 'Antivirus' ("Exclusion Defender modifiée le {0}" -f $e.TimeCreated.ToString('dd/MM/yyyy HH:mm')) (Couper $e.Message 300) 'Vérifier si c''est vous qui l''avez ajoutée.'
    }
    if ($e.Id -in 5001, 5010, 5012) { Add-Constat 'ELEVE' 'Antivirus' ("{0} le {1}" -f $descDef[$e.Id], $e.TimeCreated.ToString('dd/MM/yyyy HH:mm')) '' 'Si ce n''est pas vous ou l''installation d''un autre antivirus, c''est suspect.' }
}
$blocagesCfa = @($def | Where-Object { $_.Id -in 1121, 1123 })
if ($blocagesCfa.Count) { Add-Constat 'INFO' 'Antivirus' ("Defender a bloqué {0} action(s) d'applications (ASR / accès contrôlé aux dossiers)" -f $blocagesCfa.Count) (Couper $blocagesCfa[0].Message 250) 'Peut expliquer des applications qui échouent ou se ferment.' }

# Scripts PowerShell suspects (journalisés automatiquement par Windows)
$psEvt = Get-Evts @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; Id = 4104; Level = 3; StartTime = $dateEvenements } 300
$psEvt = @($psEvt | Where-Object {
    $_.TimeCreated -lt $debut.AddMinutes(-1) -and
    [string]$_.Properties[4].Value -notmatch 'AnalysePC' -and
    [string]$_.Properties[2].Value -notmatch 'AnalysePC' -and
    (-not $PSCommandPath -or [string]$_.Properties[4].Value -ne $PSCommandPath) })
$psBlocs = @($psEvt | Group-Object { [string]$_.Properties[3].Value })
Add-Ligne ''
Add-Ligne ('Scripts PowerShell signalés comme suspects par Windows : {0}' -f $psBlocs.Count)
foreach ($g in ($psBlocs | Select-Object -First 6)) {
    $e = $g.Group[0]
    Add-Ligne ('  {0} | {1} | {2}' -f $e.TimeCreated.ToString('dd/MM HH:mm'), $e.Properties[4].Value, (Couper ([string]$e.Properties[2].Value) 300))
}
if ($psBlocs.Count) { Add-Constat 'ELEVE' 'PowerShell' ("{0} script(s) PowerShell suspect(s) exécuté(s)" -f $psBlocs.Count) (Couper ([string]$psBlocs[0].Group[0].Properties[2].Value) 300) 'Voir le contenu dans la section 10. Peut être légitime (outils d''administration) ou malveillant.' }

# =============================================================================
#  11. Comptes et configuration de sécurité
# =============================================================================
Start-Section '11. Comptes et configuration de sécurité'
Add-Ligne 'Comptes locaux :'
$users = Get-LocalUser
Add-Table ($users | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description)
foreach ($u in $users) {
    if ($u.Enabled -and $u.SID.Value -match '-500$') { Add-Constat 'MOYEN' 'Comptes' ("Compte Administrateur intégré activé ({0})" -f $u.Name) '' 'Normalement désactivé. Le désactiver s''il n''est pas utilisé.' }
    if ($u.Enabled -and $u.SID.Value -match '-501$') { Add-Constat 'MOYEN' 'Comptes' 'Compte Invité activé' '' 'À désactiver.' }
}
Add-Ligne 'Membres du groupe Administrateurs :'
Add-Table (Get-LocalGroupMember -SID 'S-1-5-32-544' | Select-Object Name, ObjectClass, PrincipalSource)

Add-Ligne ''
Add-Ligne 'Configuration :'
$sysPol = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
Add-Ligne ('  Contrôle de compte (UAC) : EnableLUA={0}, ConsentPromptBehaviorAdmin={1}' -f $sysPol.EnableLUA, $sysPol.ConsentPromptBehaviorAdmin)
if ($sysPol.EnableLUA -eq 0) { Add-Constat 'ELEVE' 'Configuration' 'Contrôle de compte utilisateur (UAC) désactivé' '' 'Tout programme obtient les droits administrateur sans demande. À réactiver.' }
elseif ($sysPol.ConsentPromptBehaviorAdmin -eq 0) { Add-Constat 'MOYEN' 'Configuration' 'UAC ne demande plus de confirmation aux administrateurs' '' 'Réglage affaibli, souvent modifié par des malwares.' }
foreach ($fw in Get-NetFirewallProfile) {
    Add-Ligne ('  Pare-feu {0} : {1}' -f $fw.Name, (OuiNon ([string]$fw.Enabled -eq 'True')))
    if ([string]$fw.Enabled -ne 'True') { Add-Constat 'MOYEN' 'Configuration' ("Pare-feu Windows désactivé (profil {0})" -f $fw.Name) '' 'À réactiver sauf si un autre pare-feu est installé.' }
}
$rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
Add-Ligne ('  Bureau à distance autorisé : {0}' -f (OuiNon ($rdp.fDenyTSConnections -eq 0)))
if ($rdp.fDenyTSConnections -eq 0) { Add-Constat 'MOYEN' 'Configuration' 'Bureau à distance activé' '' 'À désactiver si vous ne l''utilisez pas.' }
$smb = Get-SmbServerConfiguration
if ($smb) {
    Add-Ligne ('  SMBv1 (protocole obsolète) : {0}' -f (OuiNon $smb.EnableSMB1Protocol))
    if ($smb.EnableSMB1Protocol) { Add-Constat 'MOYEN' 'Configuration' 'SMBv1 activé (protocole exploité par WannaCry)' '' 'À désactiver.' }
}
$hotfix = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
if ($hotfix) {
    Add-Ligne ('  Dernière mise à jour installée : {0} ({1})' -f $hotfix.InstalledOn.ToString('dd/MM/yyyy'), $hotfix.HotFixID)
    if (($debut - $hotfix.InstalledOn).TotalDays -gt 60) { Add-Constat 'MOYEN' 'Configuration' ("Aucune mise à jour Windows depuis le {0}" -f $hotfix.InstalledOn.ToString('dd/MM/yyyy')) '' 'Lancer Windows Update. Si cela échoue, le signaler.' }
}
try { Add-Ligne ('  Secure Boot : {0}' -f (OuiNon (Confirm-SecureBootUEFI -ErrorAction Stop))) } catch { Add-Ligne '  Secure Boot : non disponible (BIOS ancien mode)' }

Add-Ligne ''
Add-Ligne 'Règles de pare-feu autorisant des programmes situés dans des dossiers utilisateur :'
$reglesFw = foreach ($af in Get-NetFirewallApplicationFilter | Where-Object { $_.Program -match $regexCheminSuspect }) {
    $regle = $af | Get-NetFirewallRule
    if (-not $regle -or [string]$regle.Enabled -ne 'True' -or [string]$regle.Action -ne 'Allow') { continue }
    $prog = [Environment]::ExpandEnvironmentVariables($af.Program)
    $sig = Get-InfoSignature $prog
    if ($sig.Statut -notin 'Valid', 'Introuvable' -and [string]$regle.Direction -eq 'Inbound') { Add-Constat 'MOYEN' 'Réseau' ("Pare-feu : programme non signé autorisé en entrée : {0}" -f (Split-Path $prog -Leaf)) $prog 'Vérifier ce programme.' }
    [pscustomobject]@{ Regle = $regle.DisplayName; Sens = $regle.Direction; Signature = $sig.Statut; Programme = $prog }
}
Add-Table ($reglesFw | Sort-Object Programme -Unique)

# =============================================================================
#  12. Disques et intégrité de Windows
# =============================================================================
Start-Section '12. Santé des disques et intégrité de Windows'
foreach ($d in Get-PhysicalDisk) {
    $rel = $d | Get-StorageReliabilityCounter
    $extra = ''
    if ($rel) { $extra = (' | usure {0} % | température {1} °C | erreurs de lecture non corrigées {2}' -f $rel.Wear, $rel.Temperature, $rel.ReadErrorsUncorrected) }
    Add-Ligne ('Disque {0} ({1}, {2} Go) : santé {3}, état {4}{5}' -f $d.FriendlyName, $d.MediaType, [math]::Round($d.Size / 1GB), $d.HealthStatus, (@($d.OperationalStatus) -join ','), $extra)
    if ([string]$d.HealthStatus -ne 'Healthy') { Add-Constat 'ELEVE' 'Disque' ("Disque {0} signalé en mauvaise santé ({1})" -f $d.FriendlyName, $d.HealthStatus) '' 'Sauvegarder vos données au plus vite.' }
    if ($rel -and $rel.Wear -ge 80) { Add-Constat 'MOYEN' 'Disque' ("SSD {0} usé à {1} %" -f $d.FriendlyName, $rel.Wear) '' 'Prévoir son remplacement.' }
    if ($rel -and $rel.ReadErrorsUncorrected -gt 0) { Add-Constat 'ELEVE' 'Disque' ("Disque {0} : {1} erreurs de lecture non corrigées" -f $d.FriendlyName, $rel.ReadErrorsUncorrected) '' 'Cause directe de fichiers corrompus. Sauvegarder.' }
}
$dirty = ((& fsutil dirty query $env:SystemDrive) -join ' ').Trim()
Add-Ligne ('Marqueur de vérification du volume : ' + $dirty)
if ($dirty -match '(?i)\bis dirty\b| est sale') { Add-Constat 'MOYEN' 'Disque' ("Le volume {0} est marqué pour vérification" -f $env:SystemDrive) '' 'Lancer chkdsk C: /scan.' }

Write-Host '   Vérification de l''image Windows (DISM CheckHealth)...' -ForegroundColor DarkGray
$img = Repair-WindowsImage -Online -CheckHealth
if ($img) {
    Add-Ligne ('Image Windows (DISM CheckHealth) : ' + $img.ImageHealthState)
    if ([string]$img.ImageHealthState -ne 'Healthy') { Add-Constat 'ELEVE' 'Intégrité' ("Image Windows endommagée ({0})" -f $img.ImageHealthState) '' 'Lancer : DISM /Online /Cleanup-Image /RestoreHealth puis sfc /scannow' }
} else { Add-Ligne 'Image Windows (DISM CheckHealth) : vérification impossible' }

if ($VerifSysteme) {
    Write-Host '   sfc /verifyonly en cours (10 à 20 minutes, ne pas fermer)...' -ForegroundColor DarkGray
    $sortieSfc = (& "$env:SystemRoot\System32\sfc.exe" /verifyonly 2>&1 | Out-String) -replace "`0", ''
    $dernieres = @(($sortieSfc -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -Last 4)
    Add-Ligne 'Résultat sfc /verifyonly :'
    foreach ($l in $dernieres) { Add-Ligne ('  ' + $l.Trim()) }
    if ($sortieSfc -match '(?i)found integrity violations|a trouv.{1,2} des violations') { Add-Constat 'ELEVE' 'Intégrité' 'Fichiers système Windows corrompus (sfc)' '' 'Lancer : DISM /Online /Cleanup-Image /RestoreHealth puis sfc /scannow' }
} else {
    Add-Ligne 'sfc /verifyonly non lancé (relancer le script avec -VerifSysteme pour l''inclure).'
}

# =============================================================================
#  Rédaction des rapports
# =============================================================================
$fin = Get-Date
$duree = $fin - $debut
$minutes = [int][math]::Floor($duree.TotalMinutes)
$nb = @{}
foreach ($g in 'CRITIQUE', 'ELEVE', 'MOYEN', 'INFO') { $nb[$g] = @($script:Constats | Where-Object { $_.Gravite -eq $g }).Count }
$constatsTries = @($script:Constats | Sort-Object Ordre, Categorie)

$verdict = 'Aucun signe notable d''infection détecté.'
if ($nb['CRITIQUE'] -gt 0)  { $verdict = 'Signes forts de compromission : couper Internet et transmettre le rapport avant toute action.' }
elseif ($nb['ELEVE'] -gt 0) { $verdict = 'Éléments suspects à analyser en priorité.' }
elseif ($nb['MOYEN'] -gt 0) { $verdict = 'Quelques points à vérifier, rien d''alarmant à première vue.' }

# --- TXT ---
$sb = New-Object System.Text.StringBuilder
function Add-Txt([string]$T = '') { [void]$sb.AppendLine($T) }
Add-Txt ('=' * 100)
Add-Txt ' RAPPORT AnalysePC'
Add-Txt (' Généré le {0} en {1} min {2} s | PC {3} | {4} {5}' -f $fin.ToString('dd/MM/yyyy HH:mm'), $minutes, $duree.Seconds, $env:COMPUTERNAME, $os.Caption, $verWin.DisplayVersion)
Add-Txt ('=' * 100)
Add-Txt (' RÉSUMÉ : CRITIQUE {0} | ÉLEVÉ {1} | MOYEN {2} | INFO {3}' -f $nb['CRITIQUE'], $nb['ELEVE'], $nb['MOYEN'], $nb['INFO'])
Add-Txt (' VERDICT : ' + $verdict)
Add-Txt ('-' * 100)
if ($constatsTries.Count -eq 0) { Add-Txt ' Aucun constat.' }
foreach ($c in $constatsTries) {
    Add-Txt (' [{0}] {1} : {2}' -f $c.Gravite, $c.Categorie, $c.Description)
    if ($c.Element) { Add-Txt ('      Élément : ' + $c.Element) }
    if ($c.Conseil) { Add-Txt ('      Conseil : ' + $c.Conseil) }
}
Add-Txt ''
foreach ($s in $script:Sections) {
    Add-Txt ('=' * 100)
    Add-Txt (' ' + $s.Titre)
    Add-Txt ('=' * 100)
    foreach ($l in $s.Lignes) { Add-Txt $l }
    Add-Txt ''
}
Add-Txt ' Fin du rapport AnalysePC.'
$texte = $sb.ToString()

# --- HTML ---
function Enc([string]$T) { [System.Net.WebUtility]::HtmlEncode($T) }
$libelles = @{ 'CRITIQUE' = 'Critique'; 'ELEVE' = 'Élevé'; 'MOYEN' = 'Moyen'; 'INFO' = 'Info' }
$hb = New-Object System.Text.StringBuilder
function Add-Html([string]$T) { [void]$hb.AppendLine($T) }
Add-Html '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
Add-Html ('<title>Rapport AnalysePC - {0}</title>' -f (Enc $env:COMPUTERNAME))
Add-Html @'
<style>
:root{--bg:#f4f6f9;--fg:#1c2230;--carte:#fff;--bord:#d8dde6;--sub:#5d6778;--crit:#9c27b0;--elev:#d32f2f;--moy:#e08600;--info:#607d8b}
@media (prefers-color-scheme: dark){:root{--bg:#13161b;--fg:#e5e8ee;--carte:#1c2027;--bord:#323843;--sub:#9aa3b3;--crit:#ce6ee0;--elev:#ff6b6b;--moy:#ffb340;--info:#90a4ae}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1250px;margin:0 auto;padding:28px 20px 60px}
h1{font-size:26px;margin:0 0 4px}
h2{font-size:19px;margin:34px 0 12px}
.sub{color:var(--sub)}
.verdict{margin:18px 0;padding:14px 18px;border-radius:10px;background:var(--carte);border:1px solid var(--bord);font-weight:600}
.badges{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.badge{background:var(--carte);border:1px solid var(--bord);border-left:6px solid var(--info);border-radius:10px;padding:12px 16px}
.badge b{display:block;font-size:30px;line-height:1.1}
.badge.CRITIQUE{border-left-color:var(--crit)}.badge.ELEVE{border-left-color:var(--elev)}.badge.MOYEN{border-left-color:var(--moy)}
.tab{overflow-x:auto;border:1px solid var(--bord);border-radius:10px;background:var(--carte)}
table{width:100%;border-collapse:collapse}
th,td{padding:9px 12px;border-bottom:1px solid var(--bord);vertical-align:top;text-align:left}
th{font-size:13px;color:var(--sub);font-weight:600}
td.g{font-weight:700;white-space:nowrap}
tr.CRITIQUE td.g{color:var(--crit)}tr.ELEVE td.g{color:var(--elev)}tr.MOYEN td.g{color:var(--moy)}tr.INFO td.g{color:var(--info)}
.el{font-family:Consolas,monospace;font-size:12.5px;word-break:break-all;color:var(--sub);margin-top:4px}
.cs{font-size:13.5px;margin-top:4px}
details{background:var(--carte);border:1px solid var(--bord);border-radius:10px;margin:10px 0}
summary{cursor:pointer;padding:11px 16px;font-weight:600}
pre{margin:0;padding:14px 16px;overflow-x:auto;font:12.5px/1.45 Consolas,"Cascadia Mono",monospace;border-top:1px solid var(--bord)}
.etapes{background:var(--carte);border:1px solid var(--bord);border-radius:10px;padding:6px 22px}
</style></head><body><main>
'@
Add-Html '<h1>Rapport AnalysePC</h1>'
Add-Html ('<div class="sub">{0} | {1} {2} | généré le {3} en {4} min</div>' -f (Enc $env:COMPUTERNAME), (Enc $os.Caption), (Enc $verWin.DisplayVersion), $fin.ToString('dd/MM/yyyy HH:mm'), $minutes)
Add-Html '<div class="badges">'
foreach ($g in 'CRITIQUE', 'ELEVE', 'MOYEN', 'INFO') { Add-Html ('<div class="badge {0}"><b>{1}</b>{2}</div>' -f $g, $nb[$g], $libelles[$g]) }
Add-Html '</div>'
Add-Html ('<div class="verdict">{0}</div>' -f (Enc $verdict))
Add-Html '<h2>Que faire maintenant</h2><div class="etapes"><ol>'
Add-Html '<li>Ne supprimez rien pour l''instant : certains éléments signalés peuvent être légitimes.</li>'
Add-Html '<li>Transmettez le fichier <b>rapport.txt</b> (même dossier) pour obtenir un plan d''action précis.</li>'
if ($nb['CRITIQUE'] -gt 0) { Add-Html '<li><b>Constat critique :</b> débranchez Internet, n''utilisez pas ce PC pour vos comptes bancaires, et changez vos mots de passe depuis un autre appareil.</li>' }
Add-Html '<li>Pour vérifier un fichier sans l''ouvrir : copiez son empreinte SHA256 dans la recherche de <b>virustotal.com</b>.</li>'
Add-Html '</ol></div>'
Add-Html '<h2>Constats</h2>'
if ($constatsTries.Count -eq 0) { Add-Html '<p>Aucun constat.</p>' }
else {
    Add-Html '<div class="tab"><table><thead><tr><th>Gravité</th><th>Catégorie</th><th>Détail</th></tr></thead><tbody>'
    foreach ($c in $constatsTries) {
        $cellule = Enc $c.Description
        if ($c.Element) { $cellule += '<div class="el">' + (Enc $c.Element) + '</div>' }
        if ($c.Conseil) { $cellule += '<div class="cs">&rarr; ' + (Enc $c.Conseil) + '</div>' }
        Add-Html ('<tr class="{0}"><td class="g">{1}</td><td>{2}</td><td>{3}</td></tr>' -f $c.Gravite, $libelles[$c.Gravite], (Enc $c.Categorie), $cellule)
    }
    Add-Html '</tbody></table></div>'
}
Add-Html '<h2>Détails par section</h2>'
foreach ($s in $script:Sections) {
    Add-Html ('<details><summary>{0}</summary><pre>{1}</pre></details>' -f (Enc $s.Titre), (Enc (($s.Lignes) -join "`n")))
}
Add-Html '</main></body></html>'
$html = $hb.ToString()

# --- Anonymisation éventuelle ---
if ($Anonymiser) {
    $noms = @(@($profils | ForEach-Object { Split-Path $_.LocalPath -Leaf }) + $env:USERNAME | Where-Object { $_ -and $_.Length -ge 3 } | Select-Object -Unique)
    foreach ($n in $noms) {
        $texte = $texte -replace [regex]::Escape($n), '<UTILISATEUR>'
        $html  = $html  -replace [regex]::Escape($n), '&lt;UTILISATEUR&gt;'
    }
    if ($env:COMPUTERNAME.Length -ge 3) {
        $texte = $texte -replace [regex]::Escape($env:COMPUTERNAME), '<PC>'
        $html  = $html  -replace [regex]::Escape($env:COMPUTERNAME), '&lt;PC&gt;'
    }
}

$utf8Bom = New-Object System.Text.UTF8Encoding($true)
[System.IO.File]::WriteAllText($fichierTxt, $texte, $utf8Bom)
[System.IO.File]::WriteAllText($fichierHtml, $html, $utf8Bom)

# --- Résumé console ---
Write-Host ''
Write-Host '=====================================================================' -ForegroundColor Cyan
Write-Host ('  Analyse terminée en {0} min {1} s' -f $minutes, $duree.Seconds) -ForegroundColor Cyan
Write-Host '=====================================================================' -ForegroundColor Cyan
Write-Host ('  CRITIQUE : {0}' -f $nb['CRITIQUE']) -ForegroundColor Magenta
Write-Host ('  ÉLEVÉ    : {0}' -f $nb['ELEVE']) -ForegroundColor Red
Write-Host ('  MOYEN    : {0}' -f $nb['MOYEN']) -ForegroundColor Yellow
Write-Host ('  INFO     : {0}' -f $nb['INFO']) -ForegroundColor Gray
Write-Host ''
Write-Host ('  ' + $verdict) -ForegroundColor White
Write-Host ''
Write-Host ('  Rapport lisible   : {0}' -f $fichierHtml) -ForegroundColor Green
Write-Host ('  Rapport à envoyer : {0}' -f $fichierTxt) -ForegroundColor Green
Write-Host ''
if (-not $PasOuvrir) { Start-Process $fichierHtml; Start-Process explorer.exe -ArgumentList ('"' + $dossierSortie + '"') }