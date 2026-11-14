# Indicateurs de compromission

À la date de l'analyse, ni les empreintes ni les adresses n'apparaissaient dans les sources publiques consultées.

## Réseau

| Indicateur | Rôle |
| --- | --- |
| `pdf-viewer.top` | Serveur de l'implant 1 |
| `144.48.61.40`, TCP 6700 | Adresse de `pdf-viewer.top` |
| `67.43.50.11`, TCP 12584 | Serveur de l'implant 2 |

## Fichiers (SHA256)

| Fichier | SHA256 |
| --- | --- |
| `certificate.cer` | `8F470248E1A0093D3512E6D86B80BE7D2CE4272F295EC4C1B4351E04FAA07658` |
| `Cloud.ocx` | `35882420A2ABB9A857E2B93DA48A0FF661763179D0277D2CA1743A45F7BE9834` |
| `Fire.ocx` | `5F5D2BA63FC9F9332DC5EF10274ABE9C39FD655F1E177C1C0139371F2B2E2702` |
| `Swap.dll` | `5F8336EF7F7537823F3DCB01A97D63EB81B1C0CBAF97FA0B7B469EF60DABCFD9` |
| `wuacult.wsf` | `4357824F0CE1C40863866C2C1B072C5362B988DFC787BBFA5B24A33D1C7095F9` |
| `filetext.txt` | `1D0D0BCAF0F7FEA73C5EE4E239D6F5FD4A9AC2EC0B5E0094E468BED384E34A8C` |
| `clspack.exe` | `2915EFECF2A01CE0B3EF49C47666EC43C326E7804DF10E5859DB5F08EECA8A37` |
| `newdev.exe` | `1675B87BE879B45739C08D9098EF754526CE032EA054AD754B2FEF3EFAFF6AB1` |
| `TexturePackerLib.dll` | `FA73D8368C1DB36FB3FA898C0FB5E2C902947F4D5AD4ED0709FF16A33A75FD2A` |
| `backup.zip` | `BAFE53985387A31603B3E094845CAD9D705BB56B9F90EFF426C3440FFD6FB456` |

Fichiers légitimes détournés, à ne pas bloquer par empreinte seule :

| Fichier | SHA256 |
| --- | --- |
| `TexturePackerGUI.exe` (signé, aussi renommé `GPU-Z.exe`) | `338A972EC08EBE07B793804B20A4B38E47B5477378C00473DFC02878E29CAEAF` |
| `VS12-KB2961101 (N).exe` (signé Microsoft) | `C20E1520347B7472A5AA17D84828C515BB8FB75DB216A4599B97DA4A2EF472EB` |

## Chemins et noms

- `%APPDATA%\NonceChange\`
- `%APPDATA%\Microsoft\clspack.exe`
- `%APPDATA%\GPU-Z\Logs\` (attributs caché et système)
- `%APPDATA%\test.png`, `%APPDATA%\image.png`
- `C:\intel\TexturePackerGUI.exe`
- `C:\hp\install.vbs`
- `%TEMP%\VS12-KB2961101 (N).exe`
- `%TEMP%\dotnet_perf_*` (profils de navigateur)
- `IMAGE_JJMMAAAA.PIF`

## Registre

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, valeur `SearchDirectory` = `explorer.exe "SearchDirectory://Newest"`
- `HKCU\Software\Classes\SearchDirectory\shell\open\command`
- `HKCU\Software\Classes\CLSID\{7F222C4E-56B0-4E46-8359-E24FE3A4B975}` et son équivalent sous `WOW6432Node`, nom « Pure.Fire »
- Bibliothèque de types `{8F1576C0-BB08-4F05-87A6-268C0D548794}`

## Tâche planifiée et installation

- Tâche `\GPUZLogAutoSave`, auteur déclaré « TechPowerUp », action `C:\intel\TexturePackerGUI.exe`, répétition `PT1M`
- Produit Windows Installer « Safe® Softwares », version 5.2558.3668.5513

## Requêtes de détection

```powershell
# Clé Run qui passe par un protocole personnalisé
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' |
    ForEach-Object { $_.PSObject.Properties } |
    Where-Object { $_.Value -match 'explorer(\.exe)?\s+"?[a-z][a-z0-9+.-]*://' }

# Protocoles ou classes utilisateur dont la commande lance rundll32 sur un CLSID
Get-ChildItem 'HKCU:\Software\Classes' -ErrorAction SilentlyContinue | ForEach-Object {
    $k = $_.OpenSubKey('shell\open\command')
    if ($k -and "$($k.GetValue(''))" -match 'rundll32.*\{[0-9A-Fa-f-]{36}\}') { $_.Name; $k.GetValue('') }
}

# Commandes lancées au démarrage de session, sur 14 jours
Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Shell-Core/Operational'; Id = 9707; StartTime = (Get-Date).AddDays(-14) } |
    Select-Object TimeCreated, Message
```
