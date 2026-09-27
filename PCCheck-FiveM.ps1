<#
.SYNOPSIS
    PC Check forense para servidores FiveM - coleta de artefatos de execucao no Windows.

.DESCRIPTION
    Coleta e correlaciona artefatos forenses do Windows para auxiliar staff de servidores
    FiveM em verificacoes de PC consentidas ("PC check"). O script apenas LE informacoes:
    nao altera, nao remove e nao envia nada para a internet. No fim gera um relatorio
    HTML (e um .txt) que o jogador envia a staff.

    IMPORTANTE:
      - Execute somente com o consentimento explicito do dono da maquina.
      - Nenhum resultado aqui e prova definitiva de cheat. Sao INDICIOS que precisam
        ser interpretados por um humano. Falsos positivos sao comuns.

.PARAMETER OutputPath
    Pasta onde o relatorio sera gravado. Padrao: Desktop do usuario.

.PARAMETER Quick
    Modo rapido: reduz profundidade de varredura e pula verificacao de assinatura.

.PARAMETER NoOpen
    Nao abre o relatorio HTML ao final.

.PARAMETER KeepScript
    Mantem o .ps1 no disco. Por padrao o script apaga-se sozinho no fim, para o
    jogador nao ficar com uma copia. Os relatorios (.html/.txt) nao sao tocados.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Desktop\PCCheck-FiveM.ps1"

.NOTES
    Autor  : Kooshi
    Requer : PowerShell 5.1+. Rode como Administrador para cobertura completa.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = [Environment]::GetFolderPath('Desktop'),
    [switch]$Quick,
    [switch]$NoOpen,
    [switch]$KeepScript
)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# ============================================================================
#  ESTADO GLOBAL
# ============================================================================
$script:Autor     = 'Kooshi'
$script:Versao    = '2.6'
$script:Sections  = [ordered]@{}
$script:Findings  = New-Object System.Collections.ArrayList
$script:StartTime = Get-Date

# Palavras-chave associadas a cheats. Divididas em dois niveis para reduzir ruido.
#
#   FORTES = praticamente inequivocas (marcas de cheat, ferramentas de injecao).
#            Geram achado de severidade ALTA.
#   FRACAS = ambiguas, aparecem em contexto legitimo o tempo todo.
#            Geram achado MEDIA e NAO sao usadas em URLs de navegador.
$script:StrongKeywords = @(
    # ---- Marcas de cheat/menu para FiveM (pagos, os mais vendidos) ----------
    'eulen','redengine','red engine','skript.gg','skriptgg','skript gg',
    'desudo','tzx','brutan','susano','susanoo','hammafia','ham mafia',
    'absolute menu','absolutecheat','absolute cheat','phantomx','phantom x',
    'impulse menu','paragon menu','disturbed menu','nemesis menu','hydro menu',
    'tsunami menu','manticore','fatality cheat','cobra menu','astral menu',
    'aurora menu','wave menu','fewnix','hx cheats','hxcheats','d3adeye',
    'lynx menu','lynxmenu','fivesync','redseer','oneup menu','1up menu',
    'euphoria menu','quantum menu','spectre menu','celestial menu',
    'hydrogen menu','oxygen menu','vex menu','fenix menu','breeze menu',
    'requiem menu','eclipse menu','skyline menu','fusion menu','harmony menu',
    'tsar menu','saturn menu','nexus menu','doomware','solarware','crayon menu',
    # ---- Menus de GTA Online frequentemente usados em FiveM ------------------
    'kiddions','rampage menu','menyoo','lambda menu','stand menu','2take1',
    '2take1menu','cherax','midnight menu','luna menu','x-force menu',
    # ---- Termos genericos inequivocos ----------------------------------------
    'aimbot','aim bot','triggerbot','trigger bot','wallhack','wall hack',
    'mod menu','modmenu','no recoil','norecoil','silent aim','silentaim',
    'esp hack','lua executor','luaexec','fov changer','giveweapon',
    'noclip','no clip','no-clip','fly hack','flyhack','speedhack','speed hack',
    'anti aim','antiaim','spinbot','bhop','bunny hop','no spread','nospread',
    'god mode hack','godmode hack','infinite ammo','unlimited ammo',
    'esp menu','esp box','chams','aim assist hack','magic bullet','instant kill',
    # ---- Ferramentas de injecao / mapeamento manual (BYOVD) ------------------
    'extremeinjector','extreme injector','xenos injector','xenos64','gh injector',
    'guidedhacking','kdmapper','kernel mapper','manualmap','manual map',
    'scyllahide','cheat engine','cheatengine','processhacker','process hacker',
    'x64dbg','x32dbg','reclass.net','reclassex','unknowncheats','uc forum',
    # ---- Spoofers de HWID / evasao de ban ------------------------------------
    'hwid spoofer','hwidspoofer','hwid unlock','serial spoof','disk spoof',
    'mac spoofer','tz spoofer','exon spoofer','perm spoofer','permanent spoofer',
    # ---- Anti-forense (formas destrutivas) -----------------------------------
    'bleachbit','privazer','wipefile','prefetch cleaner','timestomp','deletejournal',
    # ---- Lag switch / manipulacao de pacotes (desync) ------------------------
    'clumsy','lag switch','lagswitch','windivert','netlimiter','net limiter',
    'netbalancer','packet dropper','packet loss tool'
)

$script:WeakKeywords = @(
    'cheat','hack','crack','trainer','spoofer','hwid','unlocker','bypass',
    'keygen','injector','inject','dumper','executor','godmode','god mode',
    'ollydbg','ida64','reclass','vmprotect','themida','de4dot','dnspy','ilspy',
    'ccleaner','sdelete','eraser portable','loader','cracked',
    # redutores de ping legitimos (dual-use): so aviso MEDIA, muita gente usa
    'wtfast','exitlag','kill ping','killping','speedify','cfosspeed','pingplotter','haste client'
)

# Lista RESTRITA usada SO na procura DENTRO do conteudo dos ficheiros.
# Deixa de fora verbos de jogo (noclip, giveweapon, god mode, no recoil, fly...)
# porque aparecem em scripts LEGITIMOS de FiveM (admin do ESX/QBCore, etc.).
# So marcas de cheat inequivocas e ferramentas de injecao/RE.
$script:ContentKeywords = @(
    'eulen','redengine','red engine','skript.gg','skriptgg','desudo','susano',
    'susanoo','hammafia','absolutecheat','phantomx','impulse menu','paragon menu',
    'disturbed menu','nemesis menu','hydro menu','tsunami menu','manticore',
    'fatality cheat','cobra menu','astral menu','aurora menu','fewnix','hxcheats',
    'd3adeye','lynxmenu','redseer','cherax','2take1','kiddions','unknowncheats',
    'aimbot','triggerbot','silentaim','silent aim','wallhack','spinbot',
    'antiaim','anti aim','esp hack','extremeinjector','xenos injector','gh injector',
    'guidedhacking','kdmapper','manualmap','scyllahide','reclass.net'
)

# Dominios de venda/forum de cheat. Usados SO no historico do navegador, onde
# um dominio pega a visita mesmo quando a URL nao tem palavra obvia.
# Comparados como substring simples (sem limite de palavra).
$script:CheatDomains = @(
    'unknowncheats.me','elitepvpers.com','eulen.cc','eulencheats',
    'redengine.io','redengine.gg','skript.gg','desudo.cc','tzhero',
    'hammafia','susano.gg','impulse.gg','disturbed.cc','manticore',
    'fatality.win','cobra.gg','fewnix','hx-cheats','d3adeye','lynx.cx',
    'gtacheats','fivem-cheats','fivemcheats','ragehack','ragecheats',
    'cherax.pro','2take1.menu','stand.gg','midnight-menu','guidedhacking.com',
    'cheatengine.org','nightfall','wearedevs','v3rmillion','v3rm'
)

# Contextos legitimos que contem as palavras acima e devem ser ignorados.
# Sao removidos do texto ANTES da comparacao.
$script:BenignPattern = '(?i)(anti[- ]?cheat|anticheat|easyanticheat|eac_|battleye|punkbuster|denuvo|vanguard|faceit|esea|cheat\s?sheet|hackathon|hackerrank|hacker\s?news|life\s?hack|growth\s?hack|crackle|nutcracker|firecracker|injector\s?pen|game\s?loader|boot\s?loader|down\s?loader|up\s?loader|re\s?loader)'

# Compatibilidade: lista unica usada por quem precisa de ambos os niveis.
$script:CheatKeywords = $script:StrongKeywords + $script:WeakKeywords

# Executaveis/arquivos legitimos que NAO devem ser sinalizados, mesmo sem
# assinatura valida ou dentro da pasta do FiveM. Nomes em minusculas.
$script:BenignFiles = @(
    # jogo e launchers
    'gta5.exe','gta5_enhanced.exe','gtavlauncher.exe','gta_v_launcher.exe',
    'playgtav.exe','launcher.exe','rockstarservice.exe','rockstarerrorhandler.exe',
    'socialclubhelper.exe','steam.exe','steamwebhelper.exe','steamservice.exe',
    'epicgameslauncher.exe','egslauncher.exe',
    # cliente FiveM / CitizenFX (subprocessos legitimos)
    'fivem.exe','fivem_gtaprocess.exe','fivem_dumpserver.exe','fivem_chrome.exe',
    'fivem_subprocess.exe','citizenfx.exe','citizengame.exe','cfx.re','redm.exe',
    'redm_gtaprocess.exe','redm_dumpserver.exe','chrome_subprocess.exe'
)

# Extensoes de modulo que o FiveM realmente carrega da pasta plugins.
# Qualquer outra coisa la (imagens, txt, screenshots) e listada como INFO.
$script:PluginModuleExt = @('.dll','.asi','.lua','.rpf','.ynv')

function Test-BenignFile {
    param([string]$Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return $false }
    return ($script:BenignFiles -contains (Split-Path $Name -Leaf).ToLowerInvariant())
}

# Drivers legitimos porem frequentemente abusados para mapeamento manual (BYOVD).
$script:BadDrivers = @(
    'iqvw64e.sys','gdrv.sys','gdrv2.sys','rtcore64.sys','atszio64.sys','atszio.sys',
    'capcom.sys','winio.sys','winio64.sys','winring0x64.sys','winring0.sys',
    'dbutil_2_3.sys','dbutildrv2.sys','msio64.sys','msio.sys','procexp152.sys',
    'speedfan.sys','eneio64.sys','enetechio64.sys','asrdrv10.sys','asrdrv101.sys',
    'asrdrv102.sys','nvflash.sys','amifldrv64.sys','piddrv64.sys','phymemx64.sys',
    'kprocesshacker.sys','segwindrvx64.sys','mhyprot2.sys','dbk64.sys',
    'hwinfo64a.sys','cpuz141.sys','glckio2.sys','elrawdsk.sys','rwdrv.sys'
)

# Drivers de manipulacao de rede (lag switch: clumsy, NetLimiter, etc.).
# Presenca/carregamento e sinal de ferramenta de desync ativa.
$script:NetDrivers = @(
    'windivert.sys','windivert64.sys','windivert32.sys','netfilter2.sys','nfnhk.sys'
)

# ============================================================================
#  HELPERS
# ============================================================================
function Write-Step {
    param([string]$Text)
    Write-Host ("  [>] " + $Text) -ForegroundColor DarkCyan
}

function Add-Section {
    param([string]$Name, $Data, [string]$Note = '')
    $script:Sections[$Name] = [PSCustomObject]@{
        Name = $Name
        Note = $Note
        Data = @($Data)
    }
}

function Add-Finding {
    param(
        [ValidateSet('ALTA','MEDIA','BAIXA','INFO')][string]$Severity,
        [string]$Title,
        [string]$Detail = ''
    )
    [void]$script:Findings.Add([PSCustomObject]@{
        Severity = $Severity
        Title    = $Title
        Detail   = $Detail
    })
}

function Get-KeywordHits {
    <#
      Compara o texto com uma lista de palavras-chave usando limite de palavra,
      depois de remover contextos legitimos conhecidos (anti-cheat, Denuvo, etc).
      Retorna string vazia quando nao ha correspondencia.
    #>
    param([string]$Text, [string[]]$Keywords)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }

    # Remove contextos benignos para nao contar "Anti-Cheat" como "cheat".
    $clean = [regex]::Replace($Text.ToLowerInvariant(), $script:BenignPattern, ' ')

    $hits = @()
    foreach ($k in $Keywords) {
        # \b antes da palavra evita casar no meio de outra (hackathon, crackle...).
        # Sem \b no fim, para aceitar plurais e sufixos (cheats, injector...).
        $pattern = '\b' + [regex]::Escape($k)
        if ([regex]::IsMatch($clean, $pattern)) { $hits += $k }
    }
    if ($hits.Count -gt 0) { return (($hits | Select-Object -Unique) -join ', ') }
    return ''
}

function Test-Keyword {
    # Nivel completo: fortes + fracas. Usado na maioria dos artefatos.
    param([string]$Text)
    return (Get-KeywordHits -Text $Text -Keywords $script:CheatKeywords)
}

function Test-KeywordStrong {
    # Apenas termos inequivocos. Usado onde o volume de texto gera ruido (URLs).
    param([string]$Text)
    return (Get-KeywordHits -Text $Text -Keywords $script:StrongKeywords)
}

function Test-KeywordContent {
    # Lista restrita para procurar DENTRO de ficheiros (sem verbos de jogo,
    # que existem em scripts legitimos de FiveM).
    param([string]$Text)
    return (Get-KeywordHits -Text $Text -Keywords $script:ContentKeywords)
}

function Get-KeywordSeverity {
    # ALTA se bateu em termo forte, MEDIA se so bateu em termo ambiguo.
    param([string]$Text)
    if (Test-KeywordStrong $Text) { return 'ALTA' }
    return 'MEDIA'
}

function Get-ExtraDriveRoots {
    # Raizes de discos FIXOS (2o disco interno, externo) e REMOVIVEIS (pen/HDD USB),
    # excluindo o disco do sistema. Ignora rede (lento) e CD/DVD.
    $sysRoot = ($env:SystemDrive + '\')
    $roots = @()
    try {
        foreach ($d in (Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue)) {
            if ($d.DriveType -ne 2 -and $d.DriveType -ne 3) { continue }   # 2=removivel, 3=fixo
            $r = $d.DeviceID + '\'
            if ($r -ieq $sysRoot) { continue }
            if (Test-Path $r) { $roots += $r }
        }
    } catch { }
    return ($roots | Select-Object -Unique)
}

function ConvertFrom-Rot13 {
    param([string]$Text)
    $sb = New-Object System.Text.StringBuilder
    foreach ($c in $Text.ToCharArray()) {
        $code = [int][char]$c
        if     ($code -ge 65 -and $code -le 90)  { $code = (($code - 65 + 13) % 26) + 65 }
        elseif ($code -ge 97 -and $code -le 122) { $code = (($code - 97 + 13) % 26) + 97 }
        [void]$sb.Append([char]$code)
    }
    return $sb.ToString()
}

function ConvertTo-DateSafe {
    param([long]$FileTime)
    try {
        if ($FileTime -le 0) { return $null }
        return [DateTime]::FromFileTime($FileTime)
    } catch { return $null }
}

# Callback opcional usado pelo modo GUI para manter a janela a responder
# durante tarefas longas. Em modo consola fica nulo e nao custa nada.
$script:UiPump   = $null
$script:PumpTick = 0
function Invoke-UiPump {
    param([int]$Every = 1)
    if (-not $script:UiPump) { return }
    $script:PumpTick++
    if (($script:PumpTick % $Every) -eq 0) { & $script:UiPump }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $pr = New-Object Security.Principal.WindowsPrincipal($id)
    return $pr.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


# ============================================================================
#  1. INFORMACOES DO SISTEMA
# ============================================================================
function Get-SystemOverview {
    Write-Step 'Coletando informacoes do sistema'
    $os   = Get-CimInstance Win32_OperatingSystem
    $cs   = Get-CimInstance Win32_ComputerSystem
    $bb   = Get-CimInstance Win32_BaseBoard
    $bios = Get-CimInstance Win32_BIOS
    $boot = $os.LastBootUpTime

    $adminTxt = 'NAO - cobertura reduzida'
    if (Test-IsAdmin) { $adminTxt = 'SIM' }

    $rows = @(
        [PSCustomObject]@{ Item='Hostname';            Valor=$env:COMPUTERNAME }
        [PSCustomObject]@{ Item='Usuario';             Valor=("{0}\{1}" -f $env:USERDOMAIN,$env:USERNAME) }
        [PSCustomObject]@{ Item='Sistema';             Valor=("{0} (build {1})" -f $os.Caption,$os.BuildNumber) }
        [PSCustomObject]@{ Item='Instalado em';        Valor=$os.InstallDate }
        [PSCustomObject]@{ Item='Ultimo boot';         Valor=$boot }
        [PSCustomObject]@{ Item='Uptime';              Valor=((Get-Date) - $boot).ToString('d\d\ hh\:mm\:ss') }
        [PSCustomObject]@{ Item='Fabricante / Modelo'; Valor=("{0} / {1}" -f $cs.Manufacturer,$cs.Model) }
        [PSCustomObject]@{ Item='Placa-mae';           Valor=("{0} {1} | SN: {2}" -f $bb.Manufacturer,$bb.Product,$bb.SerialNumber) }
        [PSCustomObject]@{ Item='BIOS';                Valor=("{0} | SN: {1}" -f $bios.SMBIOSBIOSVersion,$bios.SerialNumber) }
        [PSCustomObject]@{ Item='Fuso horario';        Valor=(Get-TimeZone).Id }
        [PSCustomObject]@{ Item='Rodando como Admin';  Valor=$adminTxt }
    )

    $instAge = ((Get-Date) - $os.InstallDate).TotalDays
    if ($instAge -lt 7) {
        Add-Finding 'ALTA' 'Windows instalado ha menos de 7 dias' ("Instalacao: {0} ({1:N1} dias). Formatacao recente e a forma mais comum de apagar rastros antes de um PC check." -f $os.InstallDate, $instAge)
    } elseif ($instAge -lt 30) {
        Add-Finding 'MEDIA' 'Windows instalado ha menos de 30 dias' ("Instalacao: {0} ({1:N1} dias)." -f $os.InstallDate, $instAge)
    }

    $vmHints = @('vmware','virtualbox','vbox','qemu','kvm','hyper-v','virtual machine','parallels','xen')
    $sig = ("{0} {1} {2}" -f $cs.Manufacturer,$cs.Model,$bios.SMBIOSBIOSVersion).ToLowerInvariant()
    foreach ($h in $vmHints) {
        if ($sig.Contains($h)) {
            Add-Finding 'ALTA' 'Maquina virtual detectada' ("Assinatura de hardware compativel com VM ('{0}'). Um PC check dentro de VM nao tem valor probatorio." -f $h)
            break
        }
    }

    Add-Section 'Sistema' $rows
}

# ============================================================================
#  2. PREFETCH
# ============================================================================
function Get-PrefetchArtifacts {
    Write-Step 'Analisando Prefetch'
    $pfDir = Join-Path $env:SystemRoot 'Prefetch'

    $pp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters' -ErrorAction SilentlyContinue
    if ($null -ne $pp -and $pp.EnablePrefetcher -eq 0) {
        Add-Finding 'ALTA' 'Prefetch desativado no registro' 'EnablePrefetcher = 0. O Prefetch e o principal registro de execucao de programas; desativa-lo e tecnica classica de anti-forense.'
    }

    if (-not (Test-Path $pfDir)) {
        Add-Section 'Prefetch (execucoes)' @() 'Pasta de Prefetch inacessivel (rode como Administrador).'
        return
    }

    $files = @(Get-ChildItem $pfDir -Filter *.pf -ErrorAction SilentlyContinue)
    if ($files.Count -eq 0) {
        # Sem Administrador a pasta existe mas nao pode ser lida: nao e o mesmo
        # que estar vazia, entao nao gera achado.
        if (Test-IsAdmin) {
            Add-Finding 'ALTA' 'Pasta Prefetch vazia' 'Nenhum arquivo .pf encontrado. Um Windows em uso normal tem centenas. Indica limpeza manual.'
            Add-Section 'Prefetch (execucoes)' @() 'Pasta vazia - forte indicio de limpeza.'
        } else {
            Add-Section 'Prefetch (execucoes)' @() 'Sem permissao de leitura. Rode como Administrador para avaliar este artefato.'
        }
        return
    }

    if ($files.Count -lt 40) {
        Add-Finding 'ALTA' ("Poucos arquivos de Prefetch ({0})" -f $files.Count) 'Um Windows usado no dia a dia costuma ter 100+ arquivos .pf. Volume baixo sugere limpeza recente.'
    }

    $oldest  = ($files | Sort-Object CreationTime | Select-Object -First 1).CreationTime
    $ageDays = ((Get-Date) - $oldest).TotalDays
    if ($ageDays -lt 3 -and $files.Count -gt 5) {
        Add-Finding 'ALTA' 'Todo o Prefetch foi criado recentemente' ("O .pf mais antigo e de {0} ({1:N1} dias). Sugere que a pasta foi apagada." -f $oldest, $ageDays)
    }

    $rows = foreach ($f in ($files | Sort-Object LastWriteTime -Descending)) {
        [PSCustomObject]@{
            Executavel  = ($f.BaseName -split '-')[0]
            UltimaExec  = $f.LastWriteTime
            PrimeiraVez = $f.CreationTime
            Arquivo     = $f.Name
            Suspeito    = (Test-Keyword $f.BaseName)
        }
    }

    foreach ($r in ($rows | Where-Object { $_.Suspeito })) {
        Add-Finding (Get-KeywordSeverity $r.Suspeito) ("Prefetch suspeito: {0}" -f $r.Executavel) ("Ultima execucao: {0} | Palavras-chave: {1}" -f $r.UltimaExec, $r.Suspeito)
    }

    Add-Section 'Prefetch (execucoes)' $rows ("{0} arquivos .pf. UltimaExec = ultima vez que o programa rodou." -f $files.Count)
}

# ============================================================================
#  3. BAM / DAM
# ============================================================================
function Get-BamArtifacts {
    Write-Step 'Lendo BAM/DAM (historico de execucao)'
    $roots = @(
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',
        'HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings',
        'HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings'
    )
    $rows = New-Object System.Collections.ArrayList

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($userKey in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            $sid = $userKey.PSChildName
            $account = $sid
            try { $account = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value } catch { }

            $props = Get-ItemProperty -Path $userKey.PSPath -ErrorAction SilentlyContinue
            if (-not $props) { continue }

            foreach ($p in $userKey.GetValueNames()) {
                if ($p -eq 'Version' -or $p -eq 'SequenceNumber') { continue }
                $data = $props.$p
                if ($data -isnot [byte[]] -or $data.Length -lt 8) { continue }
                $dt = ConvertTo-DateSafe ([BitConverter]::ToInt64($data, 0))
                if (-not $dt) { continue }

                $path = $p -replace '^\\Device\\HarddiskVolume\d+', 'C:'
                [void]$rows.Add([PSCustomObject]@{
                    Usuario    = $account
                    Executavel = (Split-Path $path -Leaf)
                    Caminho    = $path
                    UltimaExec = $dt
                    Suspeito   = (Test-Keyword $path)
                })
            }
        }
    }

    if ($rows.Count -eq 0) {
        Add-Section 'BAM (execucoes)' @() 'Sem dados (requer Administrador, ou chave inexistente nesta build do Windows).'
        return
    }

    foreach ($r in $rows) {
        if ($r.Suspeito) {
            Add-Finding (Get-KeywordSeverity $r.Suspeito) ("BAM suspeito: {0}" -f $r.Executavel) ("{0} | Ultima execucao: {1} | Palavras-chave: {2}" -f $r.Caminho, $r.UltimaExec, $r.Suspeito)
        } elseif ($r.Caminho -match '(?i)\\(temp|downloads)\\') {
            Add-Finding 'MEDIA' ("Executado de pasta temporaria: {0}" -f $r.Executavel) ("{0} | {1}" -f $r.Caminho, $r.UltimaExec)
        }
    }

    Add-Section 'BAM (execucoes)' ($rows | Sort-Object UltimaExec -Descending) 'O BAM guarda o caminho completo e a ultima execucao de cada binario, por usuario. E um dos artefatos mais confiaveis.'
}

# ============================================================================
#  4. USERASSIST
# ============================================================================
function Get-UserAssistArtifacts {
    Write-Step 'Lendo UserAssist'
    $base = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    $rows = New-Object System.Collections.ArrayList

    foreach ($guid in (Get-ChildItem $base -ErrorAction SilentlyContinue)) {
        $countPath = Join-Path $guid.PSPath 'Count'
        if (-not (Test-Path $countPath)) { continue }
        $key = Get-Item $countPath -ErrorAction SilentlyContinue
        if (-not $key) { continue }
        $props = Get-ItemProperty $countPath -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        foreach ($name in $key.GetValueNames()) {
            $decoded = ConvertFrom-Rot13 $name
            if ($decoded -notmatch '\.exe|\.lnk') { continue }
            $data = $props.$name
            if ($data -isnot [byte[]] -or $data.Length -lt 68) { continue }
            [void]$rows.Add([PSCustomObject]@{
                Item       = $decoded
                Execucoes  = [BitConverter]::ToInt32($data, 4)
                UltimaExec = (ConvertTo-DateSafe ([BitConverter]::ToInt64($data, 60)))
                Suspeito   = (Test-Keyword $decoded)
            })
        }
    }

    foreach ($r in ($rows | Where-Object { $_.Suspeito })) {
        Add-Finding (Get-KeywordSeverity $r.Suspeito) ("UserAssist suspeito: {0}" -f (Split-Path $r.Item -Leaf)) ("{0} | Execucoes: {1} | Ultima: {2} | Palavras-chave: {3}" -f $r.Item, $r.Execucoes, $r.UltimaExec, $r.Suspeito)
    }

    Add-Section 'UserAssist' ($rows | Sort-Object UltimaExec -Descending) 'Programas iniciados pela interface grafica, com contagem de execucoes.'
}

# ============================================================================
#  5. MUICACHE / MRU / CAMINHOS DIGITADOS
# ============================================================================
function Get-MuiCacheArtifacts {
    Write-Step 'Lendo MUICache, RunMRU e caminhos digitados'
    $rows = New-Object System.Collections.ArrayList

    $regSources = @(
        @{ Path='HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache'; Label='MUICache' },
        @{ Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU';                 Label='Executar (Win+R)' },
        @{ Path='HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths';             Label='Caminho digitado' }
    )

    foreach ($src in $regSources) {
        if (-not (Test-Path $src.Path)) { continue }
        $k = Get-Item $src.Path -ErrorAction SilentlyContinue
        if (-not $k) { continue }
        $p = Get-ItemProperty $src.Path -ErrorAction SilentlyContinue
        if (-not $p) { continue }

        foreach ($n in $k.GetValueNames()) {
            if ($n -eq 'MRUList') { continue }

            if ($src.Label -eq 'MUICache') {
                if ($n -notmatch '\.exe') { continue }
                $valor = $n -replace '\.FriendlyAppName|\.ApplicationCompany', ''
                $extra = [string]$p.$n
            } else {
                $valor = [string]$p.$n
                $extra = $n
            }
            if ([string]::IsNullOrWhiteSpace($valor)) { continue }

            [void]$rows.Add([PSCustomObject]@{
                Origem   = $src.Label
                Valor    = $valor
                Extra    = $extra
                Suspeito = (Test-Keyword ("{0} {1}" -f $valor, $extra))
            })
        }
    }

    foreach ($r in ($rows | Where-Object { $_.Suspeito })) {
        $nome = $r.Valor
        if ($nome -match '\\') { $nome = Split-Path $nome -Leaf }
        Add-Finding (Get-KeywordSeverity $r.Suspeito) ("{0}: {1}" -f $r.Origem, $nome) ("{0} | Palavras-chave: {1}" -f $r.Valor, $r.Suspeito)
    }

    Add-Section 'MUICache / MRU' $rows 'Caminhos de executaveis vistos pelo Explorer e comandos digitados na caixa Executar.'
}

# ============================================================================
#  6. ATALHOS RECENTES (.lnk)
# ============================================================================
function Get-RecentLnkArtifacts {
    Write-Step 'Analisando atalhos recentes (.lnk)'
    $recent = Join-Path $env:APPDATA 'Microsoft\Windows\Recent'
    $rows   = New-Object System.Collections.ArrayList
    $shell  = New-Object -ComObject WScript.Shell

    foreach ($lnk in (Get-ChildItem $recent -Filter *.lnk -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending)) {
        $target = ''
        try { $target = $shell.CreateShortcut($lnk.FullName).TargetPath } catch { }
        $sus = Test-Keyword ("{0} {1}" -f $lnk.BaseName, $target)
        $existe = 'sim'
        if ($target -and -not (Test-Path $target)) { $existe = 'NAO (apagado)' }

        [void]$rows.Add([PSCustomObject]@{
            Nome     = $lnk.BaseName
            Destino  = $target
            Acessado = $lnk.LastWriteTime
            Existe   = $existe
            Suspeito = $sus
        })
        if ($sus) {
            Add-Finding (Get-KeywordSeverity $sus) ("Atalho recente suspeito: {0}" -f $lnk.BaseName) ("Destino: {0} | Acessado: {1} | Palavras-chave: {2}" -f $target, $lnk.LastWriteTime, $sus)
        }
    }

    Add-Section 'Arquivos recentes (.lnk)' $rows 'Arquivos e programas abertos recentemente. Existe = NAO significa que o alvo foi apagado depois de ter sido usado.'
}

# ============================================================================
#  7. EVENT LOGS
# ============================================================================
function Get-EventLogArtifacts {
    Write-Step 'Verificando logs de eventos'
    $rows = New-Object System.Collections.ArrayList

    $cleared = @()
    $cleared += Get-WinEvent -FilterHashtable @{LogName='System';   Id=104}  -MaxEvents 30 -ErrorAction SilentlyContinue
    $cleared += Get-WinEvent -FilterHashtable @{LogName='Security'; Id=1102} -MaxEvents 30 -ErrorAction SilentlyContinue
    foreach ($e in $cleared) {
        $msg = ($e.Message -replace '\s+',' ')
        [void]$rows.Add([PSCustomObject]@{ Quando=$e.TimeCreated; Tipo='LOG APAGADO'; Detalhe=$msg; Suspeito='limpeza de log' })
        Add-Finding 'ALTA' 'Log de eventos apagado' ("{0} - {1}" -f $e.TimeCreated, $msg)
    }

    $det = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational'; Id=@(1006,1007,1015,1116,1117)} -MaxEvents 60 -ErrorAction SilentlyContinue
    foreach ($e in $det) {
        $msg = ($e.Message -replace '\s+',' ')
        # Nome da ameaca, quando presente na mensagem.
        $ameaca = ''
        if ($msg -match '(?i)(?:Name|Nome)\s*:\s*(\S+)') { $ameaca = $Matches[1] }
        $titulo = 'Deteccao do Windows Defender'
        if ($ameaca) { $titulo = ("Deteccao do Windows Defender: {0}" -f $ameaca) }

        [void]$rows.Add([PSCustomObject]@{ Quando=$e.TimeCreated; Tipo=("Defender {0}" -f $e.Id); Detalhe=$msg; Suspeito=(Test-KeywordStrong $msg) })
        $short = $msg
        if ($short.Length -gt 400) { $short = $short.Substring(0,400) }
        Add-Finding 'MEDIA' $titulo ("{0} - {1}" -f $e.TimeCreated, $short)
    }

    # Servicos/drivers instalados. A mensagem e longa, entao aqui so valem os
    # termos inequivocos e a lista de drivers abusados - senao gera muito ruido.
    $svc = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045} -MaxEvents 120 -ErrorAction SilentlyContinue
    foreach ($e in $svc) {
        $msg = ($e.Message -replace '\s+',' ')
        $sus = Test-KeywordStrong $msg
        if (-not $sus) {
            $low = $msg.ToLowerInvariant()
            foreach ($bd in $script:BadDrivers) {
                if ($low.Contains($bd)) { $sus = ("driver abusado: " + $bd); break }
            }
        }
        [void]$rows.Add([PSCustomObject]@{ Quando=$e.TimeCreated; Tipo='Servico/driver instalado'; Detalhe=$msg; Suspeito=$sus })
        if ($sus) {
            $short = $msg
            if ($short.Length -gt 200) { $short = $short.Substring(0,200) }
            Add-Finding 'ALTA' ("Servico/driver suspeito instalado ({0})" -f $sus) ("{0} - {1}" -f $e.TimeCreated, $short)
        }
    }

    Add-Section 'Eventos do Windows' ($rows | Sort-Object Quando -Descending) 'Apagamento de logs (ID 104/1102), deteccoes do Defender e instalacao de servicos/drivers (ID 7045).'
}

# ============================================================================
#  8. WINDOWS DEFENDER
# ============================================================================
function Get-DefenderArtifacts {
    Write-Step 'Verificando Windows Defender'
    $rows = New-Object System.Collections.ArrayList

    $pref = Get-MpPreference -ErrorAction SilentlyContinue
    $stat = Get-MpComputerStatus -ErrorAction SilentlyContinue

    if ($stat) {
        foreach ($p in @('RealTimeProtectionEnabled','AntivirusEnabled','IsTamperProtected','BehaviorMonitorEnabled','IoavProtectionEnabled')) {
            $v = $stat.$p
            $sus = ''
            if ($v -eq $false) { $sus = 'protecao desligada' }
            [void]$rows.Add([PSCustomObject]@{ Item=$p; Valor=[string]$v; Suspeito=$sus })
            if ($v -eq $false) {
                Add-Finding 'MEDIA' ("Defender: {0} desativado" -f $p) 'Protecao desligada. Comum em maquinas com cheat, mas tambem em quem usa outro antivirus.'
            }
        }
    }

    if ($pref) {
        $sets = @(
            @{ N='ExclusionPath';      V=$pref.ExclusionPath },
            @{ N='ExclusionProcess';   V=$pref.ExclusionProcess },
            @{ N='ExclusionExtension'; V=$pref.ExclusionExtension },
            @{ N='ExclusionIpAddress'; V=$pref.ExclusionIpAddress }
        )
        foreach ($set in $sets) {
            foreach ($item in @($set.V)) {
                $val = [string]$item
                if ([string]::IsNullOrWhiteSpace($val)) { continue }
                # Sem Administrador o cmdlet devolve o texto "N/A: Must be an
                # administrator to view exclusions" no lugar da lista real.
                if ($val -like 'N/A:*') {
                    [void]$rows.Add([PSCustomObject]@{ Item=$set.N; Valor='requer Administrador para listar'; Suspeito='' })
                    continue
                }
                $sus = Test-Keyword $val
                if (-not $sus) { $sus = 'exclusao manual' }
                [void]$rows.Add([PSCustomObject]@{ Item=$set.N; Valor=$val; Suspeito=$sus })
                Add-Finding 'ALTA' ("Exclusao no Defender: {0}" -f $val) 'Pastas ou processos excluidos do antivirus sao um dos indicios mais fortes: cheats pedem exclusao para nao serem removidos.'
            }
        }
    }

    $exRoot = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
    foreach ($sub in @('Paths','Processes','Extensions')) {
        $p2 = Join-Path $exRoot $sub
        if (-not (Test-Path $p2)) { continue }
        $k = Get-Item $p2 -ErrorAction SilentlyContinue
        if (-not $k) { continue }
        foreach ($n in $k.GetValueNames()) {
            [void]$rows.Add([PSCustomObject]@{ Item=("Registro/" + $sub); Valor=$n; Suspeito='exclusao manual' })
        }
    }

    if ($rows.Count -eq 0) {
        Add-Section 'Windows Defender' @() 'Sem dados (Defender ausente/substituido, ou falta de privilegio).'
    } else {
        Add-Section 'Windows Defender' $rows 'Estado da protecao e exclusoes configuradas.'
    }
}


# ============================================================================
#  9. INTEGRIDADE DO BOOT (test signing, DSE, debug)
# ============================================================================
function Get-BootIntegrity {
    Write-Step 'Verificando configuracao de boot / assinatura de drivers'
    $rows = New-Object System.Collections.ArrayList

    $bcd = (& bcdedit /enum '{current}' 2>$null) -join "`n"
    $flags = @(
        @{ N='testsigning';       D='Modo de teste de assinatura: permite carregar drivers nao assinados' },
        @{ N='nointegritychecks'; D='Verificacao de integridade de drivers desligada' },
        @{ N='debug';             D='Depuracao de kernel ativa' },
        @{ N='bootdebug';         D='Depuracao de boot ativa' },
        @{ N='flightsigning';     D='Assinatura de flight habilitada' }
    )
    foreach ($flag in $flags) {
        $pattern = "(?im)^\s*" + $flag.N + "\s+(Yes|Sim)"
        if ($bcd -match $pattern) {
            [void]$rows.Add([PSCustomObject]@{ Item=$flag.N; Valor='Yes'; Suspeito=$flag.D })
            Add-Finding 'ALTA' ("Boot: {0} ativado" -f $flag.N) $flag.D
        } else {
            [void]$rows.Add([PSCustomObject]@{ Item=$flag.N; Valor='No'; Suspeito='' })
        }
    }

    Add-Section 'Integridade do boot' $rows 'Flags do BCD que permitem carregar drivers nao assinados.'
}

# ============================================================================
#  9b. POSTURA DE SEGURANCA DO KERNEL (protecoes contra cheats de driver)
# ============================================================================
function Get-SecurityPostureArtifacts {
    Write-Step 'Verificando protecoes de kernel (HVCI, Secure Boot, blocklist, TPM)'
    $rows = New-Object System.Collections.ArrayList

    # --- Secure Boot / Inicializacao Segura ---
    $sb = 'indisponivel'
    try { $sb = [string](Confirm-SecureBootUEFI) } catch { $sb = 'indisponivel (BIOS legacy ou sem privilegio)' }
    $susSb = ''
    if ($sb -eq 'False') {
        $susSb = 'Secure Boot DESATIVADO'
        Add-Finding 'MEDIA' 'Secure Boot desativado' 'O arranque seguro impede componentes/drivers nao assinados no boot. Desligado facilita cheats de kernel.'
    }
    [void]$rows.Add([PSCustomObject]@{ Item='Secure Boot (Inicializacao Segura)'; Valor=$sb; Suspeito=$susSb })

    # --- Isolamento de Nucleo / Integridade de Memoria (HVCI) e VBS ---
    $dg = $null
    try { $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop } catch { }
    $hvciRun = $false; $vbsRun = $false
    if ($dg) {
        $hvciRun = @($dg.SecurityServicesRunning) -contains 2
        $vbsRun  = ($dg.VirtualizationBasedSecurityStatus -eq 2)
    }
    # confirma tambem pela configuracao no registo
    $hvciCfg = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -ErrorAction SilentlyContinue
    $hvciEnabledCfg = ($null -ne $hvciCfg -and $hvciCfg.Enabled -eq 1)

    $hvciVal = $(if ($hvciRun) { 'ATIVO' } elseif ($hvciEnabledCfg) { 'configurado mas nao ativo' } else { 'DESATIVADO' })
    $susHvci = ''
    if (-not $hvciRun) {
        $susHvci = 'Isolamento de Nucleo / Integridade de Memoria desligado'
        Add-Finding 'MEDIA' 'Isolamento de Nucleo (HVCI) desativado' 'A Integridade de Memoria bloqueia drivers maliciosos no kernel. Desligada e requisito para muitos cheats de driver. (Nota: vem desligada por defeito em muitos PCs.)'
    }
    [void]$rows.Add([PSCustomObject]@{ Item='Isolamento de Nucleo / HVCI'; Valor=$hvciVal; Suspeito=$susHvci })
    [void]$rows.Add([PSCustomObject]@{ Item='VBS (Seguranca baseada em virtualizacao)'; Valor=$(if ($vbsRun) { 'ATIVO' } else { 'inativo' }); Suspeito='' })

    # --- Lista de bloqueio de drivers vulneraveis (BYOVD) - NAO pode estar off ---
    $ci = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -ErrorAction SilentlyContinue
    if ($null -ne $ci -and $null -ne $ci.VulnerableDriverBlocklistEnable) {
        if ($ci.VulnerableDriverBlocklistEnable -eq 0) {
            [void]$rows.Add([PSCustomObject]@{ Item='Blocklist de drivers vulneraveis'; Valor='0 (DESATIVADA)'; Suspeito='NAO pode estar desativada' })
            Add-Finding 'ALTA' 'Blocklist de drivers vulneraveis DESATIVADA' 'Esta lista bloqueia drivers legitimos mas abusados (BYOVD). Desliga-la e passo tipico para carregar cheats de kernel. Nao deveria estar desativada.'
        } else {
            [void]$rows.Add([PSCustomObject]@{ Item='Blocklist de drivers vulneraveis'; Valor='1 (ativa)'; Suspeito='' })
        }
    } else {
        # Em Win11 recente vem ativa por defeito mesmo sem a chave.
        [void]$rows.Add([PSCustomObject]@{ Item='Blocklist de drivers vulneraveis'; Valor='padrao do sistema (chave ausente)'; Suspeito='' })
    }

    # --- TPM ---
    $tpm = $null
    try { $tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop } catch { }
    if ($tpm) {
        $tpmOn = ($tpm.IsEnabled_InitialValue -eq $true) -and ($tpm.IsActivated_InitialValue -eq $true)
        $tpmVal = $(if ($tpmOn) { 'presente e ativo' } else { 'presente mas inativo/desligado' })
        $susTpm = ''
        if (-not $tpmOn) { $susTpm = 'TPM presente mas nao ativo' ; Add-Finding 'BAIXA' 'TPM presente mas inativo' 'O TPM ajuda no arranque seguro. Inativo nao prova nada, mas faz parte da postura de seguranca.' }
        [void]$rows.Add([PSCustomObject]@{ Item='TPM'; Valor=$tpmVal; Suspeito=$susTpm })
    } else {
        [void]$rows.Add([PSCustomObject]@{ Item='TPM'; Valor='nao detetado (ou sem privilegio)'; Suspeito='' })
    }

    Add-Section 'Seguranca do kernel (HVCI / Secure Boot / TPM)' $rows 'Protecoes que os cheats de driver (DMA, mapeamento manual, BYOVD) precisam de ter desligadas. Muitas vem desligadas por defeito em PCs normais - avalie no conjunto.'
}

# ============================================================================
#  10. DRIVERS
# ============================================================================
function Get-DriverArtifacts {
    Write-Step 'Analisando drivers'
    $rows   = New-Object System.Collections.ArrayList
    $drvDir = Join-Path $env:SystemRoot 'System32\drivers'
    $cut    = (Get-Date).AddDays(-60)

    foreach ($f in (Get-ChildItem $drvDir -Filter *.sys -ErrorAction SilentlyContinue)) {
        $name = $f.Name.ToLowerInvariant()
        $sus  = ''
        if ($script:BadDrivers -contains $name) { $sus = 'driver frequentemente abusado (BYOVD)' }
        if ($script:NetDrivers -contains $name) { $sus = ("{0} driver de manipulacao de rede (lag switch)" -f $sus).Trim() }
        $kw = Test-KeywordStrong $f.BaseName
        if ($kw) { $sus = ("{0} {1}" -f $sus, $kw).Trim() }

        $recent = ($f.CreationTime -gt $cut)
        if (-not $sus -and -not $recent) { continue }

        $sigStatus = 'nao verificado'
        if (-not $Quick) {
            Invoke-UiPump
            try { $sigStatus = (Get-AuthenticodeSignature -LiteralPath $f.FullName).Status.ToString() } catch { }
            if ($sigStatus -ne 'Valid' -and $sigStatus -ne 'nao verificado' -and -not $sus) {
                $sus = ("assinatura: " + $sigStatus)
            }
        }

        [void]$rows.Add([PSCustomObject]@{
            Driver   = $f.Name
            Criado   = $f.CreationTime
            Assinado = $sigStatus
            Suspeito = $sus
        })

        if ($script:BadDrivers -contains $name) {
            Add-Finding 'ALTA' ("Driver abusado por cheats presente: {0}" -f $f.Name) ("Criado em {0}. Esse driver e usado para carregar codigo nao assinado no kernel (tecnica BYOVD)." -f $f.CreationTime)
        }
        if ($script:NetDrivers -contains $name) {
            Add-Finding 'ALTA' ("Driver de lag switch presente: {0}" -f $f.Name) ("Criado em {0}. Driver de manipulacao de pacotes (ex.: clumsy/NetLimiter usam WinDivert) - permite criar lag/desync de proposito." -f $f.CreationTime)
        }
    }

    foreach ($d in (Get-CimInstance Win32_SystemDriver -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' })) {
        $path = $d.PathName -replace '^\\\?\?\\',''
        if ($path -match '(?i)\\(temp|appdata|downloads|users)\\') {
            [void]$rows.Add([PSCustomObject]@{
                Driver=$d.Name; Criado=''; Assinado=''; Suspeito=("carregado de caminho incomum: " + $path)
            })
            Add-Finding 'ALTA' ("Driver carregado de caminho incomum: {0}" -f $d.Name) $path
        }
    }

    Add-Section 'Drivers' $rows 'Drivers criados nos ultimos 60 dias, drivers conhecidos por serem abusados e drivers em caminhos incomuns.'
}

# ============================================================================
#  11. PROCESSOS EM EXECUCAO
# ============================================================================
function Get-ProcessArtifacts {
    Write-Step 'Analisando processos em execucao'
    $rows = New-Object System.Collections.ArrayList

    # Tetos para este modulo nunca bloquear a aplicacao.
    $sw           = [System.Diagnostics.Stopwatch]::StartNew()
    $budgetSeg    = 20     # segundos no maximo a verificar assinaturas
    $maxSigChecks = 40     # no maximo 40 binarios verificados
    $sigChecks    = 0

    foreach ($p in (Get-CimInstance Win32_Process -ErrorAction SilentlyContinue)) {
        $path = $p.ExecutablePath
        $kw   = Test-Keyword ("{0} {1}" -f $p.Name, $path)
        $sus  = $kw

        if (-not $sus -and $path -and ($path -match '(?i)(\\appdata\\local\\temp\\|\\temp\\|\\downloads\\|\\programdata\\temp\\)')) {
            $sus = 'executando de pasta temporaria'
        }

        # Mantem a janela a responder (modo GUI); no-op em consola.
        Invoke-UiPump

        # Verificacao de assinatura e CARA (pode consultar revogacao na rede).
        # So a fazemos onde interessa: binarios FORA de Windows/Program Files,
        # que nao estao na whitelist - e com um teto de tempo para nunca travar.
        $sig = ''
        $valeAPena = $path -and
                     ($path -notmatch '(?i)^[A-Z]:\\Windows\\') -and
                     ($path -notmatch '(?i)^[A-Z]:\\Program Files') -and
                     (-not (Test-BenignFile $p.Name))

        if (-not $Quick -and $valeAPena -and ($sigChecks -lt $maxSigChecks) -and ($sw.Elapsed.TotalSeconds -lt $budgetSeg)) {
            if (Test-Path -LiteralPath $path) {
                $sigChecks++
                try {
                    $s   = Get-AuthenticodeSignature -LiteralPath $path
                    $sig = $s.Status.ToString()
                    if ($s.SignerCertificate) { $sig = ("{0} / {1}" -f $sig, $s.SignerCertificate.Subject.Split(',')[0]) }
                    if ($s.Status -ne 'Valid' -and -not $sus) {
                        $sus = 'binario sem assinatura digital valida'
                    }
                } catch { }
            }
        }

        if (-not $sus) { continue }

        [void]$rows.Add([PSCustomObject]@{
            Processo   = $p.Name
            PID        = $p.ProcessId
            Caminho    = $path
            Iniciado   = $p.CreationDate
            Assinatura = $sig
            Suspeito   = $sus
        })

        $sev = 'MEDIA'
        if ($kw) { $sev = Get-KeywordSeverity $kw }
        Add-Finding $sev ("Processo suspeito: {0} (PID {1})" -f $p.Name, $p.ProcessId) ("{0} | {1}" -f $path, $sus)
    }

    Add-Section 'Processos suspeitos' $rows 'Apenas processos que bateram em alguma regra. Binarios sem assinatura fora de C:\Windows sao comuns em jogos e utilitarios: avalie com bom senso.'
}

# ============================================================================
#  12. ARTEFATOS ESPECIFICOS DO FIVEM
# ============================================================================
function Get-ProcessStateArtifacts {
    Write-Step 'Verificando processos suspensos e apps abertas'
    $rows = New-Object System.Collections.ArrayList

    # ---- Processos SUSPENSOS (congelados) --------------------------------
    # Um cheat pode ser suspenso para ficar dormente durante o check. Apps da
    # Microsoft Store (WindowsApps) suspendem-se sozinhas quando minimizadas -
    # isso e normal e nao e sinalizado.
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        Invoke-UiPump -Every 40
        $threads = $null
        try { $threads = $p.Threads } catch { continue }
        if (-not $threads -or $threads.Count -eq 0) { continue }

        $tot = 0; $susp = 0
        foreach ($t in $threads) {
            $tot++
            try { if ($t.ThreadState -eq 'Wait' -and $t.WaitReason -eq 'Suspended') { $susp++ } } catch { }
        }
        if ($tot -eq 0 -or $susp -ne $tot) { continue }   # so interessa 100% suspenso

        $path = ''
        try { $path = $p.Path } catch { }
        $kw = Test-Keyword ("{0} {1}" -f $p.Name, $path)
        $benigno = ([string]::IsNullOrEmpty($path)) -or
                   ($path -match '(?i)\\WindowsApps\\') -or
                   ($path -match '(?i)\\SystemApps\\') -or
                   ($path -match '(?i)^[A-Z]:\\Windows\\')

        $flag = ''
        if ($kw) { $flag = "suspenso + palavra-chave: $kw" }
        elseif (-not $benigno) { $flag = 'processo suspenso (congelado)' }

        [void]$rows.Add([PSCustomObject]@{
            Item     = ("Suspenso: {0} (PID {1})" -f $p.Name, $p.Id)
            Detalhe  = $(if ($path) { $path } else { '(caminho oculto)' })
            Suspeito = $flag
        })
        if ($flag) {
            $sev = 'MEDIA'
            if ($kw) { $sev = Get-KeywordSeverity $kw }
            Add-Finding $sev ("Processo suspenso/congelado: {0}" -f $p.Name) ("{0} | um processo totalmente congelado pode ser um cheat a esconder-se durante o check." -f $path)
        }
    }

    # ---- Estado das apps comuns (aberta / fechada) -----------------------
    # Apenas informativo: ajuda a ver se o jogador fechou tudo antes do check.
    $apps = [ordered]@{
        'FiveM / FiveM_GTAProcess' = @('FiveM','FiveM_GTAProcess','FiveM_b*','CitizenFX')
        'GTA V'                    = @('GTA5','GTA5_Enhanced','PlayGTAV')
        'Steam'                    = @('steam')
        'Rockstar Launcher'        = @('Launcher','RockstarService','SocialClubHelper')
        'Discord'                  = @('Discord','DiscordPTB','DiscordCanary')
        'Navegador'                = @('chrome','msedge','firefox','brave','opera')
    }
    foreach ($nome in $apps.Keys) {
        $aberto = $false
        foreach ($pat in $apps[$nome]) {
            if (@(Get-Process -Name $pat -ErrorAction SilentlyContinue).Count -gt 0) { $aberto = $true; break }
        }
        [void]$rows.Add([PSCustomObject]@{
            Item     = $nome
            Detalhe  = $(if ($aberto) { 'ABERTA' } else { 'fechada' })
            Suspeito = ''
        })
    }

    Add-Section 'Processos: suspensos e apps' $rows 'Processos congelados (possivel cheat dormente) e se as apps comuns estao abertas. O estado das apps e so informativo.'
}

function Get-LoadedModuleArtifacts {
    Write-Step 'Analisando DLLs carregadas nos processos (injecao)'
    $rows = New-Object System.Collections.ArrayList

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $budget = 30; $sigChecks = 0; $maxSig = 80

    # Processos do jogo: uma DLL estranha AQUI dentro e o sinal mais forte de injecao.
    $gameNames = @('fivem','fivem_gtaprocess','fivem_b1','fivem_b2699','fivem_b2802',
                   'gta5','gta5_enhanced','playgtav','redm','redm_gtaprocess','cfx')
    $userWritable = '(?i)(\\appdata\\local\\temp\\|\\temp\\|\\downloads\\|\$recycle|\\users\\public\\|\\programdata\\temp\\|\\appdata\\roaming\\)'

    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        Invoke-UiPump -Every 20
        if ($sw.Elapsed.TotalSeconds -ge $budget) { break }

        $mods = $null
        try { $mods = $p.Modules } catch { continue }
        if (-not $mods) { continue }
        $isGame = $gameNames -contains $p.Name.ToLowerInvariant()

        foreach ($m in $mods) {
            $mp = $null
            try { $mp = $m.FileName } catch { }
            if ([string]::IsNullOrEmpty($mp)) { continue }
            $low = $mp.ToLowerInvariant()

            $kw     = Test-Keyword $m.ModuleName
            $inTemp = ($low -match $userWritable)
            $outsideSystem = ($low -notmatch '(?i)\\windows\\') -and ($low -notmatch '(?i)\\program files')

            $flag = ''
            if ($kw)          { $flag = ("modulo: " + $kw) }
            elseif ($inTemp)  { $flag = 'DLL carregada de pasta temporaria/utilizador' }
            elseif ($isGame -and $outsideSystem -and -not $Quick -and $sigChecks -lt $maxSig) {
                # DLL no processo do JOGO, fora das pastas do sistema -> verifica assinatura.
                $sigChecks++
                try {
                    $st = (Get-AuthenticodeSignature -LiteralPath $mp).Status
                    if ($st -ne 'Valid') { $flag = 'DLL sem assinatura valida carregada no jogo' }
                } catch { }
            }
            if (-not $flag) { continue }

            [void]$rows.Add([PSCustomObject]@{
                Processo = ("{0} (PID {1})" -f $p.Name, $p.Id)
                Modulo   = $m.ModuleName
                Caminho  = $mp
                Suspeito = $flag
            })
            $sev = 'MEDIA'
            if ($kw)          { $sev = Get-KeywordSeverity $kw }
            elseif ($isGame)  { $sev = 'ALTA' }   # DLL injetada no jogo pesa mais
            Add-Finding $sev ("DLL suspeita em {0}: {1}" -f $p.Name, $m.ModuleName) ("{0} | {1}" -f $mp, $flag)
        }
    }

    Add-Section 'DLLs carregadas (injecao)' $rows 'Modulos (DLL) carregados dentro dos processos. Uma DLL vinda do Temp/AppData/Downloads, com nome de cheat, ou sem assinatura DENTRO do FiveM/GTA, e sinal de cheat injetado.'
}

function Get-ServiceStateArtifacts {
    Write-Step 'Verificando servicos parados/desativados'
    $rows = New-Object System.Collections.ArrayList

    # Servicos relevantes para o proprio PC check. Se estiverem parados ou
    # desativados, artefactos deixam de ser gravados (anti-forense).
    $alvos = @(
        @{ N='EventLog'; D='Registo de Eventos do Windows'; Sev='ALTA';  Nota='sem isto nao ha logs de eventos' },
        @{ N='SysMain';  D='SysMain/Superfetch (alimenta o Prefetch)'; Sev='MEDIA'; Nota='Prefetch deixa de registar execucoes' },
        @{ N='bam';      D='Background Activity Moderator (alimenta o BAM)'; Sev='ALTA'; Nota='BAM deixa de registar execucoes' },
        @{ N='PcaSvc';   D='Assistente de Compatibilidade (regista execucoes)'; Sev='MEDIA'; Nota='menos registo de programas abertos' },
        @{ N='DPS';      D='Servico de Politica de Diagnostico'; Sev='MEDIA'; Nota='afeta varios registos de diagnostico' },
        @{ N='WinDefend';D='Antivirus do Windows Defender'; Sev='MEDIA'; Nota='pode ser normal se usa outro antivirus' },
        @{ N='DiagTrack';D='Telemetria (Experiencias do Utilizador)'; Sev='BAIXA'; Nota='muita gente desliga isto de proposito' }
    )

    foreach ($a in $alvos) {
        $svc = Get-Service -Name $a.N -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        $startType = ''
        try { $startType = [string](Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $a.N) -ErrorAction SilentlyContinue).StartMode } catch { }

        $status = [string]$svc.Status
        $parado = ($status -ne 'Running')
        $desativado = ($startType -match '(?i)disabled')

        $flag = ''
        if ($desativado) { $flag = ("DESATIVADO - {0}" -f $a.Nota) }
        elseif ($parado) { $flag = ("parado - {0}" -f $a.Nota) }

        [void]$rows.Add([PSCustomObject]@{
            Servico  = ("{0} ({1})" -f $a.D, $a.N)
            Estado   = $status
            Arranque = $(if ($startType) { $startType } else { '?' })
            Suspeito = $flag
        })
        if ($flag) {
            $sev = $a.Sev
            if ($desativado -and $sev -eq 'MEDIA') { $sev = 'ALTA' }   # desativar e mais grave que so parar
            Add-Finding $sev ("Servico {0}: {1}" -f $a.N, $(if ($desativado) { 'DESATIVADO' } else { 'parado' })) ("{0}. {1}." -f $a.D, $a.Nota)
        }
    }

    Add-Section 'Servicos (parados/desativados)' $rows 'Servicos que alimentam os artefactos deste relatorio. Parados ou desativados podem indicar tentativa de nao deixar rasto.'
}

function Get-FiveMArtifacts {
    Write-Step 'Analisando instalacao do FiveM'
    $rows = New-Object System.Collections.ArrayList

    $roots = @(
        (Join-Path $env:LOCALAPPDATA 'FiveM'),
        (Join-Path $env:LOCALAPPDATA 'RedM'),
        'C:\FiveM',
        'C:\Users\Public\FiveM'
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    if ($roots.Count -eq 0) {
        Add-Section 'FiveM' @() 'Nenhuma instalacao do FiveM encontrada nos caminhos padrao.'
        return
    }

    $proxyNames = @('dinput8.dll','version.dll','xinput1_3.dll','xinput1_4.dll','winmm.dll',
                    'd3d9.dll','d3d11.dll','dxgi.dll','dsound.dll','msacm32.dll','wininet.dll')

    foreach ($root in $roots) {
        [void]$rows.Add([PSCustomObject]@{ Item='Instalacao'; Detalhe=$root; Suspeito='' })
        $app = Join-Path $root 'FiveM.app'

        foreach ($dll in (Get-ChildItem -LiteralPath $root -Filter *.dll -Recurse -Depth 2 -File -ErrorAction SilentlyContinue)) {
            $isProxy = $proxyNames -contains $dll.Name.ToLowerInvariant()
            $kw = Test-Keyword $dll.Name
            if (-not $isProxy -and -not $kw) { continue }

            # ReShade e um mod VISUAL legitimo que usa uma DLL grafica de proxy
            # (dxgi/d3d9-12/opengl32) ao lado de reshade.ini / reshade.log.
            # Prova = produto embutido na DLL. O reshade.ini vizinho so serve de
            # confirmacao para as DLLs graficas - assim um injetor escondido com
            # outro nome (dinput8.dll, winmm.dll...) na mesma pasta NAO passa.
            $lowName = $dll.Name.ToLowerInvariant()
            $reshadeProxyNames = @('dxgi.dll','d3d9.dll','d3d10.dll','d3d11.dll','d3d12.dll','opengl32.dll')
            $isReshade = $false
            try {
                $prod = (Get-Item $dll.FullName).VersionInfo.ProductName
                if ($prod -match '(?i)reshade') { $isReshade = $true }
            } catch { }
            if (-not $isReshade -and ($reshadeProxyNames -contains $lowName)) {
                $dir = Split-Path $dll.FullName -Parent
                if ((Test-Path (Join-Path $dir 'reshade.ini')) -or `
                    (Test-Path (Join-Path $dir 'reshade.log')) -or `
                    (Test-Path (Join-Path $dir 'reshade-shaders'))) { $isReshade = $true }
            }

            if ($isReshade -and -not $kw) {
                [void]$rows.Add([PSCustomObject]@{
                    Item     = $dll.FullName
                    Detalhe  = ("{0} KB | modificado {1}" -f [int]($dll.Length/1KB), $dll.LastWriteTime)
                    Suspeito = 'ReShade (mod visual) - normalmente legitimo'
                })
                Add-Finding 'BAIXA' ("ReShade detectado: {0}" -f $dll.Name) ("Mod visual comum, nao e cheat por si so. So investigue se vier com addons estranhos. {0}" -f $dll.FullName)
                continue
            }

            $sus = ''
            if ($isProxy) { $sus = 'DLL de proxy tipica de injecao' }
            if ($kw)      { $sus = ("{0} {1}" -f $sus, $kw).Trim() }
            [void]$rows.Add([PSCustomObject]@{
                Item     = $dll.FullName
                Detalhe  = ("{0} KB | modificado {1}" -f [int]($dll.Length/1KB), $dll.LastWriteTime)
                Suspeito = $sus
            })
            $sev = 'ALTA'
            if ($isProxy -and -not $kw) { $sev = 'MEDIA' }   # proxy sem palavra-chave: suspeita, nao certeza
            Add-Finding $sev ("DLL de proxy/injecao na pasta do FiveM: {0}" -f $dll.Name) ("{0} | modificado em {1}" -f $dll.FullName, $dll.LastWriteTime)
        }

        $plug = Join-Path $app 'plugins'
        if (Test-Path $plug) {
            foreach ($f in (Get-ChildItem -LiteralPath $plug -File -ErrorAction SilentlyContinue)) {
                $ext = $f.Extension.ToLowerInvariant()
                $kw  = Test-Keyword $f.Name

                if ($kw) {
                    # Nome bate em termo de cheat: sinaliza conforme a forca do termo.
                    [void]$rows.Add([PSCustomObject]@{
                        Item=$f.FullName; Detalhe=("modificado " + $f.LastWriteTime); Suspeito=("plugin: " + $kw)
                    })
                    Add-Finding (Get-KeywordSeverity $kw) ("Plugin suspeito do FiveM: {0}" -f $f.Name) $f.FullName
                }
                elseif ($script:PluginModuleExt -contains $ext) {
                    # Modulo carregavel (.dll/.asi/.lua): a pasta plugins e vetor real,
                    # mas modulos podem ser legitimos. MEDIA para revisao manual.
                    [void]$rows.Add([PSCustomObject]@{
                        Item=$f.FullName; Detalhe=("modificado " + $f.LastWriteTime); Suspeito='modulo carregado pelo FiveM (verificar)'
                    })
                    Add-Finding 'MEDIA' ("Modulo na pasta plugins do FiveM: {0}" -f $f.Name) $f.FullName
                }
                else {
                    # Screenshot, txt, ini e afins: apenas lista, sem sinalizar.
                    [void]$rows.Add([PSCustomObject]@{
                        Item=$f.FullName; Detalhe=("modificado " + $f.LastWriteTime); Suspeito=''
                    })
                }
            }
        }

        $logDir = Join-Path $app 'logs'
        if (Test-Path $logDir) {
            foreach ($log in (Get-ChildItem -LiteralPath $logDir -Filter *.log -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 6)) {
                if ($log.Length -gt 60MB) { continue }
                $content = Get-Content -LiteralPath $log.FullName -Raw -ErrorAction SilentlyContinue
                $kw = Test-KeywordStrong $content
                if (-not $kw) { continue }
                [void]$rows.Add([PSCustomObject]@{
                    Item=$log.Name; Detalhe=[string]$log.LastWriteTime; Suspeito=("log contem: " + $kw)
                })
                Add-Finding 'ALTA' ("Log do FiveM com termos suspeitos: {0}" -f $log.Name) ("Palavras-chave: {0} | {1}" -f $kw, $log.FullName)
            }
        }

        $crash = Join-Path $app 'crashes'
        if (Test-Path $crash) {
            $n = @(Get-ChildItem -LiteralPath $crash -ErrorAction SilentlyContinue).Count
            [void]$rows.Add([PSCustomObject]@{ Item='Crash dumps'; Detalhe=("{0} arquivos em {1}" -f $n, $crash); Suspeito='' })
        }
    }

    Add-Section 'FiveM' $rows 'DLLs de proxy, plugins e logs do CitizenFX. ReShade (mod visual) e listado como BAIXA; screenshots e arquivos comuns na pasta plugins nao sao sinalizados.'
}

# ============================================================================
#  13. DOWNLOADS, LIXEIRA E HISTORICO DE NAVEGADOR
# ============================================================================
function Get-DownloadArtifacts {
    Write-Step 'Analisando downloads, lixeira e navegadores'
    $rows = New-Object System.Collections.ArrayList

    $exts = @('.exe','.dll','.sys','.zip','.rar','.7z','.msi','.bat','.cmd','.ps1','.lua','.asi','.iso','.torrent')
    $dirs = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents'),
        (Join-Path $env:USERPROFILE 'Videos'),
        $env:TEMP
    )
    # inclui discos externos / pen / 2o disco (raiz completa)
    $dirs += (Get-ExtraDriveRoots)
    $dirs = $dirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    $depth = 3
    if ($Quick) { $depth = 1 }
    $scanned = 0
    $maxScan = 60000

    foreach ($d in $dirs) {
        if ($scanned -ge $maxScan) { break }
        foreach ($f in (Get-ChildItem -LiteralPath $d -Recurse -Depth $depth -File -Force -ErrorAction SilentlyContinue)) {
            $scanned++
            if ($scanned -ge $maxScan) { break }
            Invoke-UiPump -Every 200      # mantem a janela viva sem custar desempenho
            if ($exts -notcontains $f.Extension.ToLowerInvariant()) { continue }
            $kw = Test-Keyword $f.Name
            if (-not $kw) { continue }
            [void]$rows.Add([PSCustomObject]@{
                Origem='Arquivo'; Valor=$f.FullName; Quando=$f.LastWriteTime; Suspeito=$kw
            })
            Add-Finding (Get-KeywordSeverity $kw) ("Arquivo com nome suspeito: {0}" -f $f.Name) ("{0} | modificado {1} | palavras-chave: {2}" -f $f.FullName, $f.LastWriteTime, $kw)
        }
    }

    foreach ($bin in (Get-ChildItem 'C:\$Recycle.Bin' -Force -Directory -ErrorAction SilentlyContinue)) {
        foreach ($i in (Get-ChildItem -LiteralPath $bin.FullName -Force -Filter '$I*' -File -ErrorAction SilentlyContinue)) {
            $name = ''
            try {
                $bytes = [IO.File]::ReadAllBytes($i.FullName)
                if ($bytes.Length -lt 30) { continue }
                $offset = 24
                if ($bytes[0] -eq 2) { $offset = 28 }
                $name = [Text.Encoding]::Unicode.GetString($bytes, $offset, $bytes.Length - $offset).Trim([char]0)
            } catch { continue }
            $kw = Test-Keyword $name
            if (-not $kw) { continue }
            [void]$rows.Add([PSCustomObject]@{
                Origem='Lixeira'; Valor=$name; Quando=$i.LastWriteTime; Suspeito=$kw
            })
            Add-Finding (Get-KeywordSeverity $kw) 'Arquivo suspeito na lixeira' ("{0} | apagado em {1} | palavras-chave: {2}" -f $name, $i.LastWriteTime, $kw)
        }
    }

    $histFiles = New-Object System.Collections.ArrayList
    $browserRoots = @(
        (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data'),
        (Join-Path $env:LOCALAPPDATA 'BraveSoftware\Brave-Browser\User Data'),
        (Join-Path $env:APPDATA      'Opera Software\Opera Stable')
    )
    foreach ($h in $browserRoots) {
        if (-not (Test-Path $h)) { continue }
        foreach ($db in (Get-ChildItem -LiteralPath $h -Recurse -Depth 2 -Filter 'History' -File -ErrorAction SilentlyContinue)) {
            [void]$histFiles.Add($db.FullName)
        }
    }
    foreach ($p in (Get-ChildItem (Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles') -Directory -ErrorAction SilentlyContinue)) {
        $pl = Join-Path $p.FullName 'places.sqlite'
        if (Test-Path $pl) { [void]$histFiles.Add($pl) }
    }

    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $tmpDir = Join-Path $env:TEMP ('pccheck_' + [Guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    foreach ($h in ($histFiles | Select-Object -Unique)) {
        try { if ((Get-Item -LiteralPath $h).Length -gt 250MB) { continue } } catch { continue }
        $copy = Join-Path $tmpDir ([Guid]::NewGuid().ToString('N') + '.db')
        try { Copy-Item -LiteralPath $h -Destination $copy -Force -ErrorAction Stop } catch { continue }

        $text = ''
        try { $text = $latin1.GetString([IO.File]::ReadAllBytes($copy)) } catch { continue }

        $browser = Split-Path (Split-Path $h -Parent) -Leaf
        $seen    = @{}
        $urlHits = New-Object System.Collections.ArrayList

        foreach ($m in [regex]::Matches($text, 'https?://[\x21-\x7E]{6,200}')) {
            $u = $m.Value
            # A extracao bruta do SQLite gruda registros vizinhos. Corta na
            # segunda URL quando duas ficaram concatenadas.
            $idx = $u.IndexOf('http', 5)
            if ($idx -gt 0) { $u = $u.Substring(0, $idx) }
            if ($u.Length -gt 160) { $u = $u.Substring(0, 160) }
            if ($seen.ContainsKey($u)) { continue }
            $seen[$u] = $true
            # Somente termos inequivocos: o historico tem milhares de URLs e os
            # termos ambiguos ("hack", "crack") geram dezenas de falsos positivos.
            $kw = Test-KeywordStrong $u
            # Alem dos termos, casa a lista de dominios de venda/forum de cheat.
            if (-not $kw) {
                $ulow = $u.ToLowerInvariant()
                foreach ($dom in $script:CheatDomains) {
                    if ($ulow.Contains($dom)) { $kw = ("dominio de cheat: " + $dom); break }
                }
            }
            if (-not $kw) { continue }
            [void]$rows.Add([PSCustomObject]@{
                Origem=('Navegador: ' + $browser); Valor=$u; Quando=''; Suspeito=$kw
            })
            [void]$urlHits.Add($u)
        }

        # Um unico achado por navegador, com amostra - em vez de um por URL.
        if ($urlHits.Count -gt 0) {
            $amostra = ($urlHits | Select-Object -First 8) -join ' ; '
            $extra = ''
            if ($urlHits.Count -gt 8) { $extra = (" (+{0} outras, veja a tabela)" -f ($urlHits.Count - 8)) }
            Add-Finding 'MEDIA' ("{0} URL(s) suspeita(s) no historico ({1})" -f $urlHits.Count, $browser) ($amostra + $extra)
        }
    }
    Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue

    Add-Section 'Downloads / Lixeira / Navegador' $rows ("Arquivos (inclui discos externos/pen ligados), itens apagados e URLs com termos associados a cheats. {0} arquivos varridos." -f $scanned)
}

# ============================================================================
#  13b. CONTEUDO DOS FICHEIROS ("strings") - procura palavras de cheat DENTRO
# ============================================================================
function Get-FileContentScan {
    Write-Step 'Procurando palavras de cheat dentro dos ficheiros'
    $rows = New-Object System.Collections.ArrayList

    # Pastas onde vale a pena procurar (evita varrer o disco todo).
    $dirs = @(
        (Join-Path $env:USERPROFILE 'Downloads'),
        (Join-Path $env:USERPROFILE 'Desktop'),
        (Join-Path $env:USERPROFILE 'Documents'),
        (Join-Path $env:LOCALAPPDATA 'FiveM'),
        $env:TEMP
    )
    # inclui discos externos / pen / 2o disco (raiz completa)
    $dirs += (Get-ExtraDriveRoots)
    $dirs = $dirs | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    # Extensoes de texto/config/script que costumam conter os termos.
    $textExt = @('.lua','.cfg','.ini','.txt','.json','.xml','.cs','.js','.log',
                 '.yml','.yaml','.bat','.cmd','.ps1','.meta','.re','.dat','.cff','.md')
    # Binarios pequenos onde tambem procuramos as strings embutidas.
    $binExt  = @('.exe','.dll','.asi')

    $latin1 = [Text.Encoding]::GetEncoding(28591)
    $depth  = 3; if ($Quick) { $depth = 1 }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $budget = 60       # segundos maximo neste modulo (inclui discos externos)
    $scanned = 0; $maxFiles = 15000

    foreach ($d in $dirs) {
        if ($sw.Elapsed.TotalSeconds -ge $budget -or $scanned -ge $maxFiles) { break }
        foreach ($f in (Get-ChildItem -LiteralPath $d -Recurse -Depth $depth -File -Force -ErrorAction SilentlyContinue)) {
            if ($sw.Elapsed.TotalSeconds -ge $budget -or $scanned -ge $maxFiles) { break }
            Invoke-UiPump -Every 50

            # Ignora os proprios ficheiros do PC Check: o script e os relatorios
            # contem as palavras-chave nas listas/achados (senao auto-detetava-se).
            if ($f.Name -match '(?i)^PCCheck') { continue }
            if ($PSCommandPath -and $f.FullName -eq $PSCommandPath) { continue }

            $ext = $f.Extension.ToLowerInvariant()
            $isText = $textExt -contains $ext
            $isBin  = $binExt  -contains $ext
            if (-not $isText -and -not $isBin) { continue }
            # limites de tamanho para nao ler ficheiros enormes
            if ($isText -and $f.Length -gt 8MB)  { continue }
            if ($isBin  -and $f.Length -gt 6MB)  { continue }

            $scanned++
            $content = ''
            try { $content = $latin1.GetString([IO.File]::ReadAllBytes($f.FullName)) } catch { continue }
            if ([string]::IsNullOrEmpty($content)) { continue }

            # Lista restrita (sem verbos de jogo) para evitar falsos positivos
            # em scripts legitimos de FiveM.
            $kw = Test-KeywordContent $content
            if (-not $kw) { continue }

            [void]$rows.Add([PSCustomObject]@{
                Ficheiro = $f.FullName
                Quando   = $f.LastWriteTime
                Suspeito = ("contem: " + $kw)
            })
            Add-Finding (Get-KeywordSeverity $kw) ("Ficheiro contem termos de cheat: {0}" -f $f.Name) ("{0} | termos: {1} | modificado {2}" -f $f.FullName, $kw, $f.LastWriteTime)
        }
    }

    Add-Section 'Conteudo de ficheiros (strings)' $rows ("Procura das palavras de cheat DENTRO dos ficheiros (texto, config, scripts e binarios pequenos), incluindo discos externos/pen ligados. {0} ficheiros lidos." -f $scanned)
}

# ============================================================================
#  14. PROGRAMAS INSTALADOS, TAREFAS E INICIALIZACAO
# ============================================================================
function Get-InstalledAndPersistence {
    Write-Step 'Analisando programas instalados, tarefas e inicializacao'
    $rows = New-Object System.Collections.ArrayList

    $unins = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($u in $unins) {
        foreach ($app in (Get-ItemProperty $u -ErrorAction SilentlyContinue)) {
            if (-not $app.DisplayName) { continue }
            $kw = Test-Keyword ("{0} {1} {2}" -f $app.DisplayName, $app.Publisher, $app.InstallLocation)
            if (-not $kw) { continue }
            [void]$rows.Add([PSCustomObject]@{
                Tipo='Programa instalado'; Nome=$app.DisplayName
                Detalhe=("{0} | {1}" -f $app.Publisher, $app.InstallLocation); Suspeito=$kw
            })
            Add-Finding (Get-KeywordSeverity $kw) ("Programa instalado suspeito: {0}" -f $app.DisplayName) ("Publisher: {0} | Local: {1} | palavras-chave: {2}" -f $app.Publisher, $app.InstallLocation, $kw)
        }
    }

    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $act = ($t.Actions | ForEach-Object { ("{0} {1}" -f $_.Execute, $_.Arguments) }) -join ' ; '
        $kw  = Test-Keyword ("{0} {1}" -f $t.TaskName, $act)
        if (-not $kw) {
            if ($act -match '(?i)(\\temp\\|\\downloads\\)') { $kw = 'tarefa aponta para pasta temporaria' } else { continue }
        }
        [void]$rows.Add([PSCustomObject]@{ Tipo='Tarefa agendada'; Nome=$t.TaskName; Detalhe=$act; Suspeito=$kw })
        Add-Finding 'MEDIA' ("Tarefa agendada suspeita: {0}" -f $t.TaskName) $act
    }

    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )
    foreach ($rk in $runKeys) {
        if (-not (Test-Path $rk)) { continue }
        $k = Get-Item $rk -ErrorAction SilentlyContinue
        if (-not $k) { continue }
        $p = Get-ItemProperty $rk -ErrorAction SilentlyContinue
        if (-not $p) { continue }
        foreach ($n in $k.GetValueNames()) {
            $val = [string]$p.$n
            $kw  = Test-Keyword ("{0} {1}" -f $n, $val)
            if (-not $kw) {
                if ($val -match '(?i)(\\temp\\|\\downloads\\)') { $kw = 'inicializacao a partir de pasta temporaria' } else { continue }
            }
            [void]$rows.Add([PSCustomObject]@{ Tipo='Inicializacao'; Nome=$n; Detalhe=$val; Suspeito=$kw })
            Add-Finding 'MEDIA' ("Item de inicializacao suspeito: {0}" -f $n) $val
        }
    }

    Add-Section 'Instalados / Persistencia' $rows 'Somente itens que bateram em alguma regra.'
}

# ============================================================================
#  15. ANTI-FORENSE E USN JOURNAL
# ============================================================================
function Get-AntiForensicArtifacts {
    Write-Step 'Verificando sinais de anti-forense'
    $rows = New-Object System.Collections.ArrayList

    $usn = (& fsutil usn queryjournal C: 2>&1 | Out-String)
    if ($usn -notmatch '(?i)USN') {
        [void]$rows.Add([PSCustomObject]@{ Item='USN Journal'; Detalhe=($usn -replace '\s+',' ').Trim(); Suspeito='journal ausente ou inacessivel' })
        Add-Finding 'ALTA' 'USN Journal ausente ou desativado' 'O journal do NTFS registra criacao e exclusao de arquivos. Apaga-lo (fsutil usn deletejournal) e tecnica de anti-forense.'
    } else {
        $sus = ''
        if ($usn -match '(?im)First\s+USN\s*:\s*(0x)?0+\s*$') { $sus = 'journal recriado recentemente (First USN = 0)' }
        [void]$rows.Add([PSCustomObject]@{ Item='USN Journal'; Detalhe=($usn -replace '\s+',' ').Trim(); Suspeito=$sus })
        if ($sus) { Add-Finding 'MEDIA' 'USN Journal aparenta ter sido recriado' 'First USN zerado indica que o journal foi apagado e recriado.' }
    }

    $cleaners = @('bleachbit','ccleaner','privazer','wisedisk','wisecleaner','eraser','wipefile','sdelete','systemcare','glary','kcleaner')
    $pfDir = Join-Path $env:SystemRoot 'Prefetch'
    foreach ($f in (Get-ChildItem $pfDir -Filter *.pf -ErrorAction SilentlyContinue)) {
        $low = $f.BaseName.ToLowerInvariant()
        foreach ($c in $cleaners) {
            if ($low.Contains($c)) {
                [void]$rows.Add([PSCustomObject]@{ Item=$f.BaseName; Detalhe=("executado em " + $f.LastWriteTime); Suspeito='ferramenta de limpeza' })
                Add-Finding 'ALTA' ("Ferramenta de limpeza executada: {0}" -f $c) ("Ultima execucao: {0}. Limpadores apagam justamente os artefatos analisados neste relatorio." -f $f.LastWriteTime)
                break
            }
        }
    }

    [void]$rows.Add([PSCustomObject]@{ Item='Hora local na coleta'; Detalhe=(Get-Date).ToString('u'); Suspeito='' })

    $jl = Join-Path $env:APPDATA 'Microsoft\Windows\Recent\AutomaticDestinations'
    if (Test-Path $jl) {
        $n = @(Get-ChildItem -LiteralPath $jl -Force -ErrorAction SilentlyContinue).Count
        $sus = ''
        if ($n -eq 0) {
            $sus = 'jumplists apagadas'
            Add-Finding 'MEDIA' 'Jump Lists apagadas' 'A pasta AutomaticDestinations esta vazia, o que e incomum em um perfil usado normalmente.'
        }
        [void]$rows.Add([PSCustomObject]@{ Item='Jump Lists'; Detalhe=("{0} arquivos" -f $n); Suspeito=$sus })
    }

    $psh = Join-Path $env:APPDATA 'Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt'
    if (Test-Path $psh) {
        foreach ($line in (Get-Content -LiteralPath $psh -ErrorAction SilentlyContinue)) {
            # Ignora as linhas que apenas iniciam este proprio script: o comando
            # documentado usa "-ExecutionPolicy Bypass" e casaria com "bypass".
            if ($line -match '(?i)PCCheck-FiveM') { continue }
            # Historico e texto curto e ruidoso: so termos inequivocos valem aqui.
            $kw = Test-KeywordStrong $line
            if (-not $kw) {
                # Exige a forma destrutiva do comando: so citar "Prefetch" nao basta.
                if ($line -match '(?i)(deletejournal|wevtutil\s+cl\b|Clear-EventLog|cipher\s+/w|(Remove-Item|rm\b|del\b|erase\b|rd\b|rmdir\b)[^\r\n]*Prefetch)') { $kw = 'comando de anti-forense' } else { continue }
            }
            [void]$rows.Add([PSCustomObject]@{ Item='Historico PowerShell'; Detalhe=$line; Suspeito=$kw })
            Add-Finding 'ALTA' 'Comando suspeito no historico do PowerShell' $line
        }
    }

    Add-Section 'Anti-forense' $rows 'Sinais de que artefatos foram apagados deliberadamente.'
}

# ============================================================================
#  16. DISPOSITIVOS USB
# ============================================================================
function Get-UsbArtifacts {
    Write-Step 'Listando dispositivos USB'
    $rows = New-Object System.Collections.ArrayList
    $root = 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR'
    foreach ($dev in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
        foreach ($inst in (Get-ChildItem $dev.PSPath -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty $inst.PSPath -ErrorAction SilentlyContinue
            [void]$rows.Add([PSCustomObject]@{
                Dispositivo = $p.FriendlyName
                Serial      = $inst.PSChildName
                Chave       = $dev.PSChildName
                Suspeito    = ''
            })
        }
    }
    Add-Section 'Dispositivos USB' $rows 'Pendrives e HDs externos ja conectados. Util quando o cheat foi executado a partir de midia removivel.'
}


# ============================================================================
#  RELATORIO HTML
# ============================================================================
function ConvertTo-HtmlText {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $t = [string]$Text
    $t = $t.Replace('&','&amp;')
    $t = $t.Replace('<','&lt;')
    $t = $t.Replace('>','&gt;')
    $t = $t.Replace('"','&quot;')
    return $t
}

function Get-HtmlReportString {
    # Constroi o HTML em memoria e devolve a string (define $script:Selo).
    $alta  = @($script:Findings | Where-Object { $_.Severity -eq 'ALTA' })
    $media = @($script:Findings | Where-Object { $_.Severity -eq 'MEDIA' })
    $baixa = @($script:Findings | Where-Object { $_.Severity -eq 'BAIXA' })

    $veredito = 'NENHUM INDICIO'
    $vClass   = 'ok'
    if ($alta.Count -gt 0)      { $veredito = 'INDICIOS FORTES';   $vClass = 'alta' }
    elseif ($media.Count -gt 0) { $veredito = 'PONTOS A REVISAR';  $vClass = 'media' }

    $css = @'
<!DOCTYPE html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PC Check FiveM</title>
<style>
:root{
  --bg:#0f1115; --panel:#171a21; --panel2:#1d2129; --line:#2a2f3a;
  --txt:#e6e8ee; --muted:#98a0b0;
  --alta:#ff4d4f; --alta-bg:rgba(255,77,79,.14);
  --media:#ffa726; --media-bg:rgba(255,167,38,.13);
  --baixa:#ffd54f; --baixa-bg:rgba(255,213,79,.12);
  --ok:#4ade80;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:14px/1.5 "Segoe UI",system-ui,sans-serif;padding:24px}
h1{font-size:22px;margin:0 0 4px}
.by{font-size:13px;font-weight:600;color:var(--ok);border:1px solid var(--ok);border-radius:20px;padding:3px 10px;margin-left:10px;vertical-align:middle;letter-spacing:.3px}
.pin{display:inline-block;margin:4px 0 8px;padding:6px 12px;border-radius:8px;background:var(--panel2);border:1px solid var(--line);font-size:14px;letter-spacing:1px}
.pin b{color:var(--ok);font-family:Consolas,monospace}
.selo{margin-top:16px;padding:10px 14px;border:1px dashed var(--line);border-radius:8px;color:var(--muted);font-size:12px}
.selo b{color:var(--txt)}
code{font-family:Consolas,monospace;color:var(--ok);word-break:break-all}
h2{font-size:16px;margin:34px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.sub{color:var(--muted);font-size:13px;margin-bottom:18px}
.verdict{display:inline-block;padding:14px 22px;border-radius:10px;font-size:20px;font-weight:700;letter-spacing:.5px;margin:6px 0 4px}
.verdict.alta{background:var(--alta-bg);color:var(--alta);border:1px solid var(--alta)}
.verdict.media{background:var(--media-bg);color:var(--media);border:1px solid var(--media)}
.verdict.ok{background:rgba(74,222,128,.12);color:var(--ok);border:1px solid var(--ok)}
.counts{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 6px}
.chip{padding:6px 12px;border-radius:20px;font-size:12px;font-weight:600;border:1px solid var(--line);background:var(--panel2)}
.chip.alta{color:var(--alta);border-color:var(--alta);background:var(--alta-bg)}
.chip.media{color:var(--media);border-color:var(--media);background:var(--media-bg)}
.chip.baixa{color:var(--baixa);border-color:var(--baixa);background:var(--baixa-bg)}
.finding{border-left:4px solid var(--line);background:var(--panel);padding:10px 14px;margin:8px 0;border-radius:0 6px 6px 0}
.finding.alta{border-left-color:var(--alta);background:var(--alta-bg)}
.finding.media{border-left-color:var(--media);background:var(--media-bg)}
.finding.baixa{border-left-color:var(--baixa);background:var(--baixa-bg)}
.finding .t{font-weight:700}
.finding.alta .t{color:var(--alta)}
.finding.media .t{color:var(--media)}
.finding.baixa .t{color:var(--baixa)}
.finding .d{color:var(--muted);font-size:12.5px;margin-top:3px;word-break:break-all}
table{width:100%;border-collapse:collapse;background:var(--panel);font-size:12.5px}
th{background:var(--panel2);text-align:left;padding:8px 10px;color:var(--muted);font-weight:600;white-space:nowrap;position:sticky;top:0}
td{padding:7px 10px;border-top:1px solid var(--line);vertical-align:top;word-break:break-word}
tr.sus td{background:var(--alta-bg);color:#ffb3b4}
tr.sus td:first-child{box-shadow:inset 3px 0 0 var(--alta)}
td.flag{color:var(--alta);font-weight:700}
.note{color:var(--muted);font-size:12px;margin-bottom:8px}
.empty{color:var(--muted);font-style:italic;padding:8px 0}
.wrap{max-height:520px;overflow:auto;border:1px solid var(--line);border-radius:8px}
.toolbar{margin:6px 0 10px;display:flex;gap:8px}
button{background:var(--panel2);color:var(--txt);border:1px solid var(--line);padding:6px 12px;border-radius:6px;cursor:pointer;font-size:12px}
button:hover{border-color:var(--alta);color:var(--alta)}
.legend{color:var(--muted);font-size:12px;margin:12px 0 0}
.legend b{color:var(--alta)}
footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}
</style></head><body>
'@

    $js = @'
<script>
function only(id){var t=document.getElementById(id);if(!t)return;
  var rs=t.querySelectorAll("tbody tr");
  for(var i=0;i<rs.length;i++){rs[i].style.display=rs[i].className==="sus"?"":"none";}}
function all(id){var t=document.getElementById(id);if(!t)return;
  var rs=t.querySelectorAll("tbody tr");
  for(var i=0;i<rs.length;i++){rs[i].style.display="";}}
</script>
</body></html>
'@

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine($css)
    [void]$sb.AppendLine('<h1>PC Check &ndash; FiveM <span class="by">por ' + (ConvertTo-HtmlText $script:Autor) + '</span></h1>')
    [void]$sb.AppendLine(('<div class="sub">{0} &nbsp;|&nbsp; {1}\{2} &nbsp;|&nbsp; gerado em {3} &nbsp;|&nbsp; v{4}</div>' -f `
        (ConvertTo-HtmlText $env:COMPUTERNAME), (ConvertTo-HtmlText $env:USERDOMAIN), (ConvertTo-HtmlText $env:USERNAME), (Get-Date).ToString('dd/MM/yyyy HH:mm:ss'), $script:Versao))
    [void]$sb.AppendLine(('<div class="verdict {0}">{1}</div>' -f $vClass, $veredito))
    [void]$sb.AppendLine('<div class="counts">')
    [void]$sb.AppendLine(('<span class="chip alta">{0} alta</span>'   -f $alta.Count))
    [void]$sb.AppendLine(('<span class="chip media">{0} media</span>' -f $media.Count))
    [void]$sb.AppendLine(('<span class="chip baixa">{0} baixa</span>' -f $baixa.Count))
    [void]$sb.AppendLine('</div>')
    [void]$sb.AppendLine('<p class="legend">Linhas em <b>vermelho</b> foram sinalizadas automaticamente pelas regras do script. Isso indica <b>suspeita</b>, nunca prova. Interprete sempre junto do contexto.</p>')

    [void]$sb.AppendLine('<h2>Achados</h2>')
    if ($script:Findings.Count -eq 0) {
        [void]$sb.AppendLine('<div class="empty">Nenhum indicio encontrado pelas regras deste script.</div>')
    } else {
        foreach ($sev in @('ALTA','MEDIA','BAIXA','INFO')) {
            foreach ($f in ($script:Findings | Where-Object { $_.Severity -eq $sev })) {
                [void]$sb.AppendLine(('<div class="finding {0}"><div class="t">[{1}] {2}</div><div class="d">{3}</div></div>' -f `
                    $sev.ToLower(), $sev, (ConvertTo-HtmlText $f.Title), (ConvertTo-HtmlText $f.Detail)))
            }
        }
    }

    foreach ($key in $script:Sections.Keys) {
        $sec = $script:Sections[$key]
        [void]$sb.AppendLine(('<h2>{0}</h2>' -f (ConvertTo-HtmlText $sec.Name)))
        if ($sec.Note) { [void]$sb.AppendLine(('<div class="note">{0}</div>' -f (ConvertTo-HtmlText $sec.Note))) }

        $data = @($sec.Data | Where-Object { $_ })
        if ($data.Count -eq 0) {
            [void]$sb.AppendLine('<div class="empty">Sem registros.</div>')
            continue
        }

        $cols   = $data[0].PSObject.Properties.Name
        $secId  = 'tb' + ($sec.Name -replace '[^a-zA-Z0-9]','')
        $hasSus = $cols -contains 'Suspeito'
        if ($hasSus) {
            [void]$sb.AppendLine(('<div class="toolbar"><button onclick="only(''{0}'')">Mostrar apenas suspeitos</button><button onclick="all(''{0}'')">Mostrar tudo</button></div>' -f $secId))
        }

        [void]$sb.AppendLine(('<div class="wrap"><table id="{0}"><thead><tr>' -f $secId))
        foreach ($c in $cols) { [void]$sb.Append(('<th>{0}</th>' -f (ConvertTo-HtmlText $c))) }
        [void]$sb.AppendLine('</tr></thead><tbody>')

        foreach ($row in $data) {
            $cls = ''
            if ($hasSus -and -not [string]::IsNullOrWhiteSpace([string]$row.Suspeito)) { $cls = ' class="sus"' }
            [void]$sb.Append(('<tr{0}>' -f $cls))
            foreach ($c in $cols) {
                $v = [string]$row.$c
                $tdcls = ''
                if ($c -eq 'Suspeito' -and $v) { $tdcls = ' class="flag"' }
                [void]$sb.Append(('<td{0}>{1}</td>' -f $tdcls, (ConvertTo-HtmlText $v)))
            }
            [void]$sb.AppendLine('</tr>')
        }
        [void]$sb.AppendLine('</tbody></table></div>')
    }

    # ---- Selo de verificacao -------------------------------------------
    # SHA-256 de todo o conteudo gerado ate aqui. O mesmo codigo e gravado no
    # .txt: se alguem editar o HTML na mao, os dois deixam de bater.
    $sha   = [Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($sb.ToString()))
    $script:Selo = ([BitConverter]::ToString($bytes) -replace '-','').Substring(0,32)

    [void]$sb.AppendLine(('<div class="selo">Relatorio gerado por <b>PC Check FiveM v{0}</b>, de <b>{1}</b>.<br>Codigo de verificacao: <code>{2}</code><br>O mesmo codigo consta no arquivo .txt que acompanha este relatorio. Se os dois nao baterem, o conteudo foi alterado depois da coleta.</div>' -f `
        $script:Versao, (ConvertTo-HtmlText $script:Autor), $script:Selo))

    [void]$sb.AppendLine(('<footer>Coleta iniciada em {0}, concluida em {1} ({2:N1}s).<br>Relatorio somente leitura: o script nao alterou nada no sistema.<br>Nenhum item aqui prova uso de cheat por si so. Avalie o conjunto.<br>PC Check FiveM v{3} &mdash; {4}</footer>' -f `
        $script:StartTime.ToString('HH:mm:ss'), (Get-Date).ToString('HH:mm:ss'), ((Get-Date) - $script:StartTime).TotalSeconds, $script:Versao, (ConvertTo-HtmlText $script:Autor)))
    [void]$sb.AppendLine($js)

    return $sb.ToString()
}

function New-HtmlReport {
    # Versao que grava em ficheiro (usada pelo modo CLI).
    param([string]$Path)
    [IO.File]::WriteAllText($Path, (Get-HtmlReportString), (New-Object System.Text.UTF8Encoding($true)))
}

# ============================================================================
#  MAIN
# ============================================================================

Write-Host ''
Write-Host '  ============================================================' -ForegroundColor DarkGray
Write-Host '   PC CHECK - FiveM  |  coleta forense somente leitura' -ForegroundColor Cyan
Write-Host ("   v{0}  -  desenvolvido por {1}" -f $script:Versao, $script:Autor) -ForegroundColor Green
Write-Host '  ============================================================' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  Este programa APENAS LE informacoes do PC. Nao altera nada e' -ForegroundColor Gray
Write-Host '  nao envia nada para a internet.' -ForegroundColor Gray
Write-Host '  Use somente com o consentimento do dono do PC.' -ForegroundColor Gray
Write-Host ''
if (-not $KeepScript) {
    Write-Host '  [i] Este .ps1 apaga-se sozinho no fim (os relatorios ficam).' -ForegroundColor DarkGray
    Write-Host '      Use -KeepScript para manter uma copia.' -ForegroundColor DarkGray
    Write-Host ''
}

if (-not (Test-IsAdmin)) {
    Write-Host '  [!] Sem privilegios de Administrador.' -ForegroundColor Yellow
    Write-Host '      Prefetch, BAM, drivers e logs ficarao incompletos - o' -ForegroundColor Yellow
    Write-Host '      relatorio perde valor. Feche e abra como Administrador.' -ForegroundColor Yellow
    Write-Host ''
}

$modules = @(
    'Get-SystemOverview','Get-PrefetchArtifacts','Get-BamArtifacts','Get-UserAssistArtifacts',
    'Get-MuiCacheArtifacts','Get-RecentLnkArtifacts','Get-EventLogArtifacts','Get-DefenderArtifacts',
    'Get-BootIntegrity','Get-SecurityPostureArtifacts','Get-DriverArtifacts','Get-ProcessArtifacts','Get-ProcessStateArtifacts',
    'Get-LoadedModuleArtifacts','Get-ServiceStateArtifacts','Get-FiveMArtifacts','Get-DownloadArtifacts',
    'Get-FileContentScan','Get-InstalledAndPersistence','Get-AntiForensicArtifacts','Get-UsbArtifacts'
)

$i = 0
foreach ($m in $modules) {
    $i++
    Write-Progress -Activity 'PC Check FiveM' -Status $m -PercentComplete (($i / $modules.Count) * 100)
    try { & $m } catch { Write-Host ("  [x] Falha em {0}: {1}" -f $m, $_.Exception.Message) -ForegroundColor DarkRed }
}
Write-Progress -Activity 'PC Check FiveM' -Completed

Write-Host ''
Write-Host '  ------------------------- RESUMO ---------------------------' -ForegroundColor DarkGray
$cAlta  = @($script:Findings | Where-Object { $_.Severity -eq 'ALTA' }).Count
$cMedia = @($script:Findings | Where-Object { $_.Severity -eq 'MEDIA' }).Count
$cBaixa = @($script:Findings | Where-Object { $_.Severity -eq 'BAIXA' }).Count

foreach ($f in $script:Findings) {
    $color = 'Gray'
    if     ($f.Severity -eq 'ALTA')  { $color = 'Red' }
    elseif ($f.Severity -eq 'MEDIA') { $color = 'Yellow' }
    elseif ($f.Severity -eq 'BAIXA') { $color = 'DarkYellow' }
    Write-Host ("  [{0,-5}] {1}" -f $f.Severity, $f.Title) -ForegroundColor $color
}

Write-Host ''
Write-Host ("  ALTA: {0}   MEDIA: {1}   BAIXA: {2}" -f $cAlta, $cMedia, $cBaixa) -ForegroundColor White
if ($cAlta -gt 0) {
    Write-Host '  >> INDICIOS FORTES - revise o relatorio com atencao.' -ForegroundColor Red
} elseif ($cMedia -gt 0) {
    Write-Host '  >> PONTOS A REVISAR - nada conclusivo.' -ForegroundColor Yellow
} else {
    Write-Host '  >> Nenhum indicio encontrado pelas regras deste script.' -ForegroundColor Green
}

if (-not (Test-Path $OutputPath)) { New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null }
$stamp    = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
$baseName = ("PCCheck_{0}_{1}" -f $env:COMPUTERNAME, $stamp)
$htmlPath = Join-Path $OutputPath ($baseName + '.html')
$txtPath  = Join-Path $OutputPath ($baseName + '.txt')

New-HtmlReport -Path $htmlPath

$txt = New-Object System.Text.StringBuilder
[void]$txt.AppendLine(("PC CHECK - FiveM v{0} - desenvolvido por {1}" -f $script:Versao, $script:Autor))
[void]$txt.AppendLine(("Maquina: {0}\{1}  |  {2}" -f $env:USERDOMAIN, $env:USERNAME, (Get-Date)))
[void]$txt.AppendLine(("Achados: ALTA={0} MEDIA={1} BAIXA={2}" -f $cAlta, $cMedia, $cBaixa))
[void]$txt.AppendLine(("Codigo de verificacao: {0}" -f $script:Selo))
[void]$txt.AppendLine('')
foreach ($f in $script:Findings) {
    [void]$txt.AppendLine(("[{0}] {1}" -f $f.Severity, $f.Title))
    if ($f.Detail) { [void]$txt.AppendLine(("       " + $f.Detail)) }
}
[IO.File]::WriteAllText($txtPath, $txt.ToString(), (New-Object System.Text.UTF8Encoding($true)))

Write-Host ''
Write-Host ("  Relatorio HTML: {0}" -f $htmlPath) -ForegroundColor Cyan
Write-Host ("  Resumo TXT    : {0}" -f $txtPath)  -ForegroundColor Cyan
Write-Host ("  Verificacao   : {0}" -f $script:Selo) -ForegroundColor DarkGray
Write-Host ''
Write-Host '  >> ENVIE OS DOIS ARQUIVOS (.html e .txt) PARA A STAFF.' -ForegroundColor Cyan
Write-Host ''

if (-not $NoOpen) { Start-Process $htmlPath }

# ---- Auto-apagar o proprio .ps1 (os relatorios ja foram gravados) ----
if (-not $KeepScript -and $PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath)) {
    try {
        Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction Stop
        Write-Host '  [i] Script apagado do disco.' -ForegroundColor DarkGray
    } catch {
        Write-Host '  [i] Nao foi possivel apagar o script (ficheiro em uso).' -ForegroundColor DarkGray
    }
    Write-Host ''
}
