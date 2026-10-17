<#
.SYNOPSIS
    OWASP IoT & Embedded Security Auditor - Helper Scanner Script (PowerShell)
.DESCRIPTION
    Executes the 4 automated support phases for the Agent:
    1. General Project Probe of Artifacts and Technologies
    2. Software Functionalities Classification per Section 6.1 (SKILL.md, Etapa 2)
    3. State Checklist Inspection/Initialization (where the agent stopped and where to go next)
    4. Automated Static Triage following strict Section 6.2 order (Modules 1 to 6)
#>
param(
    [string]$TargetDir = ".",
    [string]$ChecklistFile = "owasp_iot_checklist_progresso.md",
    [string]$ReportFile = "owasp_iot_relatorio_final.md",
    [string]$RemediationFile = "owasp_iot_plano_resolucao.md",
    [string]$VerifyId = "",
    [switch]$InitChecklist,
    [switch]$InitRemediation
)

$ErrorActionPreference = "Stop"
$ResolvedTarget = (Resolve-Path $TargetDir).Path
$ChecklistPath = Join-Path $ResolvedTarget $ChecklistFile
$ReportPath = Join-Path $ResolvedTarget $ReportFile
$RemediationPath = Join-Path $ResolvedTarget $RemediationFile

if ($InitChecklist -and -not (Test-Path $ChecklistPath)) {
    $TemplatePath = Join-Path $PSScriptRoot "..\resources\checklist_template.md"
    if (Test-Path $TemplatePath) {
        $Content = Get-Content -Path $TemplatePath -Raw -Encoding UTF8
        $ProjectName = Split-Path $ResolvedTarget -Leaf
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
        $Content = $Content.Replace("<NOME_OU_CAMINHO_DO_PROJETO>", $ProjectName).Replace("<YYYY-MM-DD HH:MM>", $Timestamp)
        Set-Content -Path $ChecklistPath -Value $Content -Encoding UTF8
    }
}

if ($InitRemediation -and -not (Test-Path $RemediationPath)) {
    $RemTemplatePath = Join-Path $PSScriptRoot "..\resources\remediation_tracker_template.md"
    if (Test-Path $RemTemplatePath) {
        $RemContent = Get-Content -Path $RemTemplatePath -Raw -Encoding UTF8
        $ProjectName = Split-Path $ResolvedTarget -Leaf
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
        $RemContent = $RemContent.Replace("<NOME_DO_PROJETO>", $ProjectName).Replace("<YYYY-MM-DD HH:MM>", $Timestamp)
        Set-Content -Path $RemediationPath -Value $RemContent -Encoding UTF8
    }
}

if (-not [string]::IsNullOrWhiteSpace($VerifyId)) {
    $TargetId = $VerifyId.Trim()
    $ChecklistMatches = @()
    $ReportMatches = @()
    $RemediationMatches = @()

    if (Test-Path $ChecklistPath) {
        $ChecklistMatches = @(Select-String -Path $ChecklistPath -SimpleMatch $TargetId | ForEach-Object { @{ Line = $_.LineNumber; Text = $_.Line.Trim() } })
    }
    if (Test-Path $ReportPath) {
        $ReportMatches = @(Select-String -Path $ReportPath -SimpleMatch $TargetId | ForEach-Object { @{ Line = $_.LineNumber; Text = $_.Line.Trim() } })
    }
    if (Test-Path $RemediationPath) {
        $RemediationMatches = @(Select-String -Path $RemediationPath -SimpleMatch $TargetId -Context 0, 8 | ForEach-Object {
            @{ Line = $_.LineNumber; Text = ($_.Line + "`n" + ($_.Context.PostContext -join "`n")).Trim() }
        })
    }

    $Modo2Result = [ordered]@{
        Modo = "Modo 2 - Reteste Pontual por ID OWASP"
        IdSolicitado = $TargetId
        RegistrosNoPlanoDeResolucao = $RemediationMatches
        RegistrosNoRelatorioFinal = $ReportMatches
        RegistrosNoChecklist = $ChecklistMatches
        InstrucaoAgente = "Inspecione cirurgicamente os arquivos citados para $TargetId, emita o veredito (PASS/PARTIAL/FAIL) e sincronize owasp_iot_plano_resolucao.md, owasp_iot_relatorio_final.md e owasp_iot_checklist_progresso.md."
    }
    $Modo2Result | ConvertTo-Json -Depth 5
    exit 0
}

$IgnoreRegex = '(\\\.git\\|\\node_modules\\|\\\.pio\\|\\\.vscode\\|\\__pycache__\\|\\IOT_OWASP\\|\\\.agents\\|\\\.agent\\)'

$AllFiles = @(Get-ChildItem -Path $ResolvedTarget -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object {
    $_.FullName -notmatch $IgnoreRegex -and
    $_.Name -ne "metodologia_owasp_iot_agente.md" -and
    -not $_.Name.StartsWith("owasp_iot_")
})

$EmbeddedFiles = @()
$BuildFiles = @()
$BackendFiles = @()
$UiFiles = @()

$RtosSdk = [System.Collections.Generic.HashSet[string]]::new()
$BuildSys = [System.Collections.Generic.HashSet[string]]::new()
$CryptoLibs = [System.Collections.Generic.HashSet[string]]::new()
$Protocols = [System.Collections.Generic.HashSet[string]]::new()
$HwInterfaces = [System.Collections.Generic.HashSet[string]]::new()
$StorageFs = [System.Collections.Generic.HashSet[string]]::new()

$SourceExts = @(".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".ino", ".s", ".py", ".js", ".ts", ".lua", ".sh", ".php", ".html", ".json", ".yaml", ".yml", ".ini", ".conf", ".cfg", ".cmake", ".mk")

$Mod1Findings = @()
$Mod2Findings = @()
$Mod3Findings = @()
$Mod4Findings = @()
$Mod5Findings = @()
$Mod6Findings = @()

foreach ($f in $AllFiles) {
    $RelPath = $f.FullName.Substring($ResolvedTarget.Length).TrimStart('\', '/')
    $Ext = $f.Extension.ToLower()
    $NameLower = $f.Name.ToLower()

    if ($NameLower -in @("cmakelists.txt", "makefile", "platformio.ini", "sdkconfig", "sdkconfig.defaults", "kconfig", "dockerfile", "docker-compose.yml", "idf_component.yml") -or
        $Ext -in @(".bin", ".elf", ".hex", ".uf2", ".img", ".squashfs", ".jffs2", ".ubifs", ".ld", ".bb", ".bbappend")) {
        $BuildFiles += $RelPath
        if ($NameLower -match "platformio\.ini") { [void]$BuildSys.Add("PlatformIO") }
        if ($NameLower -match "sdkconfig|idf_component") { [void]$RtosSdk.Add("ESP-IDF") }
        if ($NameLower -eq "cmakelists.txt") { [void]$BuildSys.Add("CMake") }
        if ($NameLower -eq "makefile") { [void]$BuildSys.Add("Make") }
        if ($NameLower -match "dockerfile|docker-compose") { [void]$BuildSys.Add("Docker") }
        if ($Ext -in @(".bb", ".bbappend")) { [void]$RtosSdk.Add("Yocto / OpenEmbedded") }
    }

    if ($NameLower -in @("package.json", "requirements.txt", "platformio.ini", "idf_component.yml")) {
        $Mod6Findings += [ordered]@{
            Ref = "ISTG-*-CONF-001 / EMB-APPSEC-10"
            File = $RelPath
            Description = "Dependency manifest found for SBOM and CVE audit"
        }
    }

    if ($Ext -in @(".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".ino", ".s")) {
        $EmbeddedFiles += $RelPath
        if ($Ext -eq ".ino") { [void]$RtosSdk.Add("Arduino") }
    }

    if ($NameLower -in @("package.json", "requirements.txt", "pyproject.toml", "mosquitto.conf") -or $Ext -in @(".py", ".js", ".ts", ".go", ".rs")) {
        if ($RelPath -notmatch '(?i)(frontend|public|www|htdocs|webui|dashboard)') {
            $BackendFiles += $RelPath
        }
    }

    if ($Ext -in @(".html", ".htm", ".css", ".vue", ".jsx", ".tsx") -or $RelPath -match '(?i)(frontend|www|htdocs|webui|dashboard)') {
        $UiFiles += $RelPath
    }

    if ($Ext -in $SourceExts -or $NameLower -in @("sdkconfig", "platformio.ini", "cmakelists.txt", "package.json")) {
        $Text = Get-Content -Path $f.FullName -Raw -ErrorAction SilentlyContinue
        if (-not [string]::IsNullOrEmpty($Text)) {
            if ($Text -match '(?i)\b(freertos|xTaskCreate|vTaskDelay|configCHECK_FOR_STACK_OVERFLOW)\b') { [void]$RtosSdk.Add("FreeRTOS") }
            if ($Text -match '(?i)\b(esp_system\.h|esp_wifi\.h|esp_log\.h|nvs_flash\.h|esp_ota_ops\.h)\b') { [void]$RtosSdk.Add("ESP-IDF") }
            if ($Text -match '\b(Arduino\.h|Serial\.begin|digitalWrite|WiFi\.begin)\b') { [void]$RtosSdk.Add("Arduino Framework") }
            if ($Text -match '(?i)\b(zephyr/kernel\.h|CONFIG_ZEPHYR)\b') { [void]$RtosSdk.Add("Zephyr RTOS") }
            if ($Text -match '(?i)\b(CONFIG_ENABLE_VBOOT|CONFIG_FIT_SIGNATURE|CONFIG_BOOTDELAY|u-boot)\b') { [void]$RtosSdk.Add("Das U-Boot") }

            if ($Text -match '(?i)\b(mbedtls_|mbedtls/)\b') { [void]$CryptoLibs.Add("mbedTLS") }
            if ($Text -match '\b(openssl/|SSL_CTX_|EVP_PKEY|X509_verify_cert)\b') { [void]$CryptoLibs.Add("OpenSSL") }
            if ($Text -match '(?i)\b(wolfssl|wc_InitRsaKey)\b') { [void]$CryptoLibs.Add("wolfSSL") }
            if ($Text -match '(?i)\b(bcrypt|argon2|pbkdf2)\b') { [void]$CryptoLibs.Add("Password Hashing (bcrypt/PBKDF2/Argon2)") }

            if ($Text -match '(?i)\b(mqtt|mosquitto|aedes|PubSubClient|esp_mqtt_client)\b') { [void]$Protocols.Add("MQTT") }
            if ($Text -match '(?i)\b(coap)\b') { [void]$Protocols.Add("CoAP") }
            if ($Text -match '(?i)\b(http|https|express|fastapi|flask|esp_http_client|WebServer)\b') { [void]$Protocols.Add("HTTP/REST") }
            if ($Text -match '(?i)\b(websocket|ws://|wss://|socket\.io)\b') { [void]$Protocols.Add("WebSockets") }

            if ($Text -match '\b(Serial\.print|uart_driver_install|ttyS|ttyAMA|UART_NUM_)\b') { [void]$HwInterfaces.Add("UART") }
            if ($Text -match '\b(Wire\.begin|i2c_master_|i2c_param_config|/dev/i2c)\b') { [void]$HwInterfaces.Add("I2C") }
            if ($Text -match '\b(SPI\.begin|spi_bus_initialize|MFRC522|RC522)\b') { [void]$HwInterfaces.Add("SPI") }
            if ($Text -match '(?i)\b(MFRC522|RC522|PN532|rfid|nfc)\b') { [void]$HwInterfaces.Add("RFID/NFC (WRLS)") }
            if ($Text -match '\b(WiFi\.|esp_wifi|wpa_supplicant)\b') { [void]$HwInterfaces.Add("Wi-Fi (WRLS)") }
            if ($Text -match '(?i)\b(BLEDevice|esp_ble_|NimBLE|bluetooth)\b') { [void]$HwInterfaces.Add("BLE/Bluetooth (WRLS)") }

            if ($Text -match '(?i)\b(LittleFS|SPIFFS|nvs_flash|EEPROM|squashfs|ubifs|jffs2|sqlite)\b') {
                [void]$StorageFs.Add($Matches[1])
            }

            # Line-by-line Section 6.2 triage
            $Lines = $Text -split "`r?`n"
            for ($i = 0; $i -lt $Lines.Count; $i++) {
                $Ln = $Lines[$i]
                $Lnum = $i + 1
                if ($Ext -in @(".c", ".cpp", ".cc", ".h", ".hpp", ".ino") -and $Ln -match '\b(gets|strcpy|strcat|sprintf|vsprintf)\s*\(') {
                    $Mod1Findings += [ordered]@{ Ref = "EMB-APPSEC-01 / ISTG-*-INPV-001"; File = $RelPath; Line = $Lnum; Match = $Matches[1] }
                }
                if ($Ln -match '\b(system|popen|execlp|execvp|os\.system|child_process\.exec|eval)\s*\(') {
                    $Mod1Findings += [ordered]@{ Ref = "EMB-APPSEC-02 / ISTG-*-INPV-002"; File = $RelPath; Line = $Lnum; Match = $Matches[1] }
                }
                if ($Ln -match '(?i)(WIFI_PASS|MQTT_PASS|PASSWORD|SECRET|API_KEY|PRIVATE_KEY)\s*[:=]\s*["''][^"'']{3,}["'']|-----BEGIN (RSA )?PRIVATE KEY-----') {
                    $Mod2Findings += [ordered]@{ Ref = "ISTG-FW-SCRT-003 / EMB-APPSEC-04"; File = $RelPath; Line = $Lnum; Match = "Hardcoded secret candidate" }
                }
                if ($Ln -match '\b(setInsecure\s*\(\)|MBEDTLS_SSL_VERIFY_NONE|rejectUnauthorized\s*:\s*false|CURLOPT_SSL_VERIFYPEER\s*,\s*0)\b') {
                    $Mod2Findings += [ordered]@{ Ref = "ISTG-*-CRYPT-001 / EMB-APPSEC-08"; File = $RelPath; Line = $Lnum; Match = $Matches[1] }
                }
                if ($Ext -in @(".c", ".cpp", ".h", ".hpp", ".ino") -and $Ln -match '(?i)\b(Serial\.print|Serial\.println|Serial\.printf|ESP_LOG[IWDVE])\s*\([^)]*(pass|key|token|secret|uid|hash|pin)') {
                    $Mod3Findings += [ordered]@{ Ref = "ISTG-INT[UART]-INFO-002"; File = $RelPath; Line = $Lnum; Match = "Potential sensitive data in UART log" }
                }
                if ($Ln -match '\b(esp_https_ota|esp_ota_begin|ArduinoOTA|HTTPUpdate|Update\.begin|CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK)\b') {
                    $Mod4Findings += [ordered]@{ Ref = "ISTG-FW[UPDT]-*"; File = $RelPath; Line = $Lnum; Match = $Matches[1] }
                }
                if ($Ln -match '\b(allow_anonymous\s+true)\b|subscribe\s*\(\s*["'']#["'']') {
                    $Mod5Findings += [ordered]@{ Ref = "ISTG-DES-AUTHZ-001"; File = $RelPath; Line = $Lnum; Match = "Anonymous broker or wildcard topic" }
                }
            }
        }
    }
}

# Etapa 2: Classificacao Secao 6.1
$HasFw = ($EmbeddedFiles.Count -gt 0) -or ($RtosSdk.Count -gt 0)
$HasBuild = ($BuildFiles.Count -gt 0)
$HasDes = ($BackendFiles.Count -gt 0) -or ($Protocols.Count -gt 0)
$HasUi = ($UiFiles.Count -gt 0)
$HasWrls = ($HwInterfaces | Where-Object { $_ -match "WRLS" }).Count -gt 0

# Etapa 3: Estado do Checklist
$ChecklistStatus = [ordered]@{
    Existe = (Test-Path $ChecklistPath)
    Caminho = $ChecklistPath
    OndeParou = "Nenhum item concluido ainda (Inicio da Auditoria)"
    ParaOndeDeveIr = "Inicializar checklist (-InitChecklist) e iniciar Modulo 1 (SAST Embarcado & Qualidade de Memoria)"
    Contagem = [ordered]@{ PASS = 0; PARTIAL = 0; FAIL = 0; NA = 0; PENDENTE = 0; OPCIONAL = 0 }
}

if (Test-Path $ChecklistPath) {
    $ChkLines = Get-Content -Path $ChecklistPath -Encoding UTF8
    $LastDone = $null
    $NextPending = $null
    foreach ($line in $ChkLines) {
        if ($line -match '^\|\s*`?((?:ISTG|EMB-APPSEC|FSTM-STAGE)-[A-Z0-9\[\]\-]+)`?\s*\|\s*([^|]+)\|\s*(M.dulo [^|]+)\|\s*(?:[^|]+\|\s*)?`?(PASS|PARTIAL|FAIL|N/A|PENDENTE|OPCIONAL)`?\s*\|') {
            $Tid = $Matches[1].Trim()
            $Tname = $Matches[2].Trim()
            $Tmod = $Matches[3].Trim()
            $Tstat = $Matches[4].Trim()
            if ($Tstat -eq "N/A") { $ChecklistStatus.Contagem.NA++ }
            else { $ChecklistStatus.Contagem[$Tstat]++ }

            if ($Tstat -notin @("PENDENTE", "OPCIONAL")) {
                $LastDone = "$Tid ($Tmod) -> $Tstat"
            } elseif ($Tstat -eq "PENDENTE" -and $null -eq $NextPending) {
                $NextPending = "$Tid ($Tmod - $Tname)"
            }
        }
    }
    if ($LastDone) { $ChecklistStatus.OndeParou = $LastDone }
    if ($NextPending) { $ChecklistStatus.ParaOndeDeveIr = $NextPending }
    else { $ChecklistStatus.ParaOndeDeveIr = "Todos os itens obrigatorios concluidos! Pronto para gerar o Relatorio Final (Etapa 5)." }
}

$FwMods = if ($HasFw) { @("ISTG-FW", "ISTG-MEM", "ISTG-PROC", "ISTG-INT[UART/I2C]", "Embedded AppSec") } else { @() }
$BuildMods = if ($HasBuild) { @("ISTG-FW-INFO-004", "ISTG-FW-CONF-002", "ISTG-FW[INST]-CRYPT-001", "ISTG-FW-CONF-001") } else { @() }
$DesMods = if ($HasDes) { @("ISTG-DES") } else { @() }
$UiMods = @()
if ($HasUi) { $UiMods += "ISTG-UI" }
if ($HasWrls) { $UiMods += "ISTG-WRLS" }

$OutputObj = [ordered]@{
    Etapa1_SondagemGeral = [ordered]@{
        TotalArquivosAnalisados = $AllFiles.Count
        ArquivosCodigoEmbarcado = $EmbeddedFiles.Count
        ArquivosBuildEFirmware = $BuildFiles.Count
        ArquivosBackendServicos = $BackendFiles.Count
        ArquivosInterfaceUI = $UiFiles.Count
        TecnologiasDetectadas = [ordered]@{
            RTOS_OS_SDK = @($RtosSdk)
            SistemasDeBuild = @($BuildSys)
            BibliotecasCripto = @($CryptoLibs)
            ProtocolosEServicos = @($Protocols)
            InterfacesHardware = @($HwInterfaces)
            Armazenamento = @($StorageFs)
        }
    }
    Etapa2_ClassificacaoSecao6_1 = [ordered]@{
        "1_Firmware_Codigo_Embarcado" = [ordered]@{ Ativo = $HasFw; ModulosAtivados = $FwMods }
        "2_Sistema_Build_Imagem_Firmware" = [ordered]@{ Ativo = $HasBuild; ModulosAtivados = $BuildMods }
        "3_Backend_Broker_Servicos_Dados" = [ordered]@{ Ativo = $HasDes; ModulosAtivados = $DesMods }
        "4_Aplicacao_Web_Painel_Mobile" = [ordered]@{ Ativo = ($HasUi -or $HasWrls); ModulosAtivados = $UiMods }
    }
    Etapa3_EstadoDoChecklist = $ChecklistStatus
    Etapa4_TriagemSecao6_2 = [ordered]@{
        Modulo1_SAST_e_Memoria = $Mod1Findings
        Modulo2_Segredos_Identidade_Cripto = $Mod2Findings
        Modulo3_Hardening_Build_Bootloader_UART = $Mod3Findings
        Modulo4_Atualizacao_Firmware_OTA = $Mod4Findings
        Modulo5_Servicos_Troca_Dados_Logica = $Mod5Findings
        Modulo6_SBOM_e_Dependencias = $Mod6Findings
    }
}

$OutputObj | ConvertTo-Json -Depth 6

