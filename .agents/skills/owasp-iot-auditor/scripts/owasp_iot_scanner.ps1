<#
.SYNOPSIS
    OWASP IoT & Embedded Security Auditor - Helper Scanner Script (PowerShell)
.DESCRIPTION
    Executes the 4 automated support steps for the Agent:
    1. General Project Discovery of Artifacts and Technologies
    2. Software Functionalities Classification per Section 6.1 (SKILL.md, Step 2)
    3. State-Tracking Checklist Inspection/Initialization (where the agent stopped and where to go next)
    4. Automated Static Triage following strict Section 6.2 order (Modules 1 to 6)
#>
param(
    [string]$TargetDir = ".",
    [string]$ChecklistFile = "owasp_iot_progress_checklist.md",
    [string]$ReportFile = "owasp_iot_final_report.md",
    [string]$RemediationFile = "owasp_iot_remediation_plan.md",
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
        $Content = $Content.Replace("<PROJECT_NAME_OR_PATH>", $ProjectName).Replace("<YYYY-MM-DD HH:MM>", $Timestamp)
        Set-Content -Path $ChecklistPath -Value $Content -Encoding UTF8
    }
}

if ($InitRemediation -and -not (Test-Path $RemediationPath)) {
    $RemTemplatePath = Join-Path $PSScriptRoot "..\resources\remediation_tracker_template.md"
    if (Test-Path $RemTemplatePath) {
        $RemContent = Get-Content -Path $RemTemplatePath -Raw -Encoding UTF8
        $ProjectName = Split-Path $ResolvedTarget -Leaf
        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm"
        $RemContent = $RemContent.Replace("<PROJECT_NAME>", $ProjectName).Replace("<YYYY-MM-DD HH:MM>", $Timestamp)
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

    $Mode2Result = [ordered]@{
        Mode = "Mode 2 - Targeted Single-ID Verification"
        RequestedId = $TargetId
        RemediationPlanRecords = $RemediationMatches
        FinalReportRecords = $ReportMatches
        ChecklistRecords = $ChecklistMatches
        AgentInstruction = "Surgically inspect the files referenced for $TargetId, issue the verdict (PASS/PARTIAL/FAIL), and synchronize owasp_iot_remediation_plan.md, owasp_iot_final_report.md, and owasp_iot_progress_checklist.md."
    }
    $Mode2Result | ConvertTo-Json -Depth 5
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

# Step 2: Section 6.1 Classification
$HasFw = ($EmbeddedFiles.Count -gt 0) -or ($RtosSdk.Count -gt 0)
$HasBuild = ($BuildFiles.Count -gt 0)
$HasDes = ($BackendFiles.Count -gt 0) -or ($Protocols.Count -gt 0)
$HasUi = ($UiFiles.Count -gt 0)
$HasWrls = ($HwInterfaces | Where-Object { $_ -match "WRLS" }).Count -gt 0

# Step 3: Checklist State
$ChecklistStatus = [ordered]@{
    Exists = (Test-Path $ChecklistPath)
    Path = $ChecklistPath
    WhereAgentStopped = "No items completed yet (Start of Audit)"
    WhereAgentMustGoNext = "Initialize checklist (-InitChecklist) and start Module 1 (Embedded SAST & Memory Quality)"
    Counts = [ordered]@{ PASS = 0; PARTIAL = 0; FAIL = 0; NA = 0; PENDING = 0; OPTIONAL = 0 }
}

if (Test-Path $ChecklistPath) {
    $ChkLines = Get-Content -Path $ChecklistPath -Encoding UTF8
    $LastDone = $null
    $NextPending = $null
    foreach ($line in $ChkLines) {
        if ($line -match '^\|\s*`?((?:ISTG|EMB-APPSEC|FSTM-STAGE)-[A-Z0-9\[\]\-]+)`?\s*\|\s*([^|]+)\|\s*(Modules? [^|]+)\|\s*(?:[^|]+\|\s*)?`?(PASS|PARTIAL|FAIL|N/A|PENDING|OPTIONAL)`?\s*\|') {
            $Tid = $Matches[1].Trim()
            $Tname = $Matches[2].Trim()
            $Tmod = $Matches[3].Trim()
            $Tstat = $Matches[4].Trim()
            if ($Tstat -eq "N/A") { $ChecklistStatus.Counts.NA++ }
            else { $ChecklistStatus.Counts[$Tstat]++ }

            if ($Tstat -notin @("PENDING", "OPTIONAL")) {
                $LastDone = "$Tid ($Tmod) -> $Tstat"
            } elseif ($Tstat -eq "PENDING" -and $null -eq $NextPending) {
                $NextPending = "$Tid ($Tmod - $Tname)"
            }
        }
    }
    if ($LastDone) { $ChecklistStatus.WhereAgentStopped = $LastDone }
    if ($NextPending) { $ChecklistStatus.WhereAgentMustGoNext = $NextPending }
    else { $ChecklistStatus.WhereAgentMustGoNext = "All mandatory items completed! Ready to generate the Final Report (Step 5)." }
}

$FwMods = if ($HasFw) { @("ISTG-FW", "ISTG-MEM", "ISTG-PROC", "ISTG-INT[UART/I2C]", "Embedded AppSec") } else { @() }
$BuildMods = if ($HasBuild) { @("ISTG-FW-INFO-004", "ISTG-FW-CONF-002", "ISTG-FW[INST]-CRYPT-001", "ISTG-FW-CONF-001") } else { @() }
$DesMods = if ($HasDes) { @("ISTG-DES") } else { @() }
$UiMods = @()
if ($HasUi) { $UiMods += "ISTG-UI" }
if ($HasWrls) { $UiMods += "ISTG-WRLS" }

$OutputObj = [ordered]@{
    Step1_GeneralDiscovery = [ordered]@{
        TotalFilesScanned = $AllFiles.Count
        EmbeddedCodeFiles = $EmbeddedFiles.Count
        BuildAndFirmwareFiles = $BuildFiles.Count
        BackendServiceFiles = $BackendFiles.Count
        UiInterfaceFiles = $UiFiles.Count
        DetectedTechnologies = [ordered]@{
            RTOS_OS_SDK = @($RtosSdk)
            BuildSystems = @($BuildSys)
            CryptoLibraries = @($CryptoLibs)
            ProtocolsAndServices = @($Protocols)
            HardwareInterfaces = @($HwInterfaces)
            Storage = @($StorageFs)
        }
    }
    Step2_Section6_1Classification = [ordered]@{
        "1_Firmware_Embedded_Code" = [ordered]@{ Active = $HasFw; ActivatedModules = $FwMods }
        "2_Build_System_Firmware_Image" = [ordered]@{ Active = $HasBuild; ActivatedModules = $BuildMods }
        "3_Backend_Broker_Data_Services" = [ordered]@{ Active = $HasDes; ActivatedModules = $DesMods }
        "4_Web_App_Dashboard_Mobile" = [ordered]@{ Active = ($HasUi -or $HasWrls); ActivatedModules = $UiMods }
    }
    Step3_ChecklistState = $ChecklistStatus
    Step4_Section6_2Triage = [ordered]@{
        Module1_SAST_and_Memory = $Mod1Findings
        Module2_Secrets_Identity_Crypto = $Mod2Findings
        Module3_Hardening_Build_Bootloader_UART = $Mod3Findings
        Module4_Firmware_Update_OTA = $Mod4Findings
        Module5_Data_Exchange_Services_Logic = $Mod5Findings
        Module6_SBOM_and_Dependencies = $Mod6Findings
    }
}

$OutputObj | ConvertTo-Json -Depth 6
