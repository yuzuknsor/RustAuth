# RustAuth GUI functional smoke via Windows UI Automation (egui accesskit)
# Preconditions: vault has RFC test entry (seed_vault), app not running.
# Checks: A window/entry/code  B copy to clipboard  C 30s auto-clear  D single instance
param([string]$Exe = "target\debug\rustauth.exe")

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName System.Windows.Forms

function Find-Win([int]$pid2, [string]$name, [int]$timeoutSec = 15) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $root = [System.Windows.Automation.AutomationElement]::RootElement
        $cond = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::ProcessIdProperty, $pid2)
        $win = $root.FindFirst([System.Windows.Automation.TreeScope]::Children, $cond)
        if ($win) { return $win }
    }
    throw "window not found: $name"
}

function All-Text($el) {
    $cond = New-Object System.Windows.Automation.PropertyCondition(
        [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
        [System.Windows.Automation.ControlType]::Text)
    $el.FindAll([System.Windows.Automation.TreeScope]::Descendants, $cond) |
        ForEach-Object { $_.Current.Name }
}

function Click-Button($el, [string]$btnName, [int]$timeoutSec = 10) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        $cond = New-Object System.Windows.Automation.PropertyCondition(
            [System.Windows.Automation.AutomationElement]::NameProperty, $btnName)
        $btn = $el.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $cond)
        if ($btn) {
            $inv = $btn.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
            $inv.Invoke(); return $true
        }
        Start-Sleep -Milliseconds 400
    }
    return $false
}

function Totp-Now([byte[]]$secret) {
    $t = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $counter = [UInt64][Math]::Floor($t / 30)
    $msg = [BitConverter]::GetBytes($counter); [Array]::Reverse($msg)
    $h = [System.Security.Cryptography.HMACSHA1]::new(); $h.Key = $secret
    $mac = $h.ComputeHash($msg)
    $off = $mac[19] -band 0x0F
    $v = (([uint32]$mac[$off] -shl 24) -bor ([uint32]$mac[$off+1] -shl 16) -bor ([uint32]$mac[$off+2] -shl 8) -bor [uint32]$mac[$off+3]) -band 0x7FFFFFFF
    ($v % 1000000).ToString('D6')
}

$secret = [byte[]]([Text.Encoding]::ASCII.GetBytes("12345678901234567890"))
$results = @()

# --- A: launch + window + code display ---
$p = Start-Process $Exe -PassThru
$win = Find-Win $p.Id "RustAuth"
$texts = All-Text $win
$entryShown = $texts | Where-Object { $_ -match '功能测试' }
$codeShown = $texts | Where-Object { $_ -match '^\d{6}$' } | Select-Object -First 1
if ($entryShown) { $results += "A1 entry shown: PASS" } else { $results += "A1 entry shown: FAIL ($($texts -join '|'))" }

$match = $false
for ($i = 0; $i -lt 3 -and -not $match; $i++) {
    $expected = Totp-Now $secret
    if ($codeShown -eq $expected) { $match = $true }
    else {
        Start-Sleep -Seconds 2
        $texts = All-Text $win
        $codeShown = ($texts | Where-Object { $_ -match '^\d{6}$' } | Select-Object -First 1)
    }
}
if ($match) { $results += "A2 code matches independent calc ($codeShown): PASS" }
else { $results += "A2 code compare: FAIL shown=$codeShown expected=$(Totp-Now $secret)" }

# --- B: copy button -> clipboard ---
Set-Clipboard -Value "init"
if (Click-Button $win "复制") {
    Start-Sleep -Milliseconds 800
    $clip = Get-Clipboard
    if ($clip -match '^\d{6}$') { $results += "B1 copied to clipboard ($clip): PASS" }
    else { $results += "B1 clipboard: FAIL clip='$clip'" }
} else { $results += "B1 copy button not found: FAIL" }

# --- C: 30s auto-clear ---
Start-Sleep -Seconds 33
$clip2 = Get-Clipboard
if ([string]::IsNullOrWhiteSpace($clip2)) { $results += "C1 clipboard auto-cleared: PASS" }
else { $results += "C1 clipboard auto-clear: FAIL still='$clip2'" }

# --- D: single instance ---
$p2 = Start-Process $Exe -PassThru
Start-Sleep -Seconds 2
$p2.Refresh()
if ($p2.HasExited) { $results += "D1 single instance mutex: PASS" }
else { $results += "D1 single instance: FAIL"; Stop-Process -Id $p2.Id -Force }

Stop-Process -Id $p.Id -Force
$results | ForEach-Object { Write-Output $_ }
if ($results -match 'FAIL') { exit 2 } else { Write-Output "ALL PASS" }
