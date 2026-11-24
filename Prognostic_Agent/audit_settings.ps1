# Operator-run only. Never invoked by the checker or daily runner.
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidateSet('Backup','Enable','Restore')][string]$Action,
      [Parameter(Mandatory=$true)][string]$BackupDirectory)
$ErrorActionPreference = 'Stop'
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use elevated PowerShell' }
$privateRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'private')) + [IO.Path]::DirectorySeparatorChar
$destination = [IO.Path]::GetFullPath($BackupDirectory)
if (-not $destination.StartsWith($privateRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Backup must be under private/' }
$manifestPath = Join-Path $destination 'settings.clixml'
$keyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
$name = 'ProcessCreationIncludeCmdLine_Enabled'
$subcategory = '{0CCE922B-69AE-11D9-BED3-505054503030}'
. (Join-Path $PSScriptRoot 'audit_policy_read.ps1')
if ($Action -eq 'Backup') {
    if (Test-Path -LiteralPath $destination) { throw 'Choose a new backup directory; never overwrite a backup' }
    $flags = [PrognosticAuditRead]::ProcessCreation()
    $key = $null
    try { $key = Get-Item -LiteralPath $keyPath }
    catch [System.Management.Automation.ItemNotFoundException] { $key = $null }
    $exists = $null -ne $key -and $key.GetValueNames() -contains $name
    $snapshot = [ordered]@{Version=1; Machine=$env:COMPUTERNAME; CreatedUtc=[DateTime]::UtcNow.ToString('o'); AuditFlags=$flags; ValueExists=$exists; ValueKind=$null; Value=$null}
    if ($exists) {
        $snapshot.ValueKind = $key.GetValueKind($name).ToString()
        $snapshot.Value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    }
    New-Item -ItemType Directory -Path $destination | Out-Null
    & auditpol.exe /backup "/file:$(Join-Path $destination 'audit-policy.csv')" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Audit backup failed; no settings were changed' }
    $snapshot | Export-Clixml -LiteralPath $manifestPath
    Write-Output 'Both settings saved. No settings changed.'
    return
}
$saved = Import-Clixml -LiteralPath $manifestPath
if ($saved.Version -ne 1 -or $saved.Machine -ne $env:COMPUTERNAME -or $saved.AuditFlags -notin 0,1,2,3,4) { throw 'Invalid or different-machine backup' }
if ($Action -eq 'Enable') {
    & auditpol.exe /set "/subcategory:$subcategory" /success:enable | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Audit enable failed' }
    if (-not (Test-Path -LiteralPath $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
    New-ItemProperty -LiteralPath $keyPath -Name $name -PropertyType DWord -Value 1 -Force | Out-Null
    Write-Output 'Both settings enabled. Retain the backup for Restore.'
    return
}
# Restore only this subcategory, not unrelated changes from the full CSV snapshot.
$success = if ($saved.AuditFlags -band 1) { 'enable' } else { 'disable' }
$failure = if ($saved.AuditFlags -band 2) { 'enable' } else { 'disable' }
& auditpol.exe /set "/subcategory:$subcategory" "/success:$success" "/failure:$failure" | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Audit restore failed; registry not yet restored' }
if ($saved.ValueExists) {
    if (-not (Test-Path -LiteralPath $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
    $value = $saved.Value
    if ($saved.ValueKind -eq 'Binary') { $value = [byte[]]$value }
    if ($saved.ValueKind -eq 'MultiString') { $value = [string[]]$value }
    New-ItemProperty -LiteralPath $keyPath -Name $name -PropertyType $saved.ValueKind -Value $value -Force | Out-Null
} elseif (Test-Path -LiteralPath $keyPath) {
    $key = Get-Item -LiteralPath $keyPath
    if ($key.GetValueNames() -contains $name) { Remove-ItemProperty -LiteralPath $keyPath -Name $name }
}
Write-Output 'Saved process-creation flags and registry value/type/absence restored. Unrelated audit settings left unchanged.'
