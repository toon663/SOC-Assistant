# Read-only OS observations. Never returns event contents or machine identities.
param([string]$WindowPath)
$ErrorActionPreference = 'Stop'
$result = [ordered]@{elevated=$false; process_creation_success_on=$null; command_lines_on=$null; both_settings_on=$null; security_log=$null; backend_started_after_analyst=$null; matching_4688_count=$null; errors=@()}
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$result.elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
try {
    . (Join-Path $PSScriptRoot 'audit_policy_read.ps1')
    $result.process_creation_success_on = [bool]([PrognosticAuditRead]::ProcessCreation() -band 1)
} catch { $result.errors += 'audit_policy_unreadable' }
try {
    $key = $null
    try { $key = Get-Item 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' }
    catch [System.Management.Automation.ItemNotFoundException] { $key = $null }
    $result.command_lines_on = $null -ne $key -and $key.GetValue('ProcessCreationIncludeCmdLine_Enabled', 0) -eq 1
} catch { $result.errors += 'command_line_policy_unreadable' }
if ($null -ne $result.process_creation_success_on -and $null -ne $result.command_lines_on) {
    $result.both_settings_on = $result.process_creation_success_on -and $result.command_lines_on
}
try {
    $log = Get-WinEvent -ListLog Security
    $result.security_log = @{maximum_bytes=$log.MaximumSizeInBytes; current_file_bytes=$log.FileSize; record_count=$log.RecordCount; usage_percent=$null; usage_basis='allocated log file bytes, not occupied record bytes'}
    if ($log.MaximumSizeInBytes -gt 0) { $result.security_log.usage_percent = [Math]::Round(100.0 * $log.FileSize / $log.MaximumSizeInBytes, 2) }
} catch { $result.errors += 'security_log_metadata_unreadable' }
try {
    $listeners = @(Get-NetTCPConnection -LocalPort 8000 -State Listen)
    $ids = @($listeners | Select-Object -ExpandProperty OwningProcess -Unique)
    if ($ids.Count -ne 1) { throw 'Listener missing or ambiguous' }
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($ids[0])"
    # Do not treat an arbitrary listener as the backend.
    if ($process.CommandLine -notmatch 'uvicorn' -or $process.CommandLine -notmatch 'api:app') { throw 'Not the expected backend command' }
    $source = Get-Item (Join-Path $PSScriptRoot '../backend/analyst.py')
    $result.backend_started_after_analyst = $process.CreationDate.ToUniversalTime() -gt $source.LastWriteTimeUtc
} catch { $result.errors += 'backend_start_unverified' }
if ($WindowPath) {
    try {
        $window = Get-Content -LiteralPath $WindowPath -Raw | ConvertFrom-Json
        if ($window.kind -ne 'controlled_test' -or -not $window.ended_at) { throw 'Invalid window' }
        $start = [DateTimeOffset]::Parse($window.started_at).UtcDateTime
        $end = [DateTimeOffset]::Parse($window.ended_at).UtcDateTime
        $count = 0
        try { $events = @(Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=$start; EndTime=$end}) }
        catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { $events = @() }
            else { throw }
        }
        foreach ($event in $events) {
            [xml]$xml = $event.ToXml()
            foreach ($data in $xml.Event.EventData.Data) {
                if ($data.Name -eq 'CommandLine' -and ([string]$data.'#text').Contains([string]$window.encoded_command)) { $count++; break }
            }
        }
        $result.matching_4688_count = $count
    } catch { $result.errors += 'security_event_query_unreadable' }
}
$result | ConvertTo-Json -Depth 5 -Compress
