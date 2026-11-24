<# Manual shadow run. Registers no task. Writes only under this agent's private/.
   The source database is read through a verified private file snapshot.
#>
[CmdletBinding()]
param(
    [string]$Python = 'python',
    [string]$ExporterPath,
    [string]$BackendDb,
    [ValidateRange(1,10000)][int]$Limit = 10000,
    [string]$WeekStart,
    [switch]$FreshOnly,
    [switch]$PlanOnly
)
$ErrorActionPreference = 'Stop'
$agentRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $ExporterPath) { $ExporterPath = Join-Path $agentRoot 'export_local_context.ps1' }
if (-not $BackendDb) { $BackendDb = Join-Path $agentRoot '../backend/soc_agents.db' }
$privateRoot = Join-Path $agentRoot 'private'
$overlayPath = Join-Path $privateRoot 'operator_overlay.json'
$historyPath = Join-Path $privateRoot 'shadow/forecast_history.db'
if ($PlanOnly) {
    [pscustomobject]@{environment='test';exporter_path=$ExporterPath;backend_source=$BackendDb;overlay_path=$overlayPath;history_path=$historyPath;registers_scheduled_task=$false;mode='plan_only_no_io'} | ConvertTo-Json
    exit 0
}
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffffffZ') + '_' + [Guid]::NewGuid().ToString('N').Substring(0,8)
$runDir = Join-Path $privateRoot ('daily/' + $runId)
$dailyStarted = [DateTime]::UtcNow.ToString('o')
$lockPath = Join-Path $privateRoot 'daily.lock'
$stage = 'initialization'
$priorBytecode = $env:PYTHONDONTWRITEBYTECODE
$env:PYTHONDONTWRITEBYTECODE = '1'
$lockStream = $null
$pushed = $false

function Invoke-PrivatePython {
    param([string]$Name, [string[]]$Arguments, [switch]$AllowFailure)
    $stderrPath = Join-Path $runDir ($Name + '.stderr.log')
    $stdoutPath = Join-Path $runDir ($Name + '.stdout.json')
    # Windows PowerShell promotes native stderr with ErrorActionPreference=Stop.
    # Capture it privately; decide success using the native exit code.
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $lines = @(& $Python -B @Arguments 2> $stderrPath); $nativeExit = $LASTEXITCODE }
    finally { $ErrorActionPreference = $savedPreference }
    $text = $lines -join [Environment]::NewLine
    [IO.File]::WriteAllText($stdoutPath, $text, [Text.UTF8Encoding]::new($false))
    if ($nativeExit -ne 0 -and -not $AllowFailure) { throw ($Name + ' failed; see its private stdout/stderr logs') }
    $parsed = $text | ConvertFrom-Json
    return [pscustomobject]@{ ExitCode=$nativeExit; Result=$parsed }
}

try {
    New-Item -ItemType Directory -Path $privateRoot -Force | Out-Null
    # Exclusive lock prevents overlapping hand runs from selecting the same work.
    $lockStream = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    $windowRoot = Join-Path $privateRoot 'activity-windows'
    New-Item -ItemType Directory -Path $windowRoot -Force | Out-Null
    [ordered]@{schema_version=1;environment='test';kind='daily_runner';window_id=$runId;host=[Net.Dns]::GetHostName();started_at=$dailyStarted;ended_at=$null} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $windowRoot ($runId + '_daily.json')) -Encoding UTF8
    New-Item -ItemType Directory -Path $runDir | Out-Null
    Push-Location (Split-Path -Parent $agentRoot)
    $pushed = $true
    if (-not (Test-Path -LiteralPath $overlayPath -PathType Leaf)) { throw 'Missing private/operator_overlay.json' }
    if (-not (Test-Path -LiteralPath $ExporterPath -PathType Leaf)) { throw 'Missing reviewed local exporter; set -ExporterPath' }
    $stage = 'exporter'
    $rawPath = Join-Path $runDir 'local_context_raw.json'
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $ExporterPath -OutputPath $rawPath 1> (Join-Path $runDir 'exporter.stdout.log') 2> (Join-Path $runDir 'exporter.stderr.log')
        $exportExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    if ($exportExit -ne 0) { throw 'Exporter failed; see private exporter logs' }
    $stage = 'importer'
    $importerStarted = [DateTime]::UtcNow.ToString('o')
    $imported = (Invoke-PrivatePython -Name 'importer' -Arguments @('-m','Prognostic_Agent.import_inventory','--adapter','local_export','--input',$rawPath,'--output-root',(Join-Path $runDir 'imports'),'--environment','test')).Result
    $windowRoot = Join-Path $privateRoot 'activity-windows'
    New-Item -ItemType Directory -Path $windowRoot -Force | Out-Null
    [ordered]@{schema_version=1;environment='test';kind='importer';window_id=($runId + '_importer');host=[Net.Dns]::GetHostName();started_at=$importerStarted;ended_at=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $windowRoot ($runId + '_importer.json')) -Encoding UTF8
    $stage = 'overlay'
    $effective = (Invoke-PrivatePython -Name 'overlay' -Arguments @('-m','Prognostic_Agent.operator_overlay','--inventory',$imported.inventory_path,'--overlay',$overlayPath,'--output-dir',(Join-Path $runDir 'effective-inventory'),'--environment','test')).Result
    $runTime = [DateTime]::UtcNow
    $inventoryHash = (Get-FileHash -LiteralPath $effective.inventory_path -Algorithm SHA256).Hash.ToLowerInvariant()
    $evaluationId = 'shadow:' + $runTime.ToString('yyyy-MM-dd') + ':inventory:' + $inventoryHash
    $asOf = $runTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'")
    $stage = 'batch'
    $batchArguments = @('-m','Prognostic_Agent.shadow_batch','--backend-db',$BackendDb,'--asset-inventory',$effective.inventory_path,'--history-db',$historyPath,'--output-dir',(Join-Path $runDir 'batch'),'--limit',[string]$Limit,'--evaluation-id',$evaluationId,'--as-of',$asOf,'--environment','test')
    if ($FreshOnly) { $batchArguments += '--fresh-only' }
    $batch = Invoke-PrivatePython -Name 'batch' -AllowFailure -Arguments $batchArguments
    $stage = 'weekly_report'
    $weeklyArguments = @('-m','Prognostic_Agent.weekly_report','--history-db',$historyPath,'--output-dir',(Join-Path $privateRoot 'weekly'),'--environment','test')
    if ($WeekStart) { $weeklyArguments += @('--week-start',$WeekStart) }
    $weekly = (Invoke-PrivatePython -Name 'weekly' -Arguments $weeklyArguments).Result
    $weeklyLegacy = (Invoke-PrivatePython -Name 'weekly_with_legacy' -Arguments ($weeklyArguments + '--include-legacy')).Result
    $stage = 'privacy_audit'
    $audit = (Invoke-PrivatePython -Name 'privacy' -Arguments @('-m','Prognostic_Agent.privacy_audit','--raw-export',$rawPath,'--output-dir',(Join-Path $runDir 'privacy'),'--environment','test')).Result
    $summary = [ordered]@{schema_version=1;environment='test';evaluation_id=$evaluationId;inventory_sha256=$inventoryHash;run_directory=$runDir;batch=$batch.Result;weekly=$weekly;weekly_with_legacy=$weeklyLegacy;privacy_audit=$audit}
    $summary | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath (Join-Path $runDir 'daily_summary.json') -Encoding UTF8
    # Full outputs stay private; console contains counts and artifact paths only.
    [pscustomobject]@{environment='test';run_directory=$runDir;evaluation_id=$evaluationId;processed_count=$batch.Result.processed_count;already_assessed_count=$batch.Result.already_assessed_count;fresh_incident_count=$batch.Result.fresh_incident_count;fresh_additive_fields_confirmed=$batch.Result.source_inspection.fresh_additive_fields_confirmed;status_counts=$batch.Result.status_counts;weekly_report=$weekly.report_file;weekly_with_legacy_report=$weeklyLegacy.report_file;privacy_clean=$audit.clean} | ConvertTo-Json -Depth 5
    exit $batch.ExitCode
} catch {
    if (-not $lockStream) { throw 'Another shadow runner owns the lock, or private/ is unavailable; no run started' }
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null
    $failurePath = Join-Path $runDir 'runner_error.json'
    [ordered]@{schema_version=1;environment='test';stage=$stage;detail=$_.Exception.Message;timestamp=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath $failurePath -Encoding UTF8
    & $Python -B -m Prognostic_Agent.shadow_batch --record-run-error $failurePath --history-db $historyPath --environment test 1> (Join-Path $runDir 'error_record.stdout.log') 2> (Join-Path $runDir 'error_record.stderr.log')
    throw ('Daily shadow run failed at ' + $stage + '; see ' + $failurePath)
} finally {
    if ($lockStream) {
        $windowRoot = Join-Path $privateRoot 'activity-windows'
        New-Item -ItemType Directory -Path $windowRoot -Force | Out-Null
        [ordered]@{schema_version=1;environment='test';kind='daily_runner';window_id=$runId;host=[Net.Dns]::GetHostName();started_at=$dailyStarted;ended_at=[DateTime]::UtcNow.ToString('o')} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $windowRoot ($runId + '_daily.json')) -Encoding UTF8
    }
    if ($pushed) { Pop-Location }
    if ($lockStream) { $lockStream.Dispose() }
    $env:PYTHONDONTWRITEBYTECODE = $priorBytecode
}
