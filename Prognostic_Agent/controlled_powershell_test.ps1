<# Confirmation-gated inert test. Never invoked by the agent or daily runner. #>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$agentRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$payload = "Write-Output 'prognostic-controlled-test'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
Write-Host 'This starts ONE hidden Windows PowerShell process with an encoded inert Write-Output command.'
Write-Host 'Flags: -EncodedCommand, -WindowStyle Hidden, -ExecutionPolicy Bypass, -NoProfile.'
Write-Host ('Decoded payload: ' + $payload)
Write-Host 'Only the activity window and captured output are written under Prognostic_Agent/private/.'
if ((Read-Host 'Type RUN PROGNOSTIC CONTROLLED TEST to proceed') -cne 'RUN PROGNOSTIC CONTROLLED TEST') {
    Write-Host 'Cancelled; no test process started.'
    return
}
$windowRoot = Join-Path $agentRoot 'private/activity-windows'
New-Item -ItemType Directory -Path $windowRoot -Force | Out-Null
$windowId = [Guid]::NewGuid().ToString('N')
$window = [ordered]@{schema_version=1;environment='test';kind='controlled_test';window_id=$windowId;host=[Net.Dns]::GetHostName();started_at=[DateTime]::UtcNow.ToString('o');ended_at=$null;payload=$payload;encoded_command=$encoded;child_pid=$null;exit_code=$null}
$windowPath = Join-Path $windowRoot ($windowId + '.json')
$window | ConvertTo-Json | Set-Content -LiteralPath $windowPath -Encoding UTF8
try {
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList @('-NoProfile','-NonInteractive','-EncodedCommand',$encoded,'-WindowStyle','Hidden','-ExecutionPolicy','Bypass') -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput (Join-Path $windowRoot ($windowId + '.stdout.txt')) -RedirectStandardError (Join-Path $windowRoot ($windowId + '.stderr.txt'))
    $window.child_pid = $process.Id
    $window.exit_code = $process.ExitCode
} finally {
    $window.ended_at = [DateTime]::UtcNow.ToString('o')
    $window | ConvertTo-Json | Set-Content -LiteralPath $windowPath -Encoding UTF8
}
Write-Host ('Test finished. Private activity record: ' + $windowPath)
