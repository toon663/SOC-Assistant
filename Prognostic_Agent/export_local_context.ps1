<# Instrumented wrapper for the reviewed local exporter. #>
[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputPath)
$ErrorActionPreference = 'Stop'
$agentRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$privateRoot = [IO.Path]::GetFullPath((Join-Path $agentRoot 'private'))
$destination = [IO.Path]::GetFullPath($OutputPath)
if (-not $destination.StartsWith($privateRoot + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Export output must stay in private/' }
$windowRoot = Join-Path $privateRoot 'activity-windows'
New-Item -ItemType Directory -Path $windowRoot -Force | Out-Null
$id = [Guid]::NewGuid().ToString('N')
$window = [ordered]@{schema_version=1;environment='test';kind='exporter';window_id=$id;host=[Net.Dns]::GetHostName();started_at=[DateTime]::UtcNow.ToString('o');ended_at=$null}
$record = Join-Path $windowRoot ($id + '.json')
$window | ConvertTo-Json | Set-Content -LiteralPath $record -Encoding UTF8
try { & (Join-Path $privateRoot 'tools/export_local_context.ps1') -OutputPath $destination }
finally { $window.ended_at=[DateTime]::UtcNow.ToString('o'); $window | ConvertTo-Json | Set-Content -LiteralPath $record -Encoding UTF8 }
