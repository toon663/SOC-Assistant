"""Collect Windows Event Viewer logs for SOC sentinel-agent review.

Reads recent records from Event Viewer channels (Security, System, Application
by default) and writes them as structured JSON or XML that a downstream
anomaly-detection agent can consume.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from xml.dom import minidom


DEFAULT_LOGS = ("Security", "System", "Application")
EVENTS_DIR = Path(__file__).resolve().parent / "events"

# PowerShell reads env vars set by collect_log(), queries Event Viewer, and
# emits a JSON array of normalized event objects on stdout.
POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$cutoff = [DateTime]::Parse($env:EVENT_CUTOFF_UTC).ToUniversalTime()
$cutoffText = $cutoff.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
$xpath = "*[System[TimeCreated[@SystemTime >= '$cutoffText']]]"
$includeRawXml = $env:EVENT_INCLUDE_RAW_XML -eq '1'

function Convert-EventValue($value) {
	if ($null -eq $value) { return $null }
	if ($value -is [datetime]) { return $value.ToUniversalTime().ToString('o') }
	if ($value -is [System.Security.Principal.SecurityIdentifier]) { return $value.Value }
	if ($value -is [byte[]]) { return [Convert]::ToBase64String($value) }
	if ($value -is [System.Collections.IEnumerable] -and -not ($value -is [string])) {
		return @($value | ForEach-Object { Convert-EventValue $_ })
	}
	return [string]$value
}

try {
	$query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
		$env:EVENT_LOG_NAME,
		[System.Diagnostics.Eventing.Reader.PathType]::LogName,
		$xpath
	)
	$query.ReverseDirection = $true
	$reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)
	$events = [System.Collections.Generic.List[object]]::new()
	$record = $reader.ReadEvent()

	while ($null -ne $record -and $events.Count -lt [int]$env:EVENT_MAX_COUNT) {
		$eventData = @()
		foreach ($property in $record.Properties) {
			$eventData += ,(Convert-EventValue $property.Value)
		}

		$message = $null
		try { $message = $record.FormatDescription() } catch { }

		$userId = $null
		if ($null -ne $record.UserId) {
			try { $userId = $record.UserId.Value } catch { $userId = [string]$record.UserId }
		}

		$activityId = $null
		if ($null -ne $record.ActivityId -and $record.ActivityId -ne [guid]::Empty) {
			$activityId = $record.ActivityId.ToString()
		}

		$keywords = @()
		if ($null -ne $record.KeywordsDisplayNames) {
			$keywords = @($record.KeywordsDisplayNames)
		}

		$entry = [ordered]@{
			recordId = $record.RecordId
			timeCreatedUtc = if ($null -ne $record.TimeCreated) {
				$record.TimeCreated.ToUniversalTime().ToString('o')
			} else {
				$null
			}
			eventId = $record.Id
			provider = $record.ProviderName
			level = $record.Level
			levelName = $record.LevelDisplayName
			keywords = $keywords
			logName = $record.LogName
			machineName = $record.MachineName
			userId = $userId
			processId = $record.ProcessId
			threadId = $record.ThreadId
			task = $record.TaskDisplayName
			opcode = $record.OpcodeDisplayName
			activityId = $activityId
			message = $message
			eventData = $eventData
		}

		if ($includeRawXml) {
			$entry['rawXml'] = $record.ToXml()
		}

		[void]$events.Add($entry)
		$record.Dispose()
		$record = $reader.ReadEvent()
	}

	$reader.Dispose()
	ConvertTo-Json -InputObject @($events.ToArray()) -Depth 8 -Compress
}
catch {
	[Console]::Error.WriteLine($_.Exception.Message)
	exit 1
}
"""


def collect_log(
	log_name: str,
	cutoff: datetime,
	max_events: int,
	*,
	include_raw_xml: bool,
) -> list[dict[str, Any]]:
	"""Query one Event Viewer channel and return normalized event dicts."""
	powershell = shutil.which("pwsh") or shutil.which("powershell")
	if powershell is None:
		raise RuntimeError("PowerShell was not found. Install PowerShell or Windows PowerShell.")

	environment = {
		**os.environ,
		"EVENT_LOG_NAME": log_name,
		"EVENT_CUTOFF_UTC": cutoff.isoformat(),
		"EVENT_MAX_COUNT": str(max_events),
		"EVENT_INCLUDE_RAW_XML": "1" if include_raw_xml else "0",
	}
	result = subprocess.run(
		[powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", POWERSHELL_SCRIPT],
		capture_output=True,
		text=True,
		encoding="utf-8",
		errors="replace",
		env=environment,
		check=False,
	)
	if result.returncode:
		message = result.stderr.strip() or "PowerShell event-log query failed."
		if "unauthorized" in message.lower():
			message = (
				f"{message} Reading the '{log_name}' log usually requires an elevated "
				"(Administrator) PowerShell/terminal session."
			)
		raise RuntimeError(message)

	stdout = result.stdout.strip()
	if not stdout:
		return []

	try:
		events = json.loads(stdout)
	except json.JSONDecodeError as error:
		raise RuntimeError(f"Could not parse PowerShell output: {error}") from error
	if not isinstance(events, list):
		raise RuntimeError("PowerShell returned an unexpected event-log response.")
	return events


def _text(value: Any) -> str:
	if value is None:
		return ""
	if isinstance(value, (list, dict)):
		return json.dumps(value, ensure_ascii=False)
	return str(value)


def events_to_xml(document: dict[str, Any]) -> str:
	"""Serialize the collection document to indented XML."""
	root = ET.Element("EventCollection")
	root.set("schemaVersion", str(document["schemaVersion"]))

	meta = ET.SubElement(root, "Metadata")
	for key in (
		"collectedAtUtc",
		"computerName",
		"lookbackHours",
		"maxEventsPerLog",
		"eventCount",
		"format",
	):
		ET.SubElement(meta, key).text = _text(document[key])

	logs_el = ET.SubElement(meta, "logs")
	for log_name in document["logs"]:
		ET.SubElement(logs_el, "log").text = str(log_name)

	events_el = ET.SubElement(root, "Events")
	for event in document["events"]:
		event_el = ET.SubElement(events_el, "Event")
		for key, value in event.items():
			if key == "rawXml" and value:
				raw = ET.SubElement(event_el, "rawXml")
				raw.append(ET.fromstring(value))
				continue
			if key == "eventData":
				data_el = ET.SubElement(event_el, "eventData")
				for index, item in enumerate(value or []):
					item_el = ET.SubElement(data_el, "data")
					item_el.set("index", str(index))
					item_el.text = _text(item)
				continue
			if key == "keywords":
				keywords_el = ET.SubElement(event_el, "keywords")
				for keyword in value or []:
					ET.SubElement(keywords_el, "keyword").text = _text(keyword)
				continue
			ET.SubElement(event_el, key).text = _text(value)

	errors_el = ET.SubElement(root, "Errors")
	for error in document["errors"]:
		error_el = ET.SubElement(errors_el, "Error")
		ET.SubElement(error_el, "logName").text = _text(error.get("logName"))
		ET.SubElement(error_el, "message").text = _text(error.get("message"))

	rough = ET.tostring(root, encoding="utf-8")
	return minidom.parseString(rough).toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")


def positive_int(value: str) -> int:
	try:
		parsed = int(value)
	except ValueError as error:
		raise argparse.ArgumentTypeError("must be a positive integer") from error
	if parsed <= 0:
		raise argparse.ArgumentTypeError("must be a positive integer")
	return parsed


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Collect recent Windows Event Viewer logs as JSON or XML for SOC agents.",
	)
	parser.add_argument(
		"--logs",
		nargs="+",
		default=list(DEFAULT_LOGS),
		metavar="CHANNEL",
		help="event log channels to collect (default: Security System Application)",
	)
	parser.add_argument(
		"--hours",
		type=positive_int,
		default=24,
		help="lookback window in hours (default: 24)",
	)
	parser.add_argument(
		"--max-events-per-log",
		type=positive_int,
		default=500,
		help="maximum events collected per channel (default: 500)",
	)
	parser.add_argument(
		"--format",
		choices=("json", "xml"),
		default="json",
		help="output format for the sentinel agent (default: json)",
	)
	parser.add_argument(
		"--include-raw-xml",
		action="store_true",
		help="embed each event's original Event Viewer XML inside the payload",
	)
	parser.add_argument(
		"--output",
		type=Path,
		help="write output to this path (default: events/events_<timestamp>.json|xml)",
	)
	parser.add_argument(
		"--stdout",
		action="store_true",
		help="print to standard output instead of writing under the events/ folder",
	)
	return parser.parse_args()


def default_output_path(output_format: str) -> Path:
	stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
	return EVENTS_DIR / f"events_{stamp}.{output_format}"


def build_document(args: argparse.Namespace) -> dict[str, Any]:
	collected_at = datetime.now(timezone.utc)
	cutoff = collected_at - timedelta(hours=args.hours)
	all_events: list[dict[str, Any]] = []
	errors: list[dict[str, str]] = []

	for log_name in args.logs:
		try:
			all_events.extend(
				collect_log(
					log_name,
					cutoff,
					args.max_events_per_log,
					include_raw_xml=args.include_raw_xml,
				)
			)
		except (OSError, RuntimeError) as error:
			errors.append({"logName": log_name, "message": str(error)})

	all_events.sort(key=lambda event: event.get("timeCreatedUtc") or "")

	return {
		"schemaVersion": 1,
		"collectedAtUtc": collected_at.isoformat(),
		"computerName": platform.node(),
		"lookbackHours": args.hours,
		"maxEventsPerLog": args.max_events_per_log,
		"logs": list(args.logs),
		"format": args.format,
		"eventCount": len(all_events),
		"events": all_events,
		"errors": errors,
	}


def render_document(document: dict[str, Any], output_format: str) -> str:
	if output_format == "xml":
		return events_to_xml(document)
	return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
	args = parse_args()
	if platform.system() != "Windows":
		print("This collector can only run on Windows.", file=sys.stderr)
		return 2

	document = build_document(args)
	output = render_document(document, args.format)

	try:
		if args.stdout:
			print(output, end="")
		else:
			if args.output is None:
				output_path = default_output_path(args.format)
			elif args.output.is_absolute() or len(args.output.parts) > 1:
				output_path = args.output
			else:
				# Bare filenames land in events/ so agent inputs stay colocated.
				output_path = EVENTS_DIR / args.output
			output_path.parent.mkdir(parents=True, exist_ok=True)
			output_path.write_text(output, encoding="utf-8")
			print(
				f"Wrote {document['eventCount']} events to {output_path}",
				file=sys.stderr,
			)
			if document["errors"]:
				print(f"Completed with {len(document['errors'])} channel error(s).", file=sys.stderr)
	except OSError as error:
		print(f"Could not write output: {error}", file=sys.stderr)
		return 1

	# Partial success (some channels failed) is still useful for the sentinel agent.
	return 1 if document["errors"] and not document["events"] else 0


if __name__ == "__main__":
	raise SystemExit(main())
