"""Download and cache public threat-intel sources for Random Forest training.

Sources:
  - MITRE ATT&CK Enterprise STIX (Windows analytics -> EventCode + techniques)
  - MITRE CAR analytics YAML (EventID / ATT&CK coverage)
  - CISA Known Exploited Vulnerabilities (KEV) catalog (CVE / product keywords)
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


AGENT_DIR = Path(__file__).resolve().parent
DEFAULT_CACHE_DIR = AGENT_DIR / "intel_cache"
CATALOG_PATH = DEFAULT_CACHE_DIR / "threat_intel_catalog.json"

ATTACK_STIX_URL = (
	"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
	"enterprise-attack/enterprise-attack.json"
)
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CAR_TREE_URL = "https://api.github.com/repos/mitre-attack/car/git/trees/master?recursive=1"
CAR_RAW_BASE = "https://raw.githubusercontent.com/mitre-attack/car/master/"

EVENT_CODE_RE = re.compile(r"EventCode\s*=\s*(\d+)", re.I)
EVENT_ID_RE = re.compile(r"(?:EventID|event_id|Event ID)\s*=?\s*(\d+)", re.I)
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Native Event Viewer channels collected by Event_Gatherer.
NATIVE_LOGS = {"Security", "System", "Application"}

LOG_ALIASES = {
	"security": "Security",
	"wineventlog:security": "Security",
	"system": "System",
	"wineventlog:system": "System",
	"application": "Application",
	"wineventlog:application": "Application",
	"powershell": "Windows PowerShell",
	"microsoft-windows-powershell/operational": "Microsoft-Windows-PowerShell/Operational",
	"sysmon": "Microsoft-Windows-Sysmon/Operational",
	"wineventlog:sysmon": "Microsoft-Windows-Sysmon/Operational",
	"microsoft-windows-sysmon/operational": "Microsoft-Windows-Sysmon/Operational",
}


@dataclass
class ThreatIntelCatalog:
	fetchedAtUtc: str
	sources: dict[str, Any] = field(default_factory=dict)
	# "Security:4625" -> ["T1110", ...]
	eventTechniques: dict[str, list[str]] = field(default_factory=dict)
	# Event IDs that appear on native Windows logs in MITRE/CAR (plus seed IDs).
	suspiciousEventIds: list[int] = field(default_factory=list)
	cisaKeywords: list[str] = field(default_factory=list)
	cisaCves: list[str] = field(default_factory=list)
	stats: dict[str, int] = field(default_factory=dict)

	def suspicious_id_set(self) -> set[int]:
		return set(self.suspiciousEventIds)

	def techniques_for(self, event_id: int, log_name: str | None = None) -> list[str]:
		techniques: list[str] = []
		seen: set[str] = set()
		keys: list[str] = []
		if log_name:
			keys.append(f"{log_name}:{event_id}")
		# Wildcard matches are only safe for classic Windows Event IDs (>= 100).
		# Low IDs collide with Sysmon codes (1-25) across unrelated channels.
		if event_id >= 100:
			keys.append(f"*:{event_id}")
		for key in keys:
			for technique in self.eventTechniques.get(key, []):
				if technique not in seen:
					seen.add(technique)
					techniques.append(technique)
		return techniques

	def matches_cisa(self, message: str, *, limit: int = 5) -> list[dict[str, str]]:
		text = message or ""
		if not text:
			return []
		lower = text.lower()
		hits: list[dict[str, str]] = []
		for cve in self.cisaCves:
			if cve.lower() in lower:
				hits.append({"type": "cve", "value": cve})
				if len(hits) >= limit:
					return hits
		for keyword in self.cisaKeywords:
			if keyword.lower() in lower:
				hits.append({"type": "keyword", "value": keyword})
				if len(hits) >= limit:
					return hits
		return hits


def _http_get_json(url: str, *, timeout: int = 120) -> Any:
	request = urllib.request.Request(
		url,
		headers={
			"User-Agent": "SOC-Assistant-Sentinel/1.0 (academic; ENGR295)",
			"Accept": "application/json",
		},
	)
	with urllib.request.urlopen(request, timeout=timeout) as response:
		return json.load(response)


def _http_get_text(url: str, *, timeout: int = 60) -> str:
	request = urllib.request.Request(
		url,
		headers={"User-Agent": "SOC-Assistant-Sentinel/1.0 (academic; ENGR295)"},
	)
	with urllib.request.urlopen(request, timeout=timeout) as response:
		return response.read().decode("utf-8", errors="replace")


def _normalize_log_name(value: str) -> str | None:
	cleaned = (value or "").strip()
	if not cleaned:
		return None
	alias = LOG_ALIASES.get(cleaned.lower())
	if alias:
		return alias
	# "WinEventLog:Security" already handled; also accept plain channel names.
	if ":" in cleaned:
		tail = cleaned.split(":", 1)[1].strip()
		alias = LOG_ALIASES.get(tail.lower())
		if alias:
			return alias
		if tail.lower() == "security":
			return "Security"
	return cleaned


def _add_mapping(
	bucket: dict[str, set[str]],
	*,
	event_id: int,
	log_name: str | None,
	techniques: set[str],
) -> None:
	keys: list[str] = []
	if log_name:
		keys.append(f"{log_name}:{event_id}")
	# Only publish wildcard keys for classic Windows Event IDs.
	if event_id >= 100:
		keys.append(f"*:{event_id}")
	for key in keys:
		bucket[key].update(techniques)


def _parse_attack_stix(bundle: dict[str, Any]) -> tuple[dict[str, set[str]], set[int], dict[str, int]]:
	objects = bundle.get("objects") or []
	by_id = {obj["id"]: obj for obj in objects if "id" in obj}

	strategy_to_tech: dict[str, set[str]] = defaultdict(set)
	for rel in objects:
		if rel.get("type") != "relationship" or rel.get("relationship_type") != "detects":
			continue
		target = by_id.get(rel.get("target_ref"), {})
		if target.get("type") != "attack-pattern":
			continue
		techs = {
			ref["external_id"]
			for ref in target.get("external_references") or []
			if ref.get("source_name") == "mitre-attack"
			and str(ref.get("external_id", "")).startswith("T")
		}
		strategy_to_tech[rel.get("source_ref")].update(techs)

	analytic_to_strategy: dict[str, set[str]] = defaultdict(set)
	for strategy in objects:
		if strategy.get("type") != "x-mitre-detection-strategy":
			continue
		for analytic_ref in strategy.get("x_mitre_analytic_refs") or []:
			analytic_to_strategy[analytic_ref].add(strategy["id"])

	mappings: dict[str, set[str]] = defaultdict(set)
	native_ids: set[int] = set()
	windows_analytics = 0

	for analytic in objects:
		if analytic.get("type") != "x-mitre-analytic":
			continue
		if "Windows" not in (analytic.get("x_mitre_platforms") or []):
			continue
		windows_analytics += 1

		techs: set[str] = set()
		for strategy_id in analytic_to_strategy.get(analytic["id"], set()):
			techs.update(strategy_to_tech.get(strategy_id, set()))

		for source in analytic.get("x_mitre_log_source_references") or []:
			name = str(source.get("name") or "")
			channel = str(source.get("channel") or "")
			blob = f"{name} {channel}"
			event_ids = [int(value) for value in EVENT_CODE_RE.findall(blob)]
			if not event_ids:
				continue
			log_name = _normalize_log_name(name)
			for event_id in event_ids:
				_add_mapping(mappings, event_id=event_id, log_name=log_name, techniques=techs)
				if log_name in NATIVE_LOGS or (log_name is None and event_id >= 100):
					native_ids.add(event_id)
				elif event_id >= 100:
					# Classic Windows Event IDs even when channel text is incomplete.
					native_ids.add(event_id)

	stats = {
		"attackWindowsAnalytics": windows_analytics,
		"attackMappedKeys": len(mappings),
		"attackNativeEventIds": len(native_ids),
	}
	return mappings, native_ids, stats


def _parse_car_analytics(cache_dir: Path) -> tuple[dict[str, set[str]], set[int], dict[str, int]]:
	mappings: dict[str, set[str]] = defaultdict(set)
	native_ids: set[int] = set()
	fetched = 0
	errors = 0

	tree = _http_get_json(CAR_TREE_URL, timeout=60)
	yaml_paths = [
		item["path"]
		for item in tree.get("tree", [])
		if item.get("path", "").startswith("analytics/") and item.get("path", "").endswith(".yaml")
	]

	car_cache = cache_dir / "car_analytics"
	car_cache.mkdir(parents=True, exist_ok=True)

	for relative in yaml_paths:
		local_path = car_cache / Path(relative).name
		try:
			if local_path.exists():
				text = local_path.read_text(encoding="utf-8")
			else:
				text = _http_get_text(CAR_RAW_BASE + relative)
				local_path.write_text(text, encoding="utf-8")
			fetched += 1
		except (urllib.error.URLError, OSError, TimeoutError):
			errors += 1
			continue

		techniques = set(TECHNIQUE_RE.findall(text))
		# Prefer explicit coverage technique lines when present.
		for match in re.finditer(r"technique:\s*(T\d{4}(?:\.\d{3})?)", text):
			techniques.add(match.group(1))

		event_ids = {int(value) for value in EVENT_ID_RE.findall(text)}
		event_ids.update(int(value) for value in EVENT_CODE_RE.findall(text))

		log_name = None
		lower = text.lower()
		if "security" in lower and "event" in lower:
			log_name = "Security"
		elif "sysmon" in lower:
			log_name = "Microsoft-Windows-Sysmon/Operational"

		for event_id in event_ids:
			_add_mapping(mappings, event_id=event_id, log_name=log_name, techniques=techniques)
			if event_id >= 100:
				native_ids.add(event_id)

	stats = {
		"carAnalyticsFetched": fetched,
		"carAnalyticsErrors": errors,
		"carNativeEventIds": len(native_ids),
	}
	return mappings, native_ids, stats


def _parse_cisa_kev(payload: dict[str, Any]) -> tuple[list[str], list[str], dict[str, int]]:
	vulnerabilities = payload.get("vulnerabilities") or []
	cves: list[str] = []
	keywords: set[str] = set()

	for item in vulnerabilities:
		cve = str(item.get("cveID") or "").strip()
		if cve:
			cves.append(cve)
		for key in ("vendorProject", "product", "vulnerabilityName"):
			value = str(item.get(key) or "").strip()
			if len(value) >= 4:
				keywords.add(value)
		if str(item.get("knownRansomwareCampaignUse") or "").lower() == "known":
			# Lightweight ransomware cue for message matching.
			keywords.add("ransomware")
		description = str(item.get("shortDescription") or "")
		for token in re.findall(r"\b[A-Za-z][A-Za-z0-9+._-]{3,}\b", description):
			if token.lower() in {"with", "that", "this", "from", "have", "been", "using", "allows"}:
				continue
			if token.isupper() and len(token) >= 4:
				keywords.add(token)

	# Keep keyword set bounded for fast scans.
	keyword_list = sorted(keywords, key=len, reverse=True)[:400]
	stats = {"cisaKevCount": len(vulnerabilities), "cisaKeywords": len(keyword_list)}
	return cves, keyword_list, stats


def build_catalog(*, cache_dir: Path = DEFAULT_CACHE_DIR, include_car: bool = True) -> ThreatIntelCatalog:
	cache_dir.mkdir(parents=True, exist_ok=True)

	attack_path = cache_dir / "enterprise-attack.json"
	kev_path = cache_dir / "cisa_kev.json"

	print("Fetching MITRE ATT&CK Enterprise STIX...", flush=True)
	attack = _http_get_json(ATTACK_STIX_URL)
	attack_path.write_text(json.dumps(attack), encoding="utf-8")
	attack_map, attack_ids, attack_stats = _parse_attack_stix(attack)

	print("Fetching CISA Known Exploited Vulnerabilities catalog...", flush=True)
	kev = _http_get_json(CISA_KEV_URL)
	kev_path.write_text(json.dumps(kev), encoding="utf-8")
	cves, keywords, kev_stats = _parse_cisa_kev(kev)

	combined: dict[str, set[str]] = defaultdict(set)
	for key, techs in attack_map.items():
		combined[key].update(techs)
	native_ids = set(attack_ids)
	car_stats: dict[str, int] = {}

	if include_car:
		print("Fetching MITRE CAR analytics...", flush=True)
		try:
			car_map, car_ids, car_stats = _parse_car_analytics(cache_dir)
			for key, techs in car_map.items():
				combined[key].update(techs)
			native_ids.update(car_ids)
		except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as error:
			print(f"CAR fetch skipped: {error}", flush=True)
			car_stats = {"carAnalyticsFetched": 0, "carAnalyticsErrors": 1}

	catalog = ThreatIntelCatalog(
		fetchedAtUtc=datetime.now(timezone.utc).isoformat(),
		sources={
			"mitreAttack": ATTACK_STIX_URL,
			"mitreCar": "https://github.com/mitre-attack/car",
			"cisaKev": CISA_KEV_URL,
		},
		eventTechniques={key: sorted(values) for key, values in sorted(combined.items())},
		suspiciousEventIds=sorted(native_ids),
		cisaKeywords=keywords,
		cisaCves=cves,
		stats={**attack_stats, **kev_stats, **car_stats, "totalMappedKeys": len(combined)},
	)
	save_catalog(catalog, CATALOG_PATH)
	print(
		f"Threat intel ready: {catalog.stats.get('totalMappedKeys', 0)} event mappings, "
		f"{len(catalog.suspiciousEventIds)} suspicious Event IDs, "
		f"{len(catalog.cisaCves)} CISA CVEs.",
		flush=True,
	)
	return catalog


def save_catalog(catalog: ThreatIntelCatalog, path: Path = CATALOG_PATH) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	path.write_text(json.dumps(asdict(catalog), indent=2) + "\n", encoding="utf-8")


def load_catalog(path: Path = CATALOG_PATH) -> ThreatIntelCatalog | None:
	if not path.exists():
		return None
	payload = json.loads(path.read_text(encoding="utf-8"))
	return ThreatIntelCatalog(**payload)


def get_catalog(*, refresh: bool = False, include_car: bool = True) -> ThreatIntelCatalog:
	if refresh:
		return build_catalog(include_car=include_car)
	cached = load_catalog()
	if cached is not None:
		return cached
	return build_catalog(include_car=include_car)


def main() -> int:
	import argparse

	parser = argparse.ArgumentParser(description="Refresh MITRE/CISA threat-intel cache for the sentinel agent.")
	parser.add_argument("--skip-car", action="store_true", help="skip MITRE CAR YAML download (faster)")
	args = parser.parse_args()
	build_catalog(include_car=not args.skip_car)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
