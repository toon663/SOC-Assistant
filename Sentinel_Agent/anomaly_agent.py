"""Sentinel anomaly-detection agent using Random Forest classifier.

Reads Event Viewer events produced by gatherer.py, scores each record for
cybersecurity anomalies, and writes structured anomaly events for downstream
SOC agents.

Training labels are weak-supervised from:
  - MITRE ATT&CK Windows analytics (EventCode -> technique mappings)
  - MITRE CAR analytics
  - CISA Known Exploited Vulnerabilities (KEV) message cues
  - local severity / message heuristics
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from threat_intel import ThreatIntelCatalog, get_catalog


AGENT_DIR = Path(__file__).resolve().parent
DEFAULT_EVENTS_DIR = AGENT_DIR.parent / "Event_Gatherer" / "events"
DEFAULT_OUTPUT_DIR = AGENT_DIR / "anomalies"
DEFAULT_MODEL_PATH = AGENT_DIR / "models" / "random_forest_anomaly.joblib"

# Fallback seed list used when threat-intel cache is unavailable.
SEED_SUSPICIOUS_EVENT_IDS: set[int] = {
	1102,
	4616,
	4625,
	4648,
	4672,
	4688,
	4697,
	4698,
	4720,
	4722,
	4728,
	4732,
	4756,
	4768,
	4769,
	4771,
	4776,
	7045,
	104,
}

SUSPICIOUS_MESSAGE_PATTERNS = (
	re.compile(r"failed\s+logon", re.I),
	re.compile(r"audit\s+(log\s+)?cleared", re.I),
	re.compile(r"privilege", re.I),
	re.compile(r"ransomware|mimikatz|cobalt\s*strike|powershell\s+-enc", re.I),
	re.compile(r"access\s+is\s+denied", re.I),
)

FEATURE_COLUMNS = [
	"eventId",
	"level",
	"processId",
	"threadId",
	"hourUtc",
	"weekdayUtc",
	"hasUserId",
	"messageLength",
	"eventDataCount",
	"keywordCount",
	"suspiciousEventId",
	"suspiciousMessage",
	"mitreMapped",
	"cisaHit",
	"providerCode",
	"logNameCode",
	"taskCode",
	"opcodeCode",
]


def _json_safe(value: Any) -> Any:
	"""Convert pandas/numpy nulls so anomaly JSON stays standards-compliant."""
	if value is None:
		return None
	try:
		if pd.isna(value):
			return None
	except (TypeError, ValueError):
		pass
	if isinstance(value, (np.integer,)):
		return int(value)
	if isinstance(value, (np.floating,)):
		return float(value)
	return value


def load_event_document(path: Path) -> dict[str, Any]:
	with path.open(encoding="utf-8") as handle:
		document = json.load(handle)
	if not isinstance(document, dict) or "events" not in document:
		raise ValueError(f"{path} is not a gatherer event document.")
	return document


def latest_event_file(events_dir: Path) -> Path:
	candidates = sorted(events_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
	preferred = [path for path in candidates if path.name.startswith("events_")]
	pool = preferred or candidates
	if not pool:
		raise FileNotFoundError(f"No JSON event files found in {events_dir}")
	return pool[0]


def _safe_int(value: Any, default: int = 0) -> int:
	try:
		if value is None:
			return default
		return int(value)
	except (TypeError, ValueError):
		return default


def _parse_timestamp(value: Any) -> datetime | None:
	if not value or not isinstance(value, str):
		return None
	try:
		return datetime.fromisoformat(value.replace("Z", "+00:00"))
	except ValueError:
		return None


def suspicious_event_ids(catalog: ThreatIntelCatalog | None) -> set[int]:
	ids = set(SEED_SUSPICIOUS_EVENT_IDS)
	if catalog is not None:
		ids.update(catalog.suspicious_id_set())
	return ids


def weak_label(
	event: dict[str, Any],
	*,
	catalog: ThreatIntelCatalog | None,
	suspicious_ids: set[int],
) -> int:
	"""Return 1 for heuristic / intel-backed anomaly, else 0."""
	event_id = _safe_int(event.get("eventId"))
	level = _safe_int(event.get("level"), default=4)
	message = str(event.get("message") or "")
	log_name = str(event.get("logName") or "")

	if event_id in suspicious_ids:
		return 1
	if catalog is not None and catalog.techniques_for(event_id, log_name):
		return 1
	if catalog is not None and catalog.matches_cisa(message):
		return 1
	if level in {1, 2}:
		return 1
	if any(pattern.search(message) for pattern in SUSPICIOUS_MESSAGE_PATTERNS):
		return 1
	return 0


def encode_categorical(
	series: pd.Series,
	encoder: LabelEncoder | None = None,
) -> tuple[np.ndarray, LabelEncoder]:
	values = series.fillna("").astype(str)
	if encoder is None:
		encoder = LabelEncoder()
		encoder.fit(list(values) + ["__unknown__"])
	known = set(encoder.classes_)
	normalized = values.map(lambda item: item if item in known else "__unknown__")
	return encoder.transform(normalized), encoder


def events_to_frame(
	events: list[dict[str, Any]],
	*,
	catalog: ThreatIntelCatalog | None,
) -> pd.DataFrame:
	suspicious_ids = suspicious_event_ids(catalog)
	rows: list[dict[str, Any]] = []

	for index, event in enumerate(events):
		timestamp = _parse_timestamp(event.get("timeCreatedUtc"))
		message = str(event.get("message") or "")
		keywords = event.get("keywords") or []
		event_data = event.get("eventData") or []
		event_id = _safe_int(event.get("eventId"))
		log_name = str(event.get("logName") or "")
		techniques = catalog.techniques_for(event_id, log_name) if catalog else []
		cisa_hits = catalog.matches_cisa(message) if catalog else []

		rows.append(
			{
				"_index": index,
				"recordId": event.get("recordId"),
				"timeCreatedUtc": event.get("timeCreatedUtc"),
				"eventId": event_id,
				"level": _safe_int(event.get("level"), default=4),
				"levelName": event.get("levelName"),
				"provider": event.get("provider") or "",
				"logName": log_name,
				"task": event.get("task") or "",
				"opcode": event.get("opcode") or "",
				"processId": _safe_int(event.get("processId")),
				"threadId": _safe_int(event.get("threadId")),
				"hourUtc": timestamp.hour if timestamp else -1,
				"weekdayUtc": timestamp.weekday() if timestamp else -1,
				"hasUserId": 1 if event.get("userId") else 0,
				"messageLength": len(message),
				"eventDataCount": len(event_data) if isinstance(event_data, list) else 0,
				"keywordCount": len(keywords) if isinstance(keywords, list) else 0,
				"suspiciousEventId": 1 if event_id in suspicious_ids else 0,
				"suspiciousMessage": 1
				if any(pattern.search(message) for pattern in SUSPICIOUS_MESSAGE_PATTERNS)
				else 0,
				"mitreMapped": 1 if techniques else 0,
				"cisaHit": 1 if cisa_hits else 0,
				"mitreTechniques": techniques,
				"cisaMatches": cisa_hits,
				"message": message,
				"userId": event.get("userId"),
				"machineName": event.get("machineName"),
				"weakLabel": weak_label(event, catalog=catalog, suspicious_ids=suspicious_ids),
				"rawEvent": event,
			}
		)
	return pd.DataFrame(rows)


def synthesize_intel_training_rows(catalog: ThreatIntelCatalog) -> pd.DataFrame:
	"""Create synthetic labeled rows from MITRE/CISA event mappings for RF training."""
	rows: list[dict[str, Any]] = []
	for key, techniques in catalog.eventTechniques.items():
		log_name, event_id_text = key.split(":", 1)
		try:
			event_id = int(event_id_text)
		except ValueError:
			continue
		if log_name == "*":
			if event_id < 100:
				continue
			log_name = "Security"
		# Skip Sysmon-only low IDs; Event_Gatherer collects native channels by default.
		if event_id < 100 and log_name not in {"Security", "System", "Application"}:
			continue
		rows.append(
			{
				"_index": -1,
				"recordId": None,
				"timeCreatedUtc": None,
				"eventId": event_id,
				"level": 2 if event_id in {1102, 4625, 7045, 104} else 3,
				"levelName": "Warning",
				"provider": "threat-intel-synthetic",
				"logName": log_name if log_name != "*" else "Security",
				"task": "intel",
				"opcode": "",
				"processId": 0,
				"threadId": 0,
				"hourUtc": 3,
				"weekdayUtc": 0,
				"hasUserId": 1,
				"messageLength": 80,
				"eventDataCount": 2,
				"keywordCount": 1,
				"suspiciousEventId": 1,
				"suspiciousMessage": 0,
				"mitreMapped": 1 if techniques else 0,
				"cisaHit": 0,
				"mitreTechniques": techniques,
				"cisaMatches": [],
				"message": f"synthetic training sample for Event ID {event_id}",
				"userId": None,
				"machineName": "intel-lab",
				"weakLabel": 1,
				"rawEvent": {},
			}
		)

	# Benign anchors so the forest sees a clear negative class.
	for event_id, log_name in (
		(4634, "Security"),
		(4624, "Security"),
		(7036, "System"),
		(1000, "Application"),
	):
		rows.append(
			{
				"_index": -1,
				"recordId": None,
				"timeCreatedUtc": None,
				"eventId": event_id,
				"level": 4,
				"levelName": "Information",
				"provider": "threat-intel-benign",
				"logName": log_name,
				"task": "",
				"opcode": "",
				"processId": 1000,
				"threadId": 1000,
				"hourUtc": 14,
				"weekdayUtc": 2,
				"hasUserId": 1,
				"messageLength": 40,
				"eventDataCount": 1,
				"keywordCount": 0,
				"suspiciousEventId": 0,
				"suspiciousMessage": 0,
				"mitreMapped": 0,
				"cisaHit": 0,
				"mitreTechniques": [],
				"cisaMatches": [],
				"message": "synthetic benign sample",
				"userId": None,
				"machineName": "intel-lab",
				"weakLabel": 0,
				"rawEvent": {},
			}
		)
	return pd.DataFrame(rows)


def build_feature_matrix(
	frame: pd.DataFrame,
	encoders: dict[str, LabelEncoder] | None = None,
) -> tuple[pd.DataFrame, dict[str, LabelEncoder]]:
	encoders = dict(encoders or {})
	features = frame.copy()

	for column, key in (
		("provider", "providerCode"),
		("logName", "logNameCode"),
		("task", "taskCode"),
		("opcode", "opcodeCode"),
	):
		codes, encoder = encode_categorical(features[column], encoders.get(key))
		features[key] = codes
		encoders[key] = encoder

	return features[FEATURE_COLUMNS].astype(float), encoders


def train_random_forest(
	features: pd.DataFrame,
	labels: np.ndarray,
	*,
	n_estimators: int = 200,
	random_state: int = 42,
) -> RandomForestClassifier:
	unique = set(np.unique(labels))
	x_train = features.to_numpy()
	y_train = labels.copy()
	if unique == {0}:
		x_train = np.vstack([x_train, x_train[0:1] + 1.0])
		y_train = np.append(y_train, 1)
	elif unique == {1}:
		x_train = np.vstack([x_train, np.zeros((1, x_train.shape[1]))])
		y_train = np.append(y_train, 0)

	model = RandomForestClassifier(
		n_estimators=n_estimators,
		max_depth=12,
		min_samples_leaf=2,
		class_weight="balanced",
		random_state=random_state,
		n_jobs=-1,
	)
	model.fit(x_train, y_train)
	return model


def score_events(
	model: RandomForestClassifier,
	features: pd.DataFrame,
) -> tuple[np.ndarray, np.ndarray]:
	probabilities = model.predict_proba(features.to_numpy())
	class_to_index = {label: index for index, label in enumerate(model.classes_)}
	anomaly_index = class_to_index.get(1, 0)
	scores = probabilities[:, anomaly_index]
	predictions = (scores >= 0.5).astype(int)
	return predictions, scores


def build_anomaly_events(
	frame: pd.DataFrame,
	scores: np.ndarray,
	*,
	threshold: float,
	source_path: Path,
	computer_name: str | None,
	intel_meta: dict[str, Any] | None,
) -> list[dict[str, Any]]:
	anomalies: list[dict[str, Any]] = []
	detected_at = datetime.now(timezone.utc).isoformat()

	for row, score in zip(frame.to_dict(orient="records"), scores):
		rf_score = float(score)
		# Intel/heuristic hits should still surface even if RF probability is soft.
		intel_backed = bool(
			row.get("mitreMapped")
			or row.get("cisaHit")
			or row.get("suspiciousEventId")
			or row.get("level") in {1, 2}
			or row.get("suspiciousMessage")
		)
		effective_score = rf_score
		if intel_backed and row.get("weakLabel") == 1:
			effective_score = max(rf_score, threshold)
		if effective_score < threshold:
			continue

		reason_bits: list[str] = []
		if row.get("mitreMapped"):
			techniques = row.get("mitreTechniques") or []
			preview = ", ".join(techniques[:4]) if techniques else "mapped"
			reason_bits.append(f"MITRE ATT&CK/CAR mapping ({preview})")
		if row.get("cisaHit"):
			reason_bits.append("CISA KEV indicator in message")
		if row["suspiciousEventId"]:
			reason_bits.append(f"high-risk eventId {row['eventId']}")
		if row["level"] in {1, 2}:
			reason_bits.append(f"severity level {row.get('levelName') or row['level']}")
		if row["suspiciousMessage"]:
			reason_bits.append("suspicious message pattern")
		if not reason_bits:
			reason_bits.append("random-forest decision boundary")

		anomalies.append(
			{
				"anomalyId": f"rf-{row.get('recordId')}-{row['_index']}",
				"detectedAtUtc": detected_at,
				"sourceFile": str(source_path),
				"computerName": computer_name or _json_safe(row.get("machineName")),
				"score": round(float(effective_score), 4),
				"modelScore": round(rf_score, 4),
				"threshold": threshold,
				"model": "RandomForestClassifier",
				"threatIntel": intel_meta,
				"mitreTechniques": list(row.get("mitreTechniques") or []),
				"cisaMatches": list(row.get("cisaMatches") or []),
				"reasons": reason_bits,
				"event": {
					"recordId": _json_safe(row.get("recordId")),
					"timeCreatedUtc": _json_safe(row.get("timeCreatedUtc")),
					"eventId": _json_safe(row.get("eventId")),
					"provider": _json_safe(row.get("provider")),
					"level": _json_safe(row.get("level")),
					"levelName": _json_safe(row.get("levelName")),
					"logName": _json_safe(row.get("logName")),
					"task": _json_safe(row.get("task")),
					"userId": _json_safe(row.get("userId")),
					"processId": _json_safe(row.get("processId")),
					"message": _json_safe(row.get("message")),
				},
				"status": "open",
				"nextHop": "triage_agent",
			}
		)

	anomalies.sort(key=lambda item: item["score"], reverse=True)
	return anomalies


def save_model(path: Path, model: RandomForestClassifier, encoders: dict[str, LabelEncoder]) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	joblib.dump({"model": model, "encoders": encoders, "featureColumns": FEATURE_COLUMNS}, path)


def load_model(path: Path) -> tuple[RandomForestClassifier, dict[str, LabelEncoder]]:
	payload = joblib.load(path)
	return payload["model"], payload["encoders"]


def write_anomaly_document(
	output_dir: Path,
	*,
	source_path: Path,
	anomalies: list[dict[str, Any]],
	event_count: int,
	threshold: float,
	intel_meta: dict[str, Any] | None,
) -> Path:
	output_dir.mkdir(parents=True, exist_ok=True)
	stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
	output_path = output_dir / f"anomalies_{stamp}.json"
	document = {
		"schemaVersion": 1,
		"agent": "sentinel_anomaly_agent",
		"model": "RandomForestClassifier",
		"detectedAtUtc": datetime.now(timezone.utc).isoformat(),
		"sourceFile": str(source_path),
		"sourceEventCount": event_count,
		"anomalyCount": len(anomalies),
		"threshold": threshold,
		"threatIntel": intel_meta,
		"anomalies": anomalies,
	}
	output_path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
	return output_path


def parse_args() -> argparse.Namespace:
	parser = argparse.ArgumentParser(
		description="Detect cybersecurity anomalies using a Random Forest trained with MITRE/CISA intel.",
	)
	parser.add_argument(
		"--input",
		type=Path,
		help="path to a gatherer JSON file (default: latest events_*.json under Event_Gatherer/events)",
	)
	parser.add_argument(
		"--events-dir",
		type=Path,
		default=DEFAULT_EVENTS_DIR,
		help=f"directory of gatherer JSON exports (default: {DEFAULT_EVENTS_DIR})",
	)
	parser.add_argument(
		"--output-dir",
		type=Path,
		default=DEFAULT_OUTPUT_DIR,
		help=f"directory for anomaly event JSON (default: {DEFAULT_OUTPUT_DIR})",
	)
	parser.add_argument(
		"--threshold",
		type=float,
		default=0.55,
		help="minimum anomaly probability to emit an event (default: 0.55)",
	)
	parser.add_argument(
		"--n-estimators",
		type=int,
		default=200,
		help="number of trees in the Random Forest (default: 200)",
	)
	parser.add_argument(
		"--model-path",
		type=Path,
		default=DEFAULT_MODEL_PATH,
		help=f"where to save/load the fitted model (default: {DEFAULT_MODEL_PATH})",
	)
	parser.add_argument(
		"--load-model",
		action="store_true",
		help="load an existing model instead of training on the current batch + intel",
	)
	parser.add_argument(
		"--no-save-model",
		action="store_true",
		help="do not persist the fitted Random Forest after training",
	)
	parser.add_argument(
		"--refresh-intel",
		action="store_true",
		help="re-download MITRE ATT&CK, MITRE CAR, and CISA KEV before training",
	)
	parser.add_argument(
		"--skip-car",
		action="store_true",
		help="skip MITRE CAR YAML download when refreshing intel (faster)",
	)
	parser.add_argument(
		"--no-intel",
		action="store_true",
		help="disable online/cached threat intel and use seed heuristics only",
	)
	parser.add_argument(
		"--refresh-intel-only",
		action="store_true",
		help="download/cache threat intel and exit without scoring events",
	)
	return parser.parse_args()


def main() -> int:
	args = parse_args()

	catalog: ThreatIntelCatalog | None = None
	intel_meta: dict[str, Any] | None = None
	if not args.no_intel:
		catalog = get_catalog(refresh=args.refresh_intel or args.refresh_intel_only, include_car=not args.skip_car)
		intel_meta = {
			"fetchedAtUtc": catalog.fetchedAtUtc,
			"sources": catalog.sources,
			"stats": catalog.stats,
		}
		if args.refresh_intel_only:
			return 0

	source_path = args.input or latest_event_file(args.events_dir)
	document = load_event_document(source_path)
	events = document.get("events") or []
	if not events:
		print(f"No events found in {source_path}", flush=True)
		return 1

	frame = events_to_frame(events, catalog=catalog)

	if args.load_model:
		if not args.model_path.exists():
			print(f"Model not found: {args.model_path}", flush=True)
			return 1
		model, encoders = load_model(args.model_path)
		features, _ = build_feature_matrix(frame, encoders)
	else:
		train_frame = frame
		if catalog is not None:
			synthetic = synthesize_intel_training_rows(catalog)
			train_frame = pd.concat([frame, synthetic], ignore_index=True)
			print(
				f"Training with {len(frame)} live events + {len(synthetic)} MITRE/CISA synthetic rows.",
				flush=True,
			)
		features_train, encoders = build_feature_matrix(train_frame)
		labels = train_frame["weakLabel"].to_numpy()
		model = train_random_forest(features_train, labels, n_estimators=args.n_estimators)
		features, _ = build_feature_matrix(frame, encoders)
		if not args.no_save_model:
			save_model(args.model_path, model, encoders)

	_predictions, scores = score_events(model, features)
	anomalies = build_anomaly_events(
		frame,
		scores,
		threshold=args.threshold,
		source_path=source_path,
		computer_name=document.get("computerName"),
		intel_meta=intel_meta,
	)
	output_path = write_anomaly_document(
		args.output_dir,
		source_path=source_path,
		anomalies=anomalies,
		event_count=len(events),
		threshold=args.threshold,
		intel_meta=intel_meta,
	)

	print(
		f"Scored {len(events)} events from {source_path.name}; "
		f"emitted {len(anomalies)} anomal(ies) -> {output_path}",
		flush=True,
	)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
