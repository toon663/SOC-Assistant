from datasets import load_dataset
from agents import SecurityOperationsPipeline, SecurityEvent, Severity

DATASET = "joyce8/EMBER2024"


def row_to_event(row, index):
    label = int(row.get("label", 0))

    return SecurityEvent(
        event_id=row.get("sha256") or f"ember-{index}",
        timestamp=str(row.get("first_submission_date", "")),
        source="ember2024",
        event_type="malware_sample" if label else "benign_sample",
        host=row.get("sha256"),
        message=f"EMBER sample: {row.get('file_type', 'unknown')}",
        severity=Severity.HIGH if label else Severity.LOW,
        metadata={
            # Do not include the ground-truth label in agent input.
            "file_type": row.get("file_type"),
            "family": row.get("family"),
            "detection_ratio": row.get("detection_ratio"),
            "size": row.get("general", {}).get("size"),
            "entropy": row.get("general", {}).get("entropy"),
            "is_pe": row.get("general", {}).get("is_pe"),
            "section_count": len(row.get("section", {}) or {}),
            "import_count": len(row.get("imports", {}) or {}),
        },
    )


def main():
    dataset = load_dataset(
        DATASET,
        split="train",
        streaming=True,
    )

    pipeline = SecurityOperationsPipeline(require_approval=True)

    for index, row in enumerate(dataset):
        event = row_to_event(row, index)

        # approved=False prevents response execution.
        incident = pipeline.run([event], approved=False)

        expected = int(row.get("label", 0))
        predicted = int(event.severity == Severity.HIGH)

        print({
            "sample": event.event_id,
            "expected_label": expected,
            "predicted_label": predicted,
            "anomaly_score": incident.anomaly_score,
            "risk_score": incident.forecast.get("forecast_score"),
            "action_status": incident.action_result.get("status"),
        })

        if index >= 99:  # first 100 samples
            break


if __name__ == "__main__":
    main()