"""Atomic overwrite and deduplicated merge support for inventory CSV files."""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


OBSERVATION_FIELDS = (
    "PremiereObservation",
    "DerniereObservation",
    "NombreObservations",
)


def _text(value: Any) -> str:
    """Normalize a value for CSV storage and identity comparisons."""
    return "" if value is None else str(value).strip()


def _identity(row: dict[str, Any], key_fields: Iterable[str]) -> tuple[str, ...]:
    """Build a case-insensitive natural key while preserving IP/value spelling."""
    return tuple(_text(row.get(field)).casefold() for field in key_fields)


def _positive_count(value: Any) -> int:
    """Return a valid existing observation count, defaulting to one."""
    try:
        return max(1, int(str(value).strip()))
    except (TypeError, ValueError):
        return 1


def _legacy_timestamp(path: Path) -> str:
    """Use the legacy file modification time when observation columns are absent."""
    try:
        timestamp = path.stat().st_mtime
    except OSError:
        return datetime.now(timezone.utc).isoformat()
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _read_existing(path: Path) -> list[dict[str, str]]:
    """Read an existing semicolon-delimited inventory CSV."""
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle, delimiter=";")]


def _deduplicate_current(
    rows: Iterable[dict[str, Any]], key_fields: tuple[str, ...]
) -> dict[tuple[str, ...], dict[str, str]]:
    """Deduplicate rows observed in the same execution without inflating counts."""
    result: dict[tuple[str, ...], dict[str, str]] = {}
    for raw in rows:
        row = {key: _text(value) for key, value in raw.items() if key not in OBSERVATION_FIELDS}
        key = _identity(row, key_fields)
        if key not in result:
            result[key] = row
            continue
        # Prefer non-empty values from the latest duplicate in the same run.
        for field, value in row.items():
            if value:
                result[key][field] = value
    return result


def prepare_rows(
    path: Path,
    rows: Iterable[dict[str, Any]],
    key_fields: tuple[str, ...],
    mode: str,
    observed_at: str,
) -> list[dict[str, str]]:
    """Return rows prepared for overwrite or deduplicated historical merge.

    In merge mode, a natural key is counted at most once per execution. New
    non-empty values replace old values, while an empty result never erases a
    previously known value. Legacy CSV files without observation columns are
    migrated using their filesystem modification time as the first/last seen
    timestamp.
    """
    if mode not in {"overwrite", "merge"}:
        raise ValueError(f"unsupported output mode: {mode}")
    current = _deduplicate_current(rows, key_fields)
    if mode == "overwrite" or not path.exists():
        return [
            {
                **row,
                "PremiereObservation": observed_at,
                "DerniereObservation": observed_at,
                "NombreObservations": "1",
            }
            for row in current.values()
        ]

    legacy_time = _legacy_timestamp(path)
    merged: dict[tuple[str, ...], dict[str, str]] = {}
    for raw in _read_existing(path):
        row = {key: _text(value) for key, value in raw.items()}
        key = _identity(row, key_fields)
        first = row.get("PremiereObservation") or legacy_time
        last = row.get("DerniereObservation") or first
        count = _positive_count(row.get("NombreObservations"))
        row.update(
            {
                "PremiereObservation": first,
                "DerniereObservation": last,
                "NombreObservations": str(count),
            }
        )
        if key not in merged:
            merged[key] = row
            continue
        # Consolidate possible duplicates already present in a legacy file.
        existing = merged[key]
        existing["PremiereObservation"] = min(existing["PremiereObservation"], first)
        existing["DerniereObservation"] = max(existing["DerniereObservation"], last)
        existing["NombreObservations"] = str(
            _positive_count(existing.get("NombreObservations")) + count
        )
        for field, value in row.items():
            if value and field not in OBSERVATION_FIELDS:
                existing[field] = value

    for key, new_row in current.items():
        if key not in merged:
            merged[key] = {
                **new_row,
                "PremiereObservation": observed_at,
                "DerniereObservation": observed_at,
                "NombreObservations": "1",
            }
            continue
        existing = merged[key]
        for field, value in new_row.items():
            if value:
                existing[field] = value
        existing["DerniereObservation"] = observed_at
        existing["NombreObservations"] = str(
            _positive_count(existing.get("NombreObservations")) + 1
        )
    return list(merged.values())


def write_inventory_csv(
    path: Path,
    rows: Iterable[dict[str, Any]],
    fieldnames: list[str],
    key_fields: tuple[str, ...],
    mode: str,
    observed_at: str,
) -> list[dict[str, str]]:
    """Prepare and atomically write an inventory CSV, returning stored rows."""
    stored = prepare_rows(path, rows, key_fields, mode, observed_at)
    columns = [*fieldnames, *[field for field in OBSERVATION_FIELDS if field not in fieldnames]]
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, delimiter=";", extrasaction="ignore")
        writer.writeheader()
        writer.writerows(stored)
    temporary.replace(path)
    return stored


def write_json_atomic(path: Path, value: Any) -> None:
    """Atomically write a UTF-8 JSON document."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    temporary.replace(path)
