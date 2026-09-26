"""Small shared helpers."""
import json
import uuid
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_now_ts() -> float:
    return datetime.now(timezone.utc).timestamp()


def new_id(prefix: str = "") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def safe_json(data: dict) -> dict:
    """Strip non-serializable fields defensively."""
    return {k: json.loads(json.dumps(v, default=str)) for k, v in data.items()}