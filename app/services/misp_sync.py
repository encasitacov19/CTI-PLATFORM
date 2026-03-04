import os
from datetime import datetime, timezone, timedelta

import requests
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from app import models

load_dotenv()


def _is_true(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no"}


def _misp_url() -> str:
    url = (os.getenv("MISP_URL") or "").strip().rstrip("/")
    if not url:
        raise RuntimeError("MISP_URL is not configured")
    return url


def _misp_key() -> str:
    key = (os.getenv("MISP_API_KEY") or "").strip()
    if not key:
        raise RuntimeError("MISP_API_KEY is not configured")
    return key


def _misp_verify_tls() -> bool:
    return _is_true(os.getenv("MISP_VERIFY_TLS"), default=True)


def _headers() -> dict:
    return {
        "Authorization": _misp_key(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _normalize_token(text: str | None) -> str:
    if not text:
        return ""
    return "".join(ch for ch in text.lower() if ch.isalnum())


def _extract_tag_names(raw_tags) -> list[str]:
    names = []
    if isinstance(raw_tags, list):
        for tag in raw_tags:
            if isinstance(tag, dict):
                value = (tag.get("name") or tag.get("tag") or "").strip()
                if value:
                    names.append(value)
            elif isinstance(tag, str):
                value = tag.strip()
                if value:
                    names.append(value)
    return names


def _extract_attributes(payload: dict) -> list[dict]:
    response = payload.get("response", payload)
    attrs = []

    if isinstance(response, dict):
        if isinstance(response.get("Attribute"), list):
            attrs.extend(response.get("Attribute") or [])
        if isinstance(response.get("attributes"), list):
            attrs.extend(response.get("attributes") or [])
        events = response.get("Event")
        if isinstance(events, dict):
            events = [events]
        if isinstance(events, list):
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                for attr in ev.get("Attribute") or []:
                    if isinstance(attr, dict) and "Event" not in attr:
                        attr["Event"] = ev
                    attrs.append(attr)

    if isinstance(response, list):
        for row in response:
            if not isinstance(row, dict):
                continue
            ev = row.get("Event", row)
            if not isinstance(ev, dict):
                continue
            for attr in ev.get("Attribute") or []:
                if isinstance(attr, dict) and "Event" not in attr:
                    attr["Event"] = ev
                attrs.append(attr)

    dedup = {}
    for attr in attrs:
        if not isinstance(attr, dict):
            continue
        attr_id = str(attr.get("id") or "").strip()
        if not attr_id:
            continue
        dedup[attr_id] = attr
    return list(dedup.values())


def _parse_observed(attr: dict, event: dict) -> tuple[datetime, datetime.date]:
    date_value = (attr.get("date") or event.get("date") or "").strip()
    if date_value:
        try:
            dt = datetime.strptime(date_value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            return dt.replace(tzinfo=None), dt.date()
        except Exception:
            pass

    timestamp_value = str(attr.get("timestamp") or event.get("timestamp") or "").strip()
    if timestamp_value.isdigit():
        try:
            dt = datetime.fromtimestamp(int(timestamp_value), tz=timezone.utc)
            return dt.replace(tzinfo=None), dt.date()
        except Exception:
            pass

    first_seen = (attr.get("first_seen") or "").strip()
    if first_seen:
        cleaned = first_seen.replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).replace(tzinfo=None), dt.date()
        except Exception:
            pass

    now_utc = datetime.utcnow()
    return now_utc, now_utc.date()


def _detect_source_bucket(attr: dict, event: dict) -> tuple[str, str | None]:
    event_info = (event.get("info") or "").strip()
    attr_comment = (attr.get("comment") or "").strip()
    attr_category = (attr.get("category") or "").strip()

    tag_names = []
    tag_names.extend(_extract_tag_names(attr.get("Tag")))
    tag_names.extend(_extract_tag_names(event.get("Tag")))
    tags_concat = " ".join(tag_names)

    candidates = [event_info, tags_concat, attr_comment, attr_category]

    for raw in candidates:
        token = _normalize_token(raw)
        if not token:
            continue
        if "tweetfeed" in token:
            return "TweetFeed", raw
        if "gti" in token or "mandiant" in token:
            return "GTI/Mandiant", raw
        if "alertadeinteligenciadeamenazas" in token:
            return "AlertaDeInteligenciaDeAmenazas", raw

    return "Otro", event_info or attr_comment or attr_category or None


def _normalize_attribute(raw: dict) -> dict | None:
    attr_id = str(raw.get("id") or "").strip()
    attr_type = (raw.get("type") or "").strip()
    value = str(raw.get("value") or "").strip()
    if not attr_id or not attr_type or not value:
        return None

    event = raw.get("Event") if isinstance(raw.get("Event"), dict) else {}
    event_id = str(raw.get("event_id") or event.get("id") or "").strip()
    event_info = (event.get("info") or "").strip() or None
    source_bucket, source_raw = _detect_source_bucket(raw, event)
    observed_at, observed_date = _parse_observed(raw, event)

    return {
        "misp_attribute_id": attr_id,
        "misp_event_id": event_id or None,
        "event_info": event_info,
        "attribute_type": attr_type,
        "attribute_category": (raw.get("category") or "").strip() or None,
        "value": value,
        "comment": (raw.get("comment") or "").strip() or None,
        "to_ids": bool(raw.get("to_ids", False)),
        "source_bucket": source_bucket,
        "source_raw": source_raw,
        "observed_at": observed_at,
        "observed_date": observed_date,
    }


def _fetch_attributes_page(page: int, limit: int, days: int | None) -> list[dict]:
    payload = {
        "returnFormat": "json",
        "page": page,
        "limit": limit,
        "includeContext": True,
        "deleted": [0],
    }

    if days is not None and days > 0:
        payload["date"] = f"{int(days)}d"

    response = requests.post(
        f"{_misp_url()}/attributes/restSearch",
        headers=_headers(),
        json=payload,
        timeout=90,
        verify=_misp_verify_tls(),
    )

    if response.status_code != 200:
        raise RuntimeError(f"MISP_HTTP_{response.status_code}")

    data = response.json()
    return _extract_attributes(data)


def sync_misp_attributes(db: Session, limit: int = 5000, page_size: int = 500, days: int | None = 30):
    limit = max(1, min(int(limit), 1000000))
    page_size = max(50, min(int(page_size), 1000))
    if days is not None and int(days) <= 0:
        days = None

    min_date = None
    if days:
        min_date = (datetime.utcnow() - timedelta(days=int(days))).date()

    fetched = 0
    created = 0
    updated = 0
    skipped = 0
    page = 1

    while fetched < limit:
        this_limit = min(page_size, limit - fetched)
        batch = _fetch_attributes_page(page=page, limit=this_limit, days=days)
        if not batch:
            break

        fetched += len(batch)
        page += 1

        normalized = {}
        for raw in batch:
            item = _normalize_attribute(raw)
            if not item:
                skipped += 1
                continue
            if min_date and item["observed_date"] < min_date:
                continue
            normalized[item["misp_attribute_id"]] = item

        if not normalized:
            if len(batch) < this_limit:
                break
            continue

        ids = list(normalized.keys())
        existing_rows = (
            db.query(models.MispAttribute)
            .filter(models.MispAttribute.misp_attribute_id.in_(ids))
            .all()
        )
        existing_by_id = {x.misp_attribute_id: x for x in existing_rows}

        for attr_id, item in normalized.items():
            existing = existing_by_id.get(attr_id)
            if not existing:
                db.add(models.MispAttribute(**item, created_at=datetime.utcnow(), updated_at=datetime.utcnow()))
                created += 1
                continue

            changed = False
            for field in [
                "misp_event_id",
                "event_info",
                "attribute_type",
                "attribute_category",
                "value",
                "comment",
                "to_ids",
                "source_bucket",
                "source_raw",
                "observed_at",
                "observed_date",
            ]:
                new_value = item[field]
                if getattr(existing, field) != new_value:
                    setattr(existing, field, new_value)
                    changed = True

            if changed:
                existing.updated_at = datetime.utcnow()
                updated += 1

        db.commit()

        if len(batch) < this_limit:
            break

    return {
        "fetched": fetched,
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "pages": page - 1,
        "window_days": days,
    }
