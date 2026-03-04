import os
import requests
from dotenv import load_dotenv
from sqlalchemy.orm import Session

from app import models

load_dotenv()

OPENCTI_URL = (os.getenv("OPENCTI_URL") or "").rstrip("/")
OPENCTI_TOKEN = os.getenv("OPENCTI_TOKEN") or ""
OPENCTI_VERIFY_TLS = (os.getenv("OPENCTI_VERIFY_TLS") or "true").strip().lower() not in {"0", "false", "no"}
OPENCTI_DEFAULT_COUNTRY = (os.getenv("OPENCTI_DEFAULT_COUNTRY") or "UNK").strip() or "UNK"


def _opencti_headers():
    if not OPENCTI_TOKEN:
        raise RuntimeError("OPENCTI_TOKEN is not configured")
    return {
        "Authorization": f"Bearer {OPENCTI_TOKEN}",
        "Content-Type": "application/json",
    }


def _opencti_graphql_url():
    if not OPENCTI_URL:
        raise RuntimeError("OPENCTI_URL is not configured")
    return f"{OPENCTI_URL}/graphql"


def _fetch_threat_actors(limit: int = 200):
    query = """
    query ThreatActors($first: Int!, $after: ID) {
      threatActors(first: $first, after: $after, orderBy: name, orderMode: asc) {
        pageInfo {
          hasNextPage
          endCursor
        }
        edges {
          node {
            id
            name
            aliases
          }
        }
      }
    }
    """

    collected = []
    after = None
    page_size = min(max(1, int(limit)), 200)

    while len(collected) < limit:
        variables = {"first": page_size, "after": after}
        resp = requests.post(
            _opencti_graphql_url(),
            headers=_opencti_headers(),
            json={"query": query, "variables": variables},
            timeout=60,
            verify=OPENCTI_VERIFY_TLS,
        )

        if resp.status_code != 200:
            raise RuntimeError(f"OPENCTI_HTTP_{resp.status_code}")

        payload = resp.json()
        if payload.get("errors"):
            message = payload["errors"][0].get("message") or "opencti graphql error"
            raise RuntimeError(f"OPENCTI_GRAPHQL_ERROR: {message}")

        conn = (((payload.get("data") or {}).get("threatActors")) or {})
        edges = conn.get("edges") or []

        for edge in edges:
            node = edge.get("node") or {}
            name = (node.get("name") or "").strip()
            if not name:
                continue
            aliases = node.get("aliases") or []
            aliases = [a.strip() for a in aliases if isinstance(a, str) and a.strip()]
            collected.append({
                "id": (node.get("id") or "").strip(),
                "name": name,
                "aliases": aliases,
            })
            if len(collected) >= limit:
                break

        page_info = conn.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        after = page_info.get("endCursor")
        if not after:
            break

    return collected


def _ensure_unique_gti_id(db: Session, candidate: str):
    value = candidate
    suffix = 1
    while db.query(models.ThreatActor.id).filter(models.ThreatActor.gti_id == value).first():
        value = f"{candidate}-{suffix}"
        suffix += 1
    return value


def sync_opencti_actors(db: Session, limit: int = 200):
    rows = _fetch_threat_actors(limit=limit)

    created = 0
    updated = 0
    unchanged = 0
    skipped = 0

    for row in rows:
        name = row["name"]
        opencti_id = row["id"] or ""
        aliases = ", ".join(sorted(set(row.get("aliases") or []))) or None

        existing = db.query(models.ThreatActor).filter(models.ThreatActor.name == name).first()
        if existing:
            changed = False
            if aliases is not None and aliases != (existing.aliases or None):
                existing.aliases = aliases
                changed = True
            if not existing.active:
                existing.active = True
                changed = True
            if (existing.source or "").strip() in {"", "OSINT", "OTRO"}:
                existing.source = "OPENCTI"
                changed = True
            if not (existing.gti_id or "").strip() and opencti_id:
                existing.gti_id = _ensure_unique_gti_id(db, opencti_id)
                changed = True

            if changed:
                updated += 1
            else:
                unchanged += 1
            continue

        if not opencti_id:
            skipped += 1
            continue

        gti_id = _ensure_unique_gti_id(db, opencti_id)
        db.add(models.ThreatActor(
            name=name,
            gti_id=gti_id,
            country=OPENCTI_DEFAULT_COUNTRY,
            aliases=aliases,
            source="OPENCTI",
            active=True,
        ))
        created += 1

    db.commit()

    return {
        "fetched": len(rows),
        "created": created,
        "updated": updated,
        "unchanged": unchanged,
        "skipped": skipped,
    }
