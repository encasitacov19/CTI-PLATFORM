import os
import requests
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from app import models
from app.services.alert_engine import generate_alert
from app.services.risk_tracker import store_snapshot, detect_risk_change

# -------------------------------------------------
# CONFIG
# -------------------------------------------------
load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

HEADERS = {
    "x-apikey": VT_API_KEY,
    "accept": "application/json"
}

BASE = "https://www.virustotal.com/api/v3"
FILES_FALLBACK_LIMIT = int(os.getenv("VT_FILES_FALLBACK_LIMIT", "40"))
SCAN_MIN_INTERVAL_MINUTES = int(os.getenv("VT_SCAN_MIN_INTERVAL_MINUTES", "60"))
NEW_ALERT_MIN_SIGHTINGS = int(os.getenv("NEW_ALERT_MIN_SIGHTINGS", "3"))
NEW_ALERT_MIN_DISTINCT_DAYS = int(os.getenv("NEW_ALERT_MIN_DISTINCT_DAYS", "2"))
WATCHLIST_TECHNIQUES = {
    x.strip().upper()
    for x in (os.getenv("WATCHLIST_TECHNIQUES", "") or "").split(",")
    if x.strip()
}
WATCHLIST_MIN_SIGHTINGS = int(os.getenv("WATCHLIST_MIN_SIGHTINGS", "1"))
WATCHLIST_MIN_DISTINCT_DAYS = int(os.getenv("WATCHLIST_MIN_DISTINCT_DAYS", "1"))
NEW_ALERT_TACTIC_THRESHOLD_OVERRIDES = os.getenv("NEW_ALERT_TACTIC_THRESHOLD_OVERRIDES", "")


def _parse_tactic_overrides(raw: str):
    # formato: "initial-access:2/1,discovery:4/3"
    result = {}
    for chunk in (raw or "").split(","):
        part = chunk.strip()
        if not part or ":" not in part:
            continue
        tactic, values = part.split(":", 1)
        tactic = tactic.strip().lower()
        if "/" not in values:
            continue
        s, d = values.split("/", 1)
        try:
            result[tactic] = (max(1, int(s)), max(1, int(d)))
        except ValueError:
            continue
    return result


TACTIC_THRESHOLD_OVERRIDES = _parse_tactic_overrides(NEW_ALERT_TACTIC_THRESHOLD_OVERRIDES)


# -------------------------------------------------
# Obtener collection ID del actor
# -------------------------------------------------
def resolve_collection_id(actor):
    # Prefer GTI/VT ID if provided (e.g. threat-actor--uuid)
    if getattr(actor, "gti_id", None):
        return actor.gti_id

    url = f"{BASE}/intelligence/search"

    params = {
        "query": f'entity:threat_actor "{actor.name}"',
        "limit": 1
    }

    r = requests.get(url, headers=HEADERS, params=params)

    if r.status_code != 200:
        print("Search error:", r.status_code, r.text)
        return None

    data = r.json().get("data", [])
    if not data:
        print("No results for", actor.name)
        return None

    return data[0]["id"]


# -------------------------------------------------
# Obtener TTPs del actor (con paginación)
# -------------------------------------------------
def fetch_actor_ttps(collection_id: str):

    print("Collection ID:", collection_id)

    url = f"{BASE}/collections/{collection_id}/relationships/attack_techniques"
    params = {"limit": 40}

    all_ttps = []

    while url:

        r = requests.get(url, headers=HEADERS, params=params)

        if r.status_code != 200:
            print("TTP error:", r.status_code, r.text)
            return all_ttps, "ERROR"

        data = r.json()

        batch = [x["id"] for x in data.get("data", [])]
        all_ttps.extend(batch)

        # paginación
        url = data.get("links", {}).get("next")
        params = None

    return list(set(all_ttps)), None


def fetch_actor_file_hashes(collection_id: str, limit: int = FILES_FALLBACK_LIMIT):
    url = f"{BASE}/collections/{collection_id}/relationships/files"
    params = {"limit": min(limit, 40)}
    hashes = []

    while url and len(hashes) < limit:
        r = requests.get(url, headers=HEADERS, params=params)

        if r.status_code != 200:
            print("Files error:", r.status_code, r.text)
            return hashes, "ERROR"

        data = r.json()
        batch = [x["id"] for x in data.get("data", []) if x.get("id")]
        hashes.extend(batch)

        url = data.get("links", {}).get("next")
        params = None

    return hashes[:limit], None


def fetch_file_mitre_techniques(file_hash: str):
    url = f"{BASE}/files/{file_hash}/behaviour_mitre_trees"
    r = requests.get(url, headers=HEADERS)

    if r.status_code != 200:
        return set()

    techniques = set()
    data = r.json().get("data", {})

    for sandbox in data.values():
        for tactic in sandbox.get("tactics", []):
            for tech in tactic.get("techniques", []):
                tech_id = tech.get("id")
                if tech_id:
                    techniques.add(tech_id)

    return techniques


def fetch_actor_ttps_from_files(collection_id: str):
    hashes, hash_err = fetch_actor_file_hashes(collection_id)
    if hash_err:
        return [], "ERROR"

    all_ttps = set()
    evidence_map = {}
    for h in hashes:
        ttps = fetch_file_mitre_techniques(h)
        all_ttps.update(ttps)
        for tech_code in ttps:
            if tech_code not in evidence_map:
                evidence_map[tech_code] = set()
            evidence_map[tech_code].add(h)

    return list(all_ttps), evidence_map, None


def get_confirmation_thresholds(technique, tech_code: str):
    if (tech_code or "").upper() in WATCHLIST_TECHNIQUES:
        return WATCHLIST_MIN_SIGHTINGS, WATCHLIST_MIN_DISTINCT_DAYS, "watchlist"

    tactic_value = ""
    if technique is not None:
        tactic_value = technique.tactic or ""
    tactic_names = [x.strip().lower() for x in tactic_value.split(",") if x.strip()]
    matches = [TACTIC_THRESHOLD_OVERRIDES[t] for t in tactic_names if t in TACTIC_THRESHOLD_OVERRIDES]
    if matches:
        # si una técnica participa en varias tácticas, usamos la regla más sensible
        min_sightings = min(x[0] for x in matches)
        min_days = min(x[1] for x in matches)
        return min_sightings, min_days, "tactic_override"

    return NEW_ALERT_MIN_SIGHTINGS, NEW_ALERT_MIN_DISTINCT_DAYS, "default"


def store_evidence(db: Session, actor_id: int, technique_id: int, hashes: set[str], source: str):
    if not hashes:
        return 0
    inserted = 0
    for h in hashes:
        exists = (
            db.query(models.TechniqueEvidence.id)
            .filter(models.TechniqueEvidence.actor_id == actor_id)
            .filter(models.TechniqueEvidence.technique_id == technique_id)
            .filter(models.TechniqueEvidence.sample_hash == h)
            .first()
        )
        if exists:
            continue
        db.add(models.TechniqueEvidence(
            actor_id=actor_id,
            technique_id=technique_id,
            sample_hash=h,
            source=source,
            observed_at=datetime.utcnow()
        ))
        inserted += 1
    return inserted


# -------------------------------------------------
# Actualizar TTPs en base de datos
# -------------------------------------------------
def update_actor_ttps(db: Session, actor):

    now = datetime.utcnow()

    print(f"\n=== ACTOR: {actor.name} ===")

    collection_id = resolve_collection_id(actor)
    if not collection_id:
        return {
            "status": "error",
            "error": "NOT_FOUND",
            "total": 0,
            "inserted": 0,
            "new_confirmed": 0,
            "new_pending": 0,
            "reactivated": 0,
            "disabled": 0,
            "missing_mitre": 0
        }

    ttps, err = fetch_actor_ttps(collection_id)
    source = "attack_techniques"
    fallback_evidence_map = {}

    if err == "ERROR":
        # Si falla este endpoint, no marcamos técnicas como desaparecidas por un error temporal.
        return {
            "status": "error",
            "error": err,
            "source": source,
            "total": 0,
            "inserted": 0,
            "new_confirmed": 0,
            "new_pending": 0,
            "reactivated": 0,
            "disabled": 0,
            "missing_mitre": 0
        }

    if not ttps:
        fallback_ttps, fallback_evidence_map, fallback_err = fetch_actor_ttps_from_files(collection_id)
        if fallback_err == "ERROR":
            return {
                "status": "error",
                "error": "FILES_FALLBACK_ERROR",
                "source": "files_behaviour_mitre_trees",
                "total": 0,
                "inserted": 0,
                "new_confirmed": 0,
                "new_pending": 0,
                "reactivated": 0,
                "disabled": 0,
                "missing_mitre": 0
            }
        if fallback_err != "ERROR" and fallback_ttps:
            ttps = fallback_ttps
            source = "files_behaviour_mitre_trees"

    print("TTPs desde GTI:", len(ttps), "| source:", source)

    # TTPs actuales en BD
    existing = db.query(models.ActorTechnique)\
        .filter(models.ActorTechnique.actor_id == actor.id)\
        .all()

    existing_map = {at.technique.tech_id: at for at in existing}

    seen_today = set()

    inserted = 0
    new_confirmed = 0
    new_pending = 0
    reactivated = 0
    disabled = 0
    missing_mitre = 0
    evidence_added = 0

    # -------------------------------------------------
    # NUEVAS Y REACTIVADAS
    # -------------------------------------------------
    for tech_code in ttps:

        technique = db.query(models.Technique)\
            .filter(models.Technique.tech_id == tech_code)\
            .first()

        if not technique:
            print("NO EXISTE EN MITRE:", tech_code)
            missing_mitre += 1
            continue

        seen_today.add(tech_code)

        # ---------------- NEW ----------------
        if tech_code not in existing_map:

            new = models.ActorTechnique(
                actor_id=actor.id,
                technique_id=technique.id,
                first_seen=now,
                last_seen=now,
                last_collected=now,
                active=True,
                sightings_count=1,
                seen_days_count=1,
                new_alert_sent=False
            )

            db.add(new)
            inserted += 1
            new_pending += 1

            min_sightings, min_days, _ = get_confirmation_thresholds(technique, tech_code)
            if min_sightings <= 1 and min_days <= 1:
                new.new_alert_sent = True
                db.add(models.IntelligenceEvent(
                    actor_id=actor.id,
                    technique_id=technique.id,
                    event_type="NEW",
                    created_at=now
                ))
                generate_alert(
                    db,
                    actor,
                    technique,
                    "NEW",
                    context=f"NEW confirmed ({1}/{min_sightings} observations, {1}/{min_days} days). source={source}"
                )
                new_confirmed += 1
                new_pending -= 1
                if source == "files_behaviour_mitre_trees":
                    evidence_added += store_evidence(
                        db,
                        actor.id,
                        technique.id,
                        fallback_evidence_map.get(tech_code, set()),
                        source
                    )

        # ---------------- REACTIVATED ----------------
        else:
            record = existing_map[tech_code]

            # datos históricos previos a esta versión: evitamos disparar NEW retroactivo
            if record.new_alert_sent is None:
                record.new_alert_sent = True

            prev_last_seen = record.last_seen
            record.last_seen = now
            record.last_collected = now
            record.sightings_count = (record.sightings_count or 0) + 1
            if not record.seen_days_count:
                record.seen_days_count = 1

            if prev_last_seen and prev_last_seen.date() != now.date():
                record.seen_days_count = (record.seen_days_count or 1) + 1

            if not record.active:
                record.active = True

                db.add(models.IntelligenceEvent(
                    actor_id=actor.id,
                    technique_id=technique.id,
                    event_type="REACTIVATED",
                    created_at=now
                ))

                generate_alert(db, actor, technique, "REACTIVATED", context="Technique reactivated after inactivity")
                reactivated += 1
            elif not record.new_alert_sent:
                sightings = record.sightings_count or 0
                seen_days = record.seen_days_count or 0
                min_sightings, min_days, _ = get_confirmation_thresholds(technique, tech_code)
                if sightings >= min_sightings and seen_days >= min_days:
                    record.new_alert_sent = True
                    db.add(models.IntelligenceEvent(
                        actor_id=actor.id,
                        technique_id=technique.id,
                        event_type="NEW",
                        created_at=now
                    ))
                    generate_alert(
                        db,
                        actor,
                        technique,
                        "NEW",
                        context=f"NEW confirmed ({sightings}/{min_sightings} observations, {seen_days}/{min_days} days). source={source}"
                    )
                    new_confirmed += 1
                    if source == "files_behaviour_mitre_trees":
                        evidence_added += store_evidence(
                            db,
                            actor.id,
                            technique.id,
                            fallback_evidence_map.get(tech_code, set()),
                            source
                        )

    # -------------------------------------------------
    # DESAPARECIDAS
    # -------------------------------------------------
    for code, record in existing_map.items():

        if code not in seen_today and record.active:

            record.active = False

            db.add(models.IntelligenceEvent(
                actor_id=actor.id,
                technique_id=record.technique_id,
                event_type="DISAPPEARED",
                created_at=now
            ))

            generate_alert(db, actor, record.technique, "DISAPPEARED", context="Technique no longer observed in current collection window")
            disabled += 1

    db.commit()

    print("Insertadas:", inserted)
    print("NEW confirmadas:", new_confirmed)
    print("NEW pendientes:", new_pending)
    print("Reactivadas:", reactivated)
    print("Desactivadas:", disabled)
    print("Evidencias:", evidence_added)

    return {
        "status": "ok",
        "error": err,
        "source": source,
        "total": len(ttps),
        "inserted": inserted,
        "new_confirmed": new_confirmed,
        "new_pending": new_pending,
        "reactivated": reactivated,
        "disabled": disabled,
        "missing_mitre": missing_mitre,
        "evidence_added": evidence_added
    }


def should_scan_actor(db: Session, actor_id: int, now: datetime) -> bool:
    # 0 o negativo = siempre escanear (sin throttling)
    if SCAN_MIN_INTERVAL_MINUTES <= 0:
        return True

    last_collected = (
        db.query(models.ActorTechnique.last_collected)
        .filter(models.ActorTechnique.actor_id == actor_id)
        .order_by(models.ActorTechnique.last_collected.desc())
        .limit(1)
        .scalar()
    )

    if not last_collected:
        return True

    return (now - last_collected) >= timedelta(minutes=SCAN_MIN_INTERVAL_MINUTES)


# -------------------------------------------------
# Ejecutar collector para todos los actores
# -------------------------------------------------
def run_collection(db: Session, progress_callback=None):

    actors = db.query(models.ThreatActor)\
        .filter_by(active=True)\
        .all()

    affected_countries = set()
    now = datetime.utcnow()
    total_actors = len(actors)
    processed = 0
    scanned = 0
    skipped = 0
    errors = 0
    actor_results = []

    for actor in actors:
        processed += 1
        if not should_scan_actor(db, actor.id, now):
            print(f"Skipping {actor.name}: scanned recently")
            skipped += 1
            if progress_callback:
                progress_callback(
                    processed_items=processed,
                    total_items=total_actors,
                    details=f"skip:{actor.name}"
                )
            continue

        result = update_actor_ttps(db, actor)
        actor_results.append({
            "actor_id": actor.id,
            "actor": actor.name,
            "status": result.get("status"),
            "source": result.get("source"),
            "total": result.get("total")
        })
        scanned += 1

        if result.get("status") != "ok":
            errors += 1

        if result.get("status") == "ok" and actor.country:
            affected_countries.add(actor.country)

        if progress_callback:
            progress_callback(
                processed_items=processed,
                total_items=total_actors,
                details=f"scan:{actor.name}:{result.get('status')}"
            )

    # -------------------------------------------------
    # CALCULAR RIESGO POR PAIS
    # -------------------------------------------------
    for country in affected_countries:
        print(f"\nEvaluating risk for {country}")
        store_snapshot(db, country)
        detect_risk_change(db, country)

    return {
        "total_actors": total_actors,
        "processed": processed,
        "scanned": scanned,
        "skipped": skipped,
        "errors": errors,
        "countries_evaluated": len(affected_countries),
        "actors": actor_results
    }
