import json
import requests
from sqlalchemy.orm import Session
from app import models

STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def _extract_tech_id(external_refs):
    for ref in external_refs or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref.get("external_id")
    return None


def _extract_tactics(kill_chain_phases):
    tactics = []
    for p in kill_chain_phases or []:
        if p.get("kill_chain_name") != "mitre-attack":
            continue
        phase = p.get("phase_name")
        if phase:
            tactics.append(phase)
    return ",".join(sorted(set(tactics)))


def sync_mitre_from_github(db: Session):
    resp = requests.get(STIX_URL, timeout=30)
    resp.raise_for_status()

    bundle = resp.json()
    objects = bundle.get("objects", [])

    updated = 0
    created = 0

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        tech_id = _extract_tech_id(obj.get("external_references"))
        if not tech_id:
            continue

        name = obj.get("name")
        description = obj.get("description")
        tactics = _extract_tactics(obj.get("kill_chain_phases"))

        existing = db.query(models.Technique).filter(models.Technique.tech_id == tech_id).first()
        if existing:
            existing.name = name
            existing.tactic = tactics
            existing.description = description
            updated += 1
        else:
            db.add(models.Technique(
                tech_id=tech_id,
                name=name,
                tactic=tactics,
                description=description
            ))
            created += 1

    db.commit()

    return {"created": created, "updated": updated}
