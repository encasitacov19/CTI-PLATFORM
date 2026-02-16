import requests
from sqlalchemy.orm import Session
from app import models

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def load_mitre(db: Session):

    print("Downloading MITRE ATT&CK...")
    data = requests.get(MITRE_URL, timeout=60).json()

    created = 0
    total = 0

    for obj in data["objects"]:

        if obj.get("type") != "attack-pattern":
            continue

        # obtener ID Txxxx
        tech_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                tech_id = ref.get("external_id")

        if not tech_id:
            continue

        name = obj.get("name", "unknown")

        # obtener táctica
        tactic = None
        phases = obj.get("kill_chain_phases", [])
        if phases:
            tactic = phases[0]["phase_name"]

        total += 1

        exists = db.query(models.Technique)\
            .filter_by(tech_id=tech_id)\
            .first()

        if exists:
            continue

        db.add(models.Technique(
            tech_id=tech_id,
            name=name,
            tactic=tactic
        ))

        created += 1

    db.commit()

    print(f"MITRE loaded: {created}/{total}")

    return {
        "created": created,
        "total": total
    }

