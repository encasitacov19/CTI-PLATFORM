from sqlalchemy.orm import Session
from app import models
from collections import defaultdict

def build_country_matrix(db: Session, country: str):

    actors = db.query(models.ThreatActor)\
        .filter_by(country=country, active=True)\
        .all()

    actor_ids = [a.id for a in actors]

    matrix = defaultdict(lambda: defaultdict(int))

    records = db.query(models.ActorTechnique)\
        .filter(models.ActorTechnique.actor_id.in_(actor_ids))\
        .filter(models.ActorTechnique.active == True)\
        .all()

    for r in records:
        tech = r.technique
        tactic = tech.tactic or "unknown"

        matrix[tactic][tech.tech_id] += 1

    # ordenar
    result = {}

    for tactic, techniques in matrix.items():
        ordered = sorted(techniques.items(), key=lambda x: x[1], reverse=True)

        result[tactic] = [
            {"technique": t, "count": c}
            for t, c in ordered
        ]

    return result

