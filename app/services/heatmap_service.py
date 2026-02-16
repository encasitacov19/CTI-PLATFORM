from sqlalchemy.orm import Session
from sqlalchemy import func
from app import models


def get_heatmap(db: Session, country: str):

    results = (
        db.query(
            models.Technique.tech_id,
            models.Technique.name,
            models.Technique.tactic,
            func.count(models.ActorTechnique.id).label("usage_count")
        )
        .join(models.ActorTechnique, models.ActorTechnique.technique_id == models.Technique.id)
        .join(models.ThreatActor, models.ThreatActor.id == models.ActorTechnique.actor_id)
        .filter(models.ThreatActor.country == country)
        .filter(models.ActorTechnique.active == True)
        .group_by(models.Technique.tech_id, models.Technique.name, models.Technique.tactic)
        .order_by(func.count(models.ActorTechnique.id).desc())
        .all()
    )

    heatmap = []

    for r in results:
        heatmap.append({
            "technique": r.tech_id,
            "name": r.name,
            "tactic": r.tactic,
            "score": r.usage_count
        })

    return heatmap

