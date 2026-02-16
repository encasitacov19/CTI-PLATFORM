from sqlalchemy.orm import Session
from app import models


def get_actor_timeline(db: Session, actor_name: str):

    actor = db.query(models.ThreatActor)\
        .filter(models.ThreatActor.name == actor_name)\
        .first()

    if not actor:
        return {"error": "actor not found"}

    events = db.query(models.IntelligenceEvent)\
        .filter(models.IntelligenceEvent.actor_id == actor.id)\
        .order_by(models.IntelligenceEvent.created_at.asc())\
        .all()

    timeline = []

    for e in events:

        tech = db.query(models.Technique).filter_by(id=e.technique_id).first()

        timeline.append({
            "date": e.created_at.strftime("%Y-%m-%d"),
            "technique": tech.tech_id if tech else None,
            "name": tech.name if tech else None,
            "event": e.event_type
        })

    return timeline

