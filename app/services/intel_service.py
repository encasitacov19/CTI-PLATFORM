from sqlalchemy.orm import Session
from app import models

def get_actor_timeline(db: Session, actor_id: int):

    events = (
        db.query(models.IntelligenceEvent)
        .join(models.Technique, models.Technique.id == models.IntelligenceEvent.technique_id)
        .filter(models.IntelligenceEvent.actor_id == actor_id)
        .order_by(models.IntelligenceEvent.created_at.desc())
        .all()
    )

    result = []

    for e in events:
        result.append({
            "technique": e.technique.tech_id,
            "tactic": e.technique.tactic,
            "event_type": e.event_type,
            "date": e.created_at
        })

    return result

