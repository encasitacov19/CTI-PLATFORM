from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app import models


def get_trends(db: Session, country: str, days: int = 7):

    since = datetime.utcnow() - timedelta(days=days)

    actors = db.query(models.ThreatActor).filter_by(country=country, active=True).all()
    actor_ids = [a.id for a in actors]

    if not actor_ids:
        return {}

    # NEW
    new_ttps = db.query(models.Technique.tech_id)\
        .join(models.IntelligenceEvent)\
        .filter(models.IntelligenceEvent.actor_id.in_(actor_ids))\
        .filter(models.IntelligenceEvent.event_type == "NEW")\
        .filter(models.IntelligenceEvent.created_at >= since)\
        .all()

    # DISAPPEARED
    disappeared = db.query(models.Technique.tech_id)\
        .join(models.IntelligenceEvent)\
        .filter(models.IntelligenceEvent.actor_id.in_(actor_ids))\
        .filter(models.IntelligenceEvent.event_type == "DISAPPEARED")\
        .filter(models.IntelligenceEvent.created_at >= since)\
        .all()

    # REACTIVATED
    reactivated = db.query(models.Technique.tech_id)\
        .join(models.IntelligenceEvent)\
        .filter(models.IntelligenceEvent.actor_id.in_(actor_ids))\
        .filter(models.IntelligenceEvent.event_type == "REACTIVATED")\
        .filter(models.IntelligenceEvent.created_at >= since)\
        .all()

    # TOP USED
    top = db.query(
        models.Technique.tech_id,
        func.count(models.ActorTechnique.id).label("count")
    ).join(models.ActorTechnique)\
     .filter(models.ActorTechnique.actor_id.in_(actor_ids))\
     .filter(models.ActorTechnique.active == True)\
     .group_by(models.Technique.tech_id)\
     .order_by(func.count(models.ActorTechnique.id).desc())\
     .limit(10)\
     .all()

    return {
        "new_ttps": [t[0] for t in new_ttps],
        "disappeared_ttps": [t[0] for t in disappeared],
        "reactivated_ttps": [t[0] for t in reactivated],
        "top_ttps": [{"technique": t[0], "count": t[1]} for t in top]
    }

