from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app import models


def calculate_actor_ranking(db: Session, country: str):

    since_7 = datetime.utcnow() - timedelta(days=7)

    actors = db.query(models.ThreatActor)\
        .filter(models.ThreatActor.country == country)\
        .filter(models.ThreatActor.active == True)\
        .all()

    results = []

    for actor in actors:

        # TTPs activas
        active_ttps = db.query(func.count(models.ActorTechnique.id))\
            .filter(models.ActorTechnique.actor_id == actor.id)\
            .filter(models.ActorTechnique.active == True)\
            .scalar() or 0

        # nuevas en 7 días
        new_7 = db.query(func.count(models.IntelligenceEvent.id))\
            .filter(models.IntelligenceEvent.actor_id == actor.id)\
            .filter(models.IntelligenceEvent.event_type == "NEW")\
            .filter(models.IntelligenceEvent.created_at >= since_7)\
            .scalar() or 0

        # reactivadas
        reactivated = db.query(func.count(models.IntelligenceEvent.id))\
            .filter(models.IntelligenceEvent.actor_id == actor.id)\
            .filter(models.IntelligenceEvent.event_type == "REACTIVATED")\
            .filter(models.IntelligenceEvent.created_at >= since_7)\
            .scalar() or 0

        # score
        risk = (
            active_ttps * 1.2
            + new_7 * 6
            + reactivated * 8
        )

        if risk > 80:
            level = "CRITICAL"
        elif risk > 50:
            level = "HIGH"
        elif risk > 20:
            level = "MEDIUM"
        else:
            level = "LOW"

        results.append({
            "actor": actor.name,
            "risk": round(risk, 2),
            "active_ttps": active_ttps,
            "new_ttps_7d": new_7,
            "activity": level
        })

    return sorted(results, key=lambda x: x["risk"], reverse=True)

