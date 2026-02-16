from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import func
from app import models


def calculate_risk(db: Session, country: str):

    # 1️⃣ Obtener actores activos del país objetivo
    actors = (
        db.query(models.ThreatActor)
        .filter(models.ThreatActor.country == country)
        .filter(models.ThreatActor.active == True)
        .all()
    )

    if not actors:
        return []

    actor_ids = [a.id for a in actors]

    since_7 = datetime.utcnow() - timedelta(days=7)

    results = []

    # 2️⃣ Recorrer todas las técnicas MITRE
    techniques = db.query(models.Technique).all()

    for tech in techniques:

        # --- CUANTOS ACTORES LA USAN ACTUALMENTE ---
        actors_using = (
            db.query(func.count(models.ActorTechnique.id))
            .filter(models.ActorTechnique.technique_id == tech.id)
            .filter(models.ActorTechnique.actor_id.in_(actor_ids))
            .filter(models.ActorTechnique.active == True)
            .scalar()
        ) or 0

        if actors_using == 0:
            continue

        # --- NUEVAS APARICIONES (últimos 7 días) ---
        new_7 = (
            db.query(func.count(models.IntelligenceEvent.id))
            .filter(models.IntelligenceEvent.technique_id == tech.id)
            .filter(models.IntelligenceEvent.event_type == "NEW")
            .filter(models.IntelligenceEvent.created_at >= since_7)
            .scalar()
        ) or 0

        # --- REACTIVACIONES ---
        reactivated = (
            db.query(func.count(models.IntelligenceEvent.id))
            .filter(models.IntelligenceEvent.technique_id == tech.id)
            .filter(models.IntelligenceEvent.event_type == "REACTIVATED")
            .filter(models.IntelligenceEvent.created_at >= since_7)
            .scalar()
        ) or 0

        # --- PERSISTENCIA PROMEDIO ---
        avg_days = float(
            db.query(
                func.avg(
                    func.extract(
                        'epoch',
                        datetime.utcnow() - models.ActorTechnique.first_seen
                    ) / 86400
                )
            )
            .filter(models.ActorTechnique.technique_id == tech.id)
            .filter(models.ActorTechnique.active == True)
            .scalar()
            or 0
        )

        # 3️⃣ Fórmula de riesgo CTI
        risk = (
            actors_using * 5      # adopción
            + new_7 * 8           # aparición reciente
            + reactivated * 10    # resurgimiento
            + avg_days * 0.3      # persistencia
        )

        results.append({
            "technique": tech.tech_id,
            "name": tech.name,
            "risk": round(risk, 2)
        })

    # 4️⃣ Top 15 más peligrosas
    return sorted(results, key=lambda x: x["risk"], reverse=True)[:15]

