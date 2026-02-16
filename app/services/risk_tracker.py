from datetime import datetime
from sqlalchemy.orm import Session
from app import models
from app.services.risk_score import calculate_risk


# -------------------------------------------------
# Guardar snapshot
# -------------------------------------------------
def store_snapshot(db: Session, country: str):

    risks = calculate_risk(db, country)

    if not risks:
        return

    total_risk = sum(r["risk"] for r in risks)
    techniques = len(risks)

    actors = db.query(models.ThreatActor)\
        .filter_by(country=country, active=True)\
        .count()

    snap = models.CountryRiskSnapshot(
        country=country,
        risk_score=total_risk,
        techniques=techniques,
        actors=actors,
        created_at=datetime.utcnow()
    )

    db.add(snap)
    db.commit()


# -------------------------------------------------
# Detectar cambio de riesgo
# -------------------------------------------------
def detect_risk_change(db: Session, country: str):

    snaps = db.query(models.CountryRiskSnapshot)\
        .filter_by(country=country)\
        .order_by(models.CountryRiskSnapshot.created_at.desc())\
        .limit(2)\
        .all()

    if len(snaps) < 2:
        return

    latest = snaps[0]
    previous = snaps[1]

    if previous.risk_score == 0:
        return

    change = ((latest.risk_score - previous.risk_score) / previous.risk_score) * 100

    if abs(change) < 15:
        return

    severity = "HIGH" if change > 0 else "LOW"

    alert = models.Alert(
        actor_id=None,
        technique_id=None,
        title=f"Risk change detected in {country}",
        description=f"Risk changed {change:.2f}% (from {previous.risk_score:.2f} to {latest.risk_score:.2f})",
        severity=severity,
        created_at=datetime.utcnow()
    )

    db.add(alert)
    db.commit()

