from datetime import datetime, timedelta
from app import models

ALERT_WINDOW_HOURS = 24


# -------------------------------------------------
# Controla spam de alertas
# -------------------------------------------------
def should_alert(db, actor, technique, event_type):

    state = db.query(models.AlertState)\
        .filter_by(
            actor_id=actor.id,
            technique_id=technique.id,
            event_type=event_type
        ).first()

    now = datetime.utcnow()

    # nunca alertado
    if not state:
        state = models.AlertState(
            actor_id=actor.id,
            technique_id=technique.id,
            event_type=event_type,
            last_alert_at=now
        )
        db.add(state)
        return True

    # ventana de silencio
    if now - state.last_alert_at > timedelta(hours=ALERT_WINDOW_HOURS):
        state.last_alert_at = now
        return True

    return False


# -------------------------------------------------
# Crear alerta
# -------------------------------------------------
def generate_alert(db, actor, technique, event_type, context: str | None = None):

    if not should_alert(db, actor, technique, event_type):
        return

    severity_map = {
        "NEW": "HIGH",
        "REACTIVATED": "MEDIUM",
        "DISAPPEARED": "LOW"
    }

    alert = models.Alert(
        actor_id=actor.id,
        technique_id=technique.id,
        title=f"{actor.name} using {technique.tech_id}",
        description=(context or f"{event_type} technique detected in monitored region"),
        severity=severity_map.get(event_type, "LOW"),
        created_at=datetime.utcnow()
    )

    db.add(alert)
