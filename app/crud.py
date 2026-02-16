from sqlalchemy.orm import Session
from . import models, schemas

def create_actor(db: Session, actor: schemas.ActorCreate):

    existing = db.query(models.ThreatActor)\
        .filter(models.ThreatActor.gti_id == actor.gti_id)\
        .first()

    if existing:
        # actualizar datos (ej: nuevo país monitoreado)
        existing.name = actor.name
        existing.country = actor.country
        existing.aliases = actor.aliases
        existing.source = actor.source
        existing.active = True
        db.commit()
        db.refresh(existing)
        return existing

    db_actor = models.ThreatActor(**actor.dict())
    db.add(db_actor)
    db.commit()
    db.refresh(db_actor)
    return db_actor


def get_actors(db: Session, include_inactive: bool = False):
    query = db.query(models.ThreatActor)
    if not include_inactive:
        query = query.filter(models.ThreatActor.active == True)
    return query.order_by(models.ThreatActor.created_at.desc()).all()


def deactivate_actor(db: Session, actor_id: int):
    actor = db.query(models.ThreatActor).filter(models.ThreatActor.id == actor_id).first()
    if not actor:
        return None
    actor.active = False
    db.commit()
    db.refresh(actor)
    return actor


def update_actor(db: Session, actor_id: int, actor: schemas.ActorCreate):
    existing = db.query(models.ThreatActor).filter(models.ThreatActor.id == actor_id).first()
    if not existing:
        return None
    existing.name = actor.name
    existing.gti_id = actor.gti_id
    existing.country = actor.country
    existing.aliases = actor.aliases
    existing.source = actor.source
    db.commit()
    db.refresh(existing)
    return existing


def set_actor_active(db: Session, actor_id: int, active: bool):
    actor = db.query(models.ThreatActor).filter(models.ThreatActor.id == actor_id).first()
    if not actor:
        return None
    actor.active = active
    db.commit()
    db.refresh(actor)
    return actor
