from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Float, UniqueConstraint
from datetime import datetime
from .database import Base


class ThreatActor(Base):
    __tablename__ = "threat_actors"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)
    gti_id = Column(String, unique=True)
    country = Column(String)
    aliases = Column(String)
    source = Column(String, default="GTI")
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship


class Technique(Base):
    __tablename__ = "techniques"

    id = Column(Integer, primary_key=True)
    tech_id = Column(String, unique=True, index=True)  # T1059
    name = Column(String)
    tactic = Column(String, index=True)
    description = Column(String)

class ActorTechnique(Base):
    __tablename__ = "actor_techniques"

    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"))
    technique_id = Column(Integer, ForeignKey("techniques.id"))

    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    last_collected = Column(DateTime, index=True)
    active = Column(Boolean, default=True)
    sightings_count = Column(Integer, default=1)
    seen_days_count = Column(Integer, default=1)
    new_alert_sent = Column(Boolean, default=False)

    actor = relationship("ThreatActor")
    technique = relationship("Technique")

class IntelligenceEvent(Base):
    __tablename__ = "intelligence_events"

    id = Column(Integer, primary_key=True)

    actor_id = Column(Integer, ForeignKey("threat_actors.id"))
    technique_id = Column(Integer, ForeignKey("techniques.id"))

    event_type = Column(String)  # NEW | DISAPPEARED | REACTIVATED
    created_at = Column(DateTime)

    actor = relationship("ThreatActor")
    technique = relationship("Technique")


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)

    actor_id = Column(Integer, ForeignKey("threat_actors.id"))
    technique_id = Column(Integer, ForeignKey("techniques.id"))

    title = Column(String)
    description = Column(String)
    severity = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)

    actor = relationship("ThreatActor")
    technique = relationship("Technique")

class AlertState(Base):
    __tablename__ = "alert_state"

    id = Column(Integer, primary_key=True)

    actor_id = Column(Integer)
    technique_id = Column(Integer)
    event_type = Column(String)

    last_alert_at = Column(DateTime)

class CountryRiskSnapshot(Base):
    __tablename__ = "country_risk_snapshots"

    id = Column(Integer, primary_key=True)
    country = Column(String, index=True)

    risk_score = Column(Float)
    techniques = Column(Integer)
    actors = Column(Integer)

    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class ScheduleConfig(Base):
    __tablename__ = "schedule_config"

    id = Column(Integer, primary_key=True)
    time_hhmm = Column(String, default="06:00")
    days = Column(String)  # e.g. "mon,tue,wed"
    enabled = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    running = Column(Boolean, default=False)
    lock_until = Column(DateTime, nullable=True)


class MitreSyncConfig(Base):
    __tablename__ = "mitre_sync_config"

    id = Column(Integer, primary_key=True)
    day_of_week = Column(String, default="sun")  # mon..sun
    time_hhmm = Column(String, default="03:00")
    enabled = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=datetime.utcnow)
    last_run_at = Column(DateTime, nullable=True)
    running = Column(Boolean, default=False)
    lock_until = Column(DateTime, nullable=True)


class JobRun(Base):
    __tablename__ = "job_runs"

    id = Column(Integer, primary_key=True)
    job_type = Column(String, index=True)  # collector | actor_scan | mitre_sync
    trigger = Column(String, default="manual")  # manual | scheduler
    status = Column(String, default="RUNNING", index=True)  # RUNNING | SUCCESS | ERROR

    actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True)
    actor_name = Column(String, nullable=True)

    total_items = Column(Integer, default=0)
    processed_items = Column(Integer, default=0)

    details = Column(String, nullable=True)
    error = Column(String, nullable=True)

    started_at = Column(DateTime, default=datetime.utcnow, index=True)
    finished_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


class TechniqueEvidence(Base):
    __tablename__ = "technique_evidence"

    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"), index=True)
    technique_id = Column(Integer, ForeignKey("techniques.id"), index=True)
    sample_hash = Column(String, index=True)
    source = Column(String, default="files_behaviour_mitre_trees")
    observed_at = Column(DateTime, default=datetime.utcnow, index=True)


class DetectionUseCase(Base):
    __tablename__ = "detection_use_cases"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    description = Column(String, nullable=True)
    severity = Column(String, default="MEDIUM")
    enabled = Column(Boolean, default=True)
    country_scope = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow)


class DetectionCondition(Base):
    __tablename__ = "detection_conditions"

    id = Column(Integer, primary_key=True)
    use_case_id = Column(Integer, ForeignKey("detection_use_cases.id"), index=True)

    tactic = Column(String, nullable=True)
    technique_id = Column(Integer, ForeignKey("techniques.id"), nullable=True)
    procedure = Column(String, nullable=True)

    min_sightings = Column(Integer, default=1)
    min_days = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)


class Client(Base):
    __tablename__ = "clients"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ClientProject(Base):
    __tablename__ = "client_projects"
    __table_args__ = (UniqueConstraint("client_id", "name", name="uq_client_project_name"),)

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("clients.id"), index=True)
    name = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ActorProjectTag(Base):
    __tablename__ = "actor_project_tags"
    __table_args__ = (UniqueConstraint("actor_id", "project_id", name="uq_actor_project"),)

    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"), index=True)
    project_id = Column(Integer, ForeignKey("client_projects.id"), index=True)
    label = Column(String, default="Impacto potencial")
    note = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Tag(Base):
    __tablename__ = "tags"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ActorTag(Base):
    __tablename__ = "actor_tags"
    __table_args__ = (UniqueConstraint("actor_id", "tag_id", name="uq_actor_tag"),)

    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"), index=True)
    tag_id = Column(Integer, ForeignKey("tags.id"), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
