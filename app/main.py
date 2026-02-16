from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi import Body
from sqlalchemy.orm import Session
from .database import engine, Base, get_db, SessionLocal
from . import crud, schemas, models
from app.services.gti_collector import run_collection, update_actor_ttps, get_confirmation_thresholds
from app.services.intel_service import get_actor_timeline
from app.schemas import TimelineEvent
from app.services.heatmap_service import get_heatmap
from app.schemas import HeatmapItem
from fastapi.responses import JSONResponse
from app.services.navigator_service import build_navigator_layer
from app.services.trends import get_trends
from app.services.risk_score import calculate_risk
from app.services.matrix_builder import build_matrix
from app.services.timeline import get_actor_timeline
from app.services.actor_ranking import calculate_actor_ranking
from app.services.matrix_service import build_country_matrix
from app.services.mitre_loader import load_mitre
from app.services.mitre_sync import sync_mitre_from_github
from app.services.threat_profile import build_country_profile
from app.services.predictor import predict_next_techniques
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import asyncio
from sqlalchemy import func
from sqlalchemy import case
from fastapi.responses import StreamingResponse
import csv
import io
from datetime import datetime, timedelta


# crear tablas automáticamente (temporal)
Base.metadata.create_all(bind=engine)

app = FastAPI(title="CTI Platform")

BOGOTA_TZ = ZoneInfo("America/Bogota")

def utc_to_bogota(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(BOGOTA_TZ)

# =====================================================
# BACKGROUND SCHEDULER (NO CRON)
# =====================================================
_scheduler_lock = asyncio.Lock()
_mitre_lock = asyncio.Lock()


def _job_to_response(job: models.JobRun):
    progress = None
    if (job.total_items or 0) > 0:
        progress = round((job.processed_items / job.total_items) * 100, 2)

    return {
        "id": job.id,
        "job_type": job.job_type,
        "trigger": job.trigger,
        "status": job.status,
        "actor_id": job.actor_id,
        "actor_name": job.actor_name,
        "total_items": job.total_items,
        "processed_items": job.processed_items,
        "progress_pct": progress,
        "details": job.details,
        "error": job.error,
        "started_at": utc_to_bogota(job.started_at).isoformat() if job.started_at else None,
        "finished_at": utc_to_bogota(job.finished_at).isoformat() if job.finished_at else None,
        "updated_at": utc_to_bogota(job.updated_at).isoformat() if job.updated_at else None,
    }


def _start_job(
    db: Session,
    job_type: str,
    trigger: str = "manual",
    actor_id: int | None = None,
    actor_name: str | None = None,
    total_items: int = 0
):
    job = models.JobRun(
        job_type=job_type,
        trigger=trigger,
        status="RUNNING",
        actor_id=actor_id,
        actor_name=actor_name,
        total_items=total_items,
        processed_items=0,
        started_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _update_job(db: Session, job_id: int, processed_items: int | None = None, total_items: int | None = None, details: str | None = None):
    job = db.query(models.JobRun).filter(models.JobRun.id == job_id).first()
    if not job:
        return
    if processed_items is not None:
        job.processed_items = processed_items
    if total_items is not None:
        job.total_items = total_items
    if details is not None:
        job.details = details
    job.updated_at = datetime.utcnow()
    db.commit()


def _finish_job_success(db: Session, job_id: int, details: str | None = None):
    job = db.query(models.JobRun).filter(models.JobRun.id == job_id).first()
    if not job:
        return
    job.status = "SUCCESS"
    if details is not None:
        job.details = details
    job.finished_at = datetime.utcnow()
    job.updated_at = datetime.utcnow()
    db.commit()


def _finish_job_error(db: Session, job_id: int, error: str):
    job = db.query(models.JobRun).filter(models.JobRun.id == job_id).first()
    if not job:
        return
    job.status = "ERROR"
    job.error = error[:1000]
    job.finished_at = datetime.utcnow()
    job.updated_at = datetime.utcnow()
    db.commit()

def _parse_time_hhmm(value: str):
    try:
        parts = value.split(":")
        if len(parts) != 2:
            return None
        hour = int(parts[0])
        minute = int(parts[1])
        if hour < 0 or hour > 23 or minute < 0 or minute > 59:
            return None
        return f"{hour:02d}:{minute:02d}"
    except Exception:
        return None

def _run_collection_job():
    db = SessionLocal()
    job = None
    try:
        actor_count = db.query(models.ThreatActor).filter_by(active=True).count()
        job = _start_job(
            db,
            job_type="collector",
            trigger="scheduler",
            total_items=actor_count
        )

        summary = run_collection(
            db,
            progress_callback=lambda processed_items, total_items, details: _update_job(
                db,
                job.id,
                processed_items=processed_items,
                total_items=total_items,
                details=details
            )
        )

        _finish_job_success(db, job.id, details=f"scanned={summary.get('scanned')} skipped={summary.get('skipped')} errors={summary.get('errors')}")
        cfg = db.query(models.ScheduleConfig).first()
        if cfg:
            cfg.last_run_at = datetime.utcnow()
            cfg.running = False
            cfg.lock_until = None
            db.commit()
    except Exception as e:
        if job:
            _finish_job_error(db, job.id, str(e))
        cfg = db.query(models.ScheduleConfig).first()
        if cfg:
            cfg.running = False
            cfg.lock_until = None
            db.commit()
        raise
    finally:
        db.close()


def _run_mitre_sync_job():
    db = SessionLocal()
    job = None
    try:
        job = _start_job(db, job_type="mitre_sync", trigger="scheduler", total_items=2)
        _update_job(db, job.id, processed_items=0, total_items=2, details="load_mitre:start")

        # Load MITRE (legacy) then sync from GitHub STIX
        load_mitre(db)
        _update_job(db, job.id, processed_items=1, total_items=2, details="sync_mitre_from_github:start")
        sync_mitre_from_github(db)
        _finish_job_success(db, job.id, details="mitre sync completed")

        cfg = db.query(models.MitreSyncConfig).first()
        if cfg:
            cfg.last_run_at = datetime.utcnow()
            cfg.running = False
            cfg.lock_until = None
            db.commit()
    except Exception as e:
        if job:
            _finish_job_error(db, job.id, str(e))
        cfg = db.query(models.MitreSyncConfig).first()
        if cfg:
            cfg.running = False
            cfg.lock_until = None
            db.commit()
        raise
    finally:
        db.close()

async def _scheduler_loop():
    await asyncio.sleep(3)
    while True:
        try:
            db = SessionLocal()
            try:
                cfg = db.query(models.ScheduleConfig).first()
                if cfg and cfg.enabled and cfg.time_hhmm:
                    now = datetime.now(BOGOTA_TZ)
                    today_key = ["mon","tue","wed","thu","fri","sat","sun"][now.weekday()]
                    days = [d for d in (cfg.days or "").split(",") if d]
                    time_hhmm = _parse_time_hhmm(cfg.time_hhmm)

                    if time_hhmm and today_key in days and now.strftime("%H:%M") == time_hhmm:
                        already_ran = False
                        if cfg.last_run_at:
                            last_run_bogota = utc_to_bogota(cfg.last_run_at)
                            already_ran = (
                                last_run_bogota.date() == now.date() and
                                last_run_bogota.strftime("%H:%M") == time_hhmm
                            )

                        if not already_ran:
                            # Acquire DB lease to avoid duplicate runs across workers
                            lock_until = datetime.utcnow() + timedelta(minutes=30)
                            updated = db.query(models.ScheduleConfig)\
                                .filter(models.ScheduleConfig.id == cfg.id)\
                                .filter(
                                    (models.ScheduleConfig.running == False) |
                                    (models.ScheduleConfig.lock_until == None) |
                                    (models.ScheduleConfig.lock_until < now)
                                )\
                                .update({
                                    "running": True,
                                    "lock_until": lock_until
                                }, synchronize_session=False)
                            db.commit()

                            if updated == 1 and not _scheduler_lock.locked():
                                async with _scheduler_lock:
                                    await asyncio.to_thread(_run_collection_job)
            finally:
                db.close()
        except Exception as e:
            print("Scheduler error:", e)

        await asyncio.sleep(30)


async def _mitre_scheduler_loop():
    await asyncio.sleep(5)
    while True:
        try:
            db = SessionLocal()
            try:
                cfg = db.query(models.MitreSyncConfig).first()
                if not cfg:
                    cfg = models.MitreSyncConfig(day_of_week="sun", time_hhmm="03:00", enabled=True)
                    db.add(cfg)
                    db.commit()
                    db.refresh(cfg)

                if cfg.enabled and cfg.time_hhmm:
                    now = datetime.now(BOGOTA_TZ)
                    today_key = ["mon","tue","wed","thu","fri","sat","sun"][now.weekday()]
                    time_hhmm = _parse_time_hhmm(cfg.time_hhmm)

                    if time_hhmm and today_key == (cfg.day_of_week or "sun").lower() and now.strftime("%H:%M") == time_hhmm:
                        already_ran = False
                        if cfg.last_run_at:
                            last_run_bogota = utc_to_bogota(cfg.last_run_at)
                            already_ran = (
                                last_run_bogota.date() == now.date() and
                                last_run_bogota.strftime("%H:%M") == time_hhmm
                            )

                        if not already_ran:
                            lock_until = datetime.utcnow() + timedelta(minutes=60)
                            updated = db.query(models.MitreSyncConfig)\
                                .filter(models.MitreSyncConfig.id == cfg.id)\
                                .filter(
                                    (models.MitreSyncConfig.running == False) |
                                    (models.MitreSyncConfig.lock_until == None) |
                                    (models.MitreSyncConfig.lock_until < datetime.utcnow())
                                )\
                                .update({
                                    "running": True,
                                    "lock_until": lock_until
                                }, synchronize_session=False)
                            db.commit()

                            if updated == 1 and not _mitre_lock.locked():
                                async with _mitre_lock:
                                    await asyncio.to_thread(_run_mitre_sync_job)
            finally:
                db.close()
        except Exception as e:
            print("MITRE scheduler error:", e)

        await asyncio.sleep(60)

@app.on_event("startup")
async def start_scheduler():
    asyncio.create_task(_scheduler_loop())
    asyncio.create_task(_mitre_scheduler_loop())


@app.get("/")
def root():
    return {"status": "running"}


@app.get("/jobs")
def list_jobs(
    limit: int = 50,
    status: str | None = None,
    job_type: str | None = None,
    db: Session = Depends(get_db)
):
    limit = max(1, min(limit, 200))

    query = db.query(models.JobRun)
    if status:
        query = query.filter(models.JobRun.status == status.upper())
    if job_type:
        query = query.filter(models.JobRun.job_type == job_type)

    rows = query.order_by(models.JobRun.started_at.desc()).limit(limit).all()
    return [_job_to_response(r) for r in rows]


@app.get("/jobs/{job_id}")
def get_job(job_id: int, db: Session = Depends(get_db)):
    row = db.query(models.JobRun).filter(models.JobRun.id == job_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="job not found")
    return _job_to_response(row)


@app.post("/actors", response_model=schemas.ActorOut)
def add_actor(actor: schemas.ActorCreate, db: Session = Depends(get_db)):
    return crud.create_actor(db, actor)


@app.get("/actors", response_model=list[schemas.ActorOut])
def list_actors(include_inactive: bool = False, db: Session = Depends(get_db)):
    query = (
        db.query(models.ThreatActor, func.max(models.ActorTechnique.last_collected).label("last_scan_at"))
        .outerjoin(models.ActorTechnique, models.ActorTechnique.actor_id == models.ThreatActor.id)
        .group_by(models.ThreatActor.id)
        .order_by(models.ThreatActor.created_at.desc())
    )
    if not include_inactive:
        query = query.filter(models.ThreatActor.active == True)

    rows = query.all()
    result = []
    for actor, last_scan_at in rows:
        result.append({
            "id": actor.id,
            "name": actor.name,
            "gti_id": actor.gti_id,
            "country": actor.country,
            "active": actor.active,
            "aliases": actor.aliases,
            "last_scan_at": utc_to_bogota(last_scan_at).isoformat() if last_scan_at else None,
            "source": actor.source
        })
    return result


@app.get("/actors/export")
def export_actors(include_inactive: bool = True, db: Session = Depends(get_db)):
    actors = crud.get_actors(db, include_inactive=include_inactive)

    def generate():
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["name", "gti_id", "country", "aliases", "active"])
        for a in actors:
            writer.writerow([
                a.name,
                a.gti_id,
                a.country,
                a.aliases or "",
                "true" if a.active else "false"
            ])
        return output.getvalue()

    data = generate()
    return StreamingResponse(
        io.BytesIO(data.encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=actors.csv"}
    )


@app.post("/actors/import")
def import_actors(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are supported")

    content = file.file.read().decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))

    created = 0
    updated = 0

    for row in reader:
        name = (row.get("name") or "").strip()
        gti_id = (row.get("gti_id") or "").strip()
        country = (row.get("country") or "").strip()
        aliases = (row.get("aliases") or "").strip() or None
        active_str = (row.get("active") or "true").strip().lower()
        active = active_str in ["true", "1", "yes", "y"]

        if not name or not gti_id or not country:
            continue

        existing = db.query(models.ThreatActor).filter(models.ThreatActor.gti_id == gti_id).first()
        if existing:
            existing.name = name
            existing.country = country
            existing.aliases = aliases
            existing.active = active
            updated += 1
        else:
            db.add(models.ThreatActor(
                name=name,
                gti_id=gti_id,
                country=country,
                aliases=aliases,
                active=active
            ))
            created += 1

    db.commit()
    return {"status": "ok", "created": created, "updated": updated}


@app.put("/actors/{actor_id}", response_model=schemas.ActorOut)
def update_actor(actor_id: int, actor: schemas.ActorCreate, db: Session = Depends(get_db)):
    updated = crud.update_actor(db, actor_id, actor)
    if not updated:
        return {"error": "actor not found"}
    return updated


@app.patch("/actors/{actor_id}/active")
def set_actor_active(actor_id: int, active: bool, db: Session = Depends(get_db)):
    actor = crud.set_actor_active(db, actor_id, active)
    if not actor:
        return {"error": "actor not found"}
    return {"status": "updated", "id": actor.id, "active": actor.active}


@app.delete("/actors/{actor_id}")
def delete_actor(actor_id: int, db: Session = Depends(get_db)):
    actor = crud.deactivate_actor(db, actor_id)
    if not actor:
        return {"error": "actor not found"}
    return {"status": "deactivated", "id": actor.id}


def _actor_project_tag_to_response(
    row: models.ActorProjectTag,
    actor_name: str,
    project_name: str,
    client_id: int,
    client_name: str
):
    return {
        "id": row.id,
        "actor_id": row.actor_id,
        "actor_name": actor_name,
        "project_id": row.project_id,
        "project_name": project_name,
        "client_id": client_id,
        "client_name": client_name,
        "label": row.label or "Impacto potencial",
        "note": row.note,
        "created_at": utc_to_bogota(row.created_at).isoformat() if row.created_at else None
    }


@app.get("/clients", response_model=list[schemas.ClientOut])
def list_clients(db: Session = Depends(get_db)):
    rows = (
        db.query(models.Client, func.count(models.ClientProject.id).label("projects_count"))
        .outerjoin(models.ClientProject, models.ClientProject.client_id == models.Client.id)
        .group_by(models.Client.id)
        .order_by(models.Client.name.asc())
        .all()
    )
    return [
        {
            "id": c.id,
            "name": c.name,
            "projects_count": int(projects_count or 0)
        }
        for c, projects_count in rows
    ]


@app.post("/clients", response_model=schemas.ClientOut)
def create_client(payload: schemas.ClientCreate, db: Session = Depends(get_db)):
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="client name required")
    existing = db.query(models.Client).filter(func.lower(models.Client.name) == name.lower()).first()
    if existing:
        return {"id": existing.id, "name": existing.name, "projects_count": 0}
    row = models.Client(name=name)
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "name": row.name, "projects_count": 0}


@app.delete("/clients/{client_id}")
def delete_client(client_id: int, db: Session = Depends(get_db)):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="client not found")

    project_ids = [
        p.id for p in db.query(models.ClientProject.id).filter(models.ClientProject.client_id == client_id).all()
    ]
    if project_ids:
        db.query(models.ActorProjectTag).filter(models.ActorProjectTag.project_id.in_(project_ids)).delete(synchronize_session=False)
    db.query(models.ClientProject).filter(models.ClientProject.client_id == client_id).delete(synchronize_session=False)
    db.delete(client)
    db.commit()
    return {"status": "deleted", "id": client_id}


@app.get("/clients/{client_id}/projects", response_model=list[schemas.ClientProjectOut])
def list_client_projects(client_id: int, db: Session = Depends(get_db)):
    rows = (
        db.query(models.ClientProject, models.Client.name.label("client_name"))
        .join(models.Client, models.Client.id == models.ClientProject.client_id)
        .filter(models.ClientProject.client_id == client_id)
        .order_by(models.ClientProject.name.asc())
        .all()
    )
    return [
        {
            "id": p.id,
            "client_id": p.client_id,
            "client_name": client_name,
            "name": p.name
        }
        for p, client_name in rows
    ]


@app.post("/clients/{client_id}/projects", response_model=schemas.ClientProjectOut)
def create_client_project(client_id: int, payload: schemas.ClientProjectCreate, db: Session = Depends(get_db)):
    client = db.query(models.Client).filter(models.Client.id == client_id).first()
    if not client:
        raise HTTPException(status_code=404, detail="client not found")

    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="project name required")

    existing = (
        db.query(models.ClientProject)
        .filter(models.ClientProject.client_id == client_id)
        .filter(func.lower(models.ClientProject.name) == name.lower())
        .first()
    )
    if existing:
        return {
            "id": existing.id,
            "client_id": existing.client_id,
            "client_name": client.name,
            "name": existing.name
        }

    project = models.ClientProject(client_id=client_id, name=name)
    db.add(project)
    db.commit()
    db.refresh(project)
    return {
        "id": project.id,
        "client_id": project.client_id,
        "client_name": client.name,
        "name": project.name
    }


@app.delete("/projects/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db)):
    project = db.query(models.ClientProject).filter(models.ClientProject.id == project_id).first()
    if not project:
        raise HTTPException(status_code=404, detail="project not found")
    db.query(models.ActorProjectTag).filter(models.ActorProjectTag.project_id == project_id).delete(synchronize_session=False)
    db.delete(project)
    db.commit()
    return {"status": "deleted", "id": project_id}


@app.get("/actors/{actor_id}/tags", response_model=list[schemas.ActorProjectTagOut])
def list_actor_tags(actor_id: int, db: Session = Depends(get_db)):
    rows = (
        db.query(
            models.ActorProjectTag,
            models.ThreatActor.name.label("actor_name"),
            models.ClientProject.name.label("project_name"),
            models.Client.id.label("client_id"),
            models.Client.name.label("client_name"),
        )
        .join(models.ThreatActor, models.ThreatActor.id == models.ActorProjectTag.actor_id)
        .join(models.ClientProject, models.ClientProject.id == models.ActorProjectTag.project_id)
        .join(models.Client, models.Client.id == models.ClientProject.client_id)
        .filter(models.ActorProjectTag.actor_id == actor_id)
        .order_by(models.Client.name.asc(), models.ClientProject.name.asc())
        .all()
    )
    return [
        _actor_project_tag_to_response(tag, actor_name, project_name, client_id, client_name)
        for tag, actor_name, project_name, client_id, client_name in rows
    ]


@app.get("/actors-tags", response_model=list[schemas.ActorProjectTagOut])
def list_all_actor_tags(db: Session = Depends(get_db)):
    rows = (
        db.query(
            models.ActorProjectTag,
            models.ThreatActor.name.label("actor_name"),
            models.ClientProject.name.label("project_name"),
            models.Client.id.label("client_id"),
            models.Client.name.label("client_name"),
        )
        .join(models.ThreatActor, models.ThreatActor.id == models.ActorProjectTag.actor_id)
        .join(models.ClientProject, models.ClientProject.id == models.ActorProjectTag.project_id)
        .join(models.Client, models.Client.id == models.ClientProject.client_id)
        .order_by(models.ThreatActor.name.asc(), models.Client.name.asc(), models.ClientProject.name.asc())
        .all()
    )
    return [
        _actor_project_tag_to_response(tag, actor_name, project_name, client_id, client_name)
        for tag, actor_name, project_name, client_id, client_name in rows
    ]


@app.post("/actors/{actor_id}/tags", response_model=schemas.ActorProjectTagOut)
def create_actor_tag(actor_id: int, payload: schemas.ActorProjectTagCreate, db: Session = Depends(get_db)):
    actor = db.query(models.ThreatActor).filter(models.ThreatActor.id == actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="actor not found")

    project_row = (
        db.query(models.ClientProject, models.Client)
        .join(models.Client, models.Client.id == models.ClientProject.client_id)
        .filter(models.ClientProject.id == payload.project_id)
        .first()
    )
    if not project_row:
        raise HTTPException(status_code=404, detail="project not found")

    project, client = project_row
    existing = (
        db.query(models.ActorProjectTag)
        .filter(models.ActorProjectTag.actor_id == actor_id)
        .filter(models.ActorProjectTag.project_id == payload.project_id)
        .first()
    )
    label = (payload.label or "").strip() or "Impacto potencial"
    note = (payload.note or "").strip() or None
    if existing:
        existing.label = label
        existing.note = note
        db.commit()
        db.refresh(existing)
        return _actor_project_tag_to_response(existing, actor.name, project.name, client.id, client.name)

    row = models.ActorProjectTag(
        actor_id=actor_id,
        project_id=payload.project_id,
        label=label,
        note=note,
        created_at=datetime.utcnow()
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return _actor_project_tag_to_response(row, actor.name, project.name, client.id, client.name)


@app.delete("/actors/{actor_id}/tags/{tag_id}")
def delete_actor_tag(actor_id: int, tag_id: int, db: Session = Depends(get_db)):
    row = (
        db.query(models.ActorProjectTag)
        .filter(models.ActorProjectTag.id == tag_id)
        .filter(models.ActorProjectTag.actor_id == actor_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="tag not found")
    db.delete(row)
    db.commit()
    return {"status": "deleted", "id": tag_id}


@app.get("/tags", response_model=list[schemas.TagOut])
def list_tags(db: Session = Depends(get_db)):
    rows = db.query(models.Tag).order_by(models.Tag.name.asc()).all()
    return [{"id": r.id, "name": r.name} for r in rows]


@app.post("/tags", response_model=schemas.TagOut)
def create_tag(payload: schemas.TagCreate, db: Session = Depends(get_db)):
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="tag name required")
    existing = db.query(models.Tag).filter(func.lower(models.Tag.name) == name.lower()).first()
    if existing:
        return {"id": existing.id, "name": existing.name}
    row = models.Tag(name=name, created_at=datetime.utcnow())
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "name": row.name}


@app.delete("/tags/{tag_id}")
def delete_tag(tag_id: int, db: Session = Depends(get_db)):
    row = db.query(models.Tag).filter(models.Tag.id == tag_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="tag not found")
    db.query(models.ActorTag).filter(models.ActorTag.tag_id == tag_id).delete(synchronize_session=False)
    db.delete(row)
    db.commit()
    return {"status": "deleted", "id": tag_id}


def _actor_label_to_response(actor_id: int, actor_name: str, tag_id: int, tag_name: str, created_at: datetime | None):
    return {
        "actor_id": actor_id,
        "actor_name": actor_name,
        "tag_id": tag_id,
        "tag_name": tag_name,
        "created_at": utc_to_bogota(created_at).isoformat() if created_at else None
    }


@app.get("/actors/{actor_id}/labels", response_model=list[schemas.ActorTagOut])
def list_actor_labels(actor_id: int, db: Session = Depends(get_db)):
    rows = (
        db.query(
            models.ActorTag.actor_id,
            models.ThreatActor.name.label("actor_name"),
            models.ActorTag.tag_id,
            models.Tag.name.label("tag_name"),
            models.ActorTag.created_at,
        )
        .join(models.ThreatActor, models.ThreatActor.id == models.ActorTag.actor_id)
        .join(models.Tag, models.Tag.id == models.ActorTag.tag_id)
        .filter(models.ActorTag.actor_id == actor_id)
        .order_by(models.Tag.name.asc())
        .all()
    )
    return [
        _actor_label_to_response(r.actor_id, r.actor_name, r.tag_id, r.tag_name, r.created_at)
        for r in rows
    ]


@app.get("/actors-labels", response_model=list[schemas.ActorTagOut])
def list_all_actor_labels(db: Session = Depends(get_db)):
    rows = (
        db.query(
            models.ActorTag.actor_id,
            models.ThreatActor.name.label("actor_name"),
            models.ActorTag.tag_id,
            models.Tag.name.label("tag_name"),
            models.ActorTag.created_at,
        )
        .join(models.ThreatActor, models.ThreatActor.id == models.ActorTag.actor_id)
        .join(models.Tag, models.Tag.id == models.ActorTag.tag_id)
        .order_by(models.ThreatActor.name.asc(), models.Tag.name.asc())
        .all()
    )
    return [
        _actor_label_to_response(r.actor_id, r.actor_name, r.tag_id, r.tag_name, r.created_at)
        for r in rows
    ]


@app.post("/actors/{actor_id}/labels", response_model=schemas.ActorTagOut)
def assign_actor_label(actor_id: int, payload: schemas.ActorTagAssign, db: Session = Depends(get_db)):
    actor = db.query(models.ThreatActor).filter(models.ThreatActor.id == actor_id).first()
    if not actor:
        raise HTTPException(status_code=404, detail="actor not found")
    tag = db.query(models.Tag).filter(models.Tag.id == payload.tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="tag not found")

    row = (
        db.query(models.ActorTag)
        .filter(models.ActorTag.actor_id == actor_id)
        .filter(models.ActorTag.tag_id == payload.tag_id)
        .first()
    )
    if not row:
        row = models.ActorTag(actor_id=actor_id, tag_id=payload.tag_id, created_at=datetime.utcnow())
        db.add(row)
        db.commit()
        db.refresh(row)

    return _actor_label_to_response(actor.id, actor.name, tag.id, tag.name, row.created_at)


@app.delete("/actors/{actor_id}/labels/{tag_id}")
def remove_actor_label(actor_id: int, tag_id: int, db: Session = Depends(get_db)):
    row = (
        db.query(models.ActorTag)
        .filter(models.ActorTag.actor_id == actor_id)
        .filter(models.ActorTag.tag_id == tag_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="label not found")
    db.delete(row)
    db.commit()
    return {"status": "deleted", "actor_id": actor_id, "tag_id": tag_id}


@app.post("/actors/{actor_id}/scan")
def scan_actor(actor_id: int, db: Session = Depends(get_db)):
    actor = db.query(models.ThreatActor).filter(models.ThreatActor.id == actor_id).first()
    if not actor:
        return {"error": "actor not found"}
    job = _start_job(
        db,
        job_type="actor_scan",
        trigger="manual",
        actor_id=actor.id,
        actor_name=actor.name,
        total_items=1
    )
    _update_job(db, job.id, processed_items=0, total_items=1, details=f"scan:{actor.name}:start")
    try:
        result = update_actor_ttps(db, actor)
        _update_job(db, job.id, processed_items=1, total_items=1, details=f"scan:{actor.name}:{result.get('status')}")
        if result.get("status") == "ok":
            _finish_job_success(db, job.id, details=f"source={result.get('source')} total={result.get('total')}")
        else:
            _finish_job_error(db, job.id, str(result.get("error") or "actor scan error"))
        return {"status": "ok", "actor_id": actor.id, "job_id": job.id, "result": result}
    except Exception as e:
        _finish_job_error(db, job.id, str(e))
        raise


@app.post("/admin/load-mitre")
def load_mitre_endpoint(db: Session = Depends(get_db)):
    load_mitre(db)
    return {"status": "MITRE loaded"}

@app.post("/admin/run-collector")
def run_collector(db: Session = Depends(get_db)):
    actor_count = db.query(models.ThreatActor).filter_by(active=True).count()
    job = _start_job(
        db,
        job_type="collector",
        trigger="manual",
        total_items=actor_count
    )
    try:
        summary = run_collection(
            db,
            progress_callback=lambda processed_items, total_items, details: _update_job(
                db,
                job.id,
                processed_items=processed_items,
                total_items=total_items,
                details=details
            )
        )
        _finish_job_success(db, job.id, details=f"scanned={summary.get('scanned')} skipped={summary.get('skipped')} errors={summary.get('errors')}")
        return {"status": "collection completed", "job_id": job.id, "summary": summary}
    except Exception as e:
        _finish_job_error(db, job.id, str(e))
        raise


@app.post("/admin/run-alerts")
def run_alerts(db: Session = Depends(get_db)):
    run_alert_engine(db)
    return {"status": "alerts generated"}


@app.get("/intel/timeline/{actor_id}", response_model=list[TimelineEvent])
def actor_timeline(actor_id: int, db: Session = Depends(get_db)):
    return get_actor_timeline(db, actor_id)

@app.get("/intel/heatmap", response_model=list[HeatmapItem])
def heatmap(country: str, db: Session = Depends(get_db)):
    return get_heatmap(db, country)


@app.get("/intel/navigator")
def navigator(country: str, db: Session = Depends(get_db)):
    layer = build_navigator_layer(db, country)
    return JSONResponse(content=layer)

@app.get("/intel/trends")
def trends(country: str = "CO", days: int = 7, db: Session = Depends(get_db)):
    return get_trends(db, country, days)


@app.get("/intel/risk")
def risk(country: str = "CO", db: Session = Depends(get_db)):
    return calculate_risk(db, country)


from app.services.matrix_builder import build_matrix

@app.get("/intel/matrix")
def matrix(country: str, db: Session = Depends(get_db)):
    return build_matrix(db, country)

@app.get("/intel/timeline")
def timeline(actor: str, db: Session = Depends(get_db)):
    return get_actor_timeline(db, actor)


@app.get("/alerts")
def get_alerts(db: Session = Depends(get_db)):

    alerts = db.query(models.Alert)\
        .order_by(models.Alert.created_at.desc())\
        .limit(100)\
        .all()

    response = []

    for a in alerts:

        actor_name = a.actor.name if a.actor else None
        technique_id = a.technique.tech_id if a.technique else None
        technique_name = a.technique.name if a.technique else None
        technique_tactic = a.technique.tactic if a.technique else None

        actor_technique = None
        evidence_hashes = []
        first_seen = None
        last_seen = None
        sightings = 0
        seen_days = 0
        thresholds = {"sightings": None, "days": None, "reason": None}
        event_type = None

        if a.actor_id and a.technique_id:
            actor_technique = (
                db.query(models.ActorTechnique)
                .filter(models.ActorTechnique.actor_id == a.actor_id)
                .filter(models.ActorTechnique.technique_id == a.technique_id)
                .first()
            )
            if actor_technique:
                first_seen = utc_to_bogota(actor_technique.first_seen).isoformat() if actor_technique.first_seen else None
                last_seen = utc_to_bogota(actor_technique.last_seen).isoformat() if actor_technique.last_seen else None
                sightings = int(actor_technique.sightings_count or 0)
                seen_days = int(actor_technique.seen_days_count or 0)
                min_s, min_d, reason = get_confirmation_thresholds(a.technique, technique_id)
                thresholds = {"sightings": min_s, "days": min_d, "reason": reason}

            ev = (
                db.query(models.IntelligenceEvent)
                .filter(models.IntelligenceEvent.actor_id == a.actor_id)
                .filter(models.IntelligenceEvent.technique_id == a.technique_id)
                .filter(models.IntelligenceEvent.created_at <= a.created_at)
                .order_by(models.IntelligenceEvent.created_at.desc())
                .first()
            )
            event_type = ev.event_type if ev else None

            evidence_rows = (
                db.query(models.TechniqueEvidence.sample_hash)
                .filter(models.TechniqueEvidence.actor_id == a.actor_id)
                .filter(models.TechniqueEvidence.technique_id == a.technique_id)
                .order_by(models.TechniqueEvidence.observed_at.desc())
                .limit(3)
                .all()
            )
            evidence_hashes = [x[0] for x in evidence_rows if x and x[0]]

        response.append({
            "actor": actor_name,
            "technique": technique_id,
            "technique_name": technique_name,
            "tactic": technique_tactic,
            "title": a.title,
            "description": a.description,
            "severity": a.severity,
            "created_at": utc_to_bogota(a.created_at).isoformat() if a.created_at else None,
            "event_type": event_type,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "sightings_count": sightings,
            "seen_days_count": seen_days,
            "threshold_sightings": thresholds["sightings"],
            "threshold_days": thresholds["days"],
            "threshold_reason": thresholds["reason"],
            "evidence_hashes": evidence_hashes
        })

    return response





@app.get("/intel/adversaries")
def adversary_ranking(country: str, db: Session = Depends(get_db)):
    return calculate_actor_ranking(db, country)


@app.get("/intel/matrix")
def get_matrix(country: str, db: Session = Depends(get_db)):
    return build_country_matrix(db, country)

@app.get("/intel/profile")
def country_profile(country: str, db: Session = Depends(get_db)):
    matrix = build_country_matrix(db, country)
    return build_country_profile(matrix)

@app.get("/intel/predict")
def predict(country: str, db: Session = Depends(get_db)):
    matrix = build_country_matrix(db, country)
    return predict_next_techniques(db, matrix)

# =====================================================
# DASHBOARD SUMMARY
# =====================================================
from sqlalchemy import func
from datetime import datetime, timedelta

@app.get("/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):

    # ---------------- ALERTS 24H ----------------
    alerts_24h = db.query(models.Alert)\
        .filter(models.Alert.created_at >= datetime.utcnow() - timedelta(hours=24))\
        .count()

    # ---------------- ACTORS ----------------
    active_actors = db.query(models.ThreatActor)\
        .filter(models.ThreatActor.active == True)\
        .count()

    # ---------------- TECHNIQUES ----------------
    techniques = db.query(models.ActorTechnique)\
        .filter(models.ActorTechnique.active == True)\
        .count()

    # ---------------- COUNTRY RISK (ULTIMO SNAPSHOT) ----------------
    latest = db.query(
        models.CountryRiskSnapshot.country,
        func.max(models.CountryRiskSnapshot.created_at).label("max_date")
    ).group_by(models.CountryRiskSnapshot.country).subquery()

    risk_rows = db.query(models.CountryRiskSnapshot)\
        .join(latest,
              (models.CountryRiskSnapshot.country == latest.c.country) &
              (models.CountryRiskSnapshot.created_at == latest.c.max_date)
        ).all()

    country_risk = [
        {
            "country": r.country,
            "risk_score": r.risk_score
        }
        for r in risk_rows
    ]

    return {
        "alerts_24h": alerts_24h,
        "active_actors": active_actors,
        "techniques": techniques,
        "country_risk": country_risk
    }


@app.get("/dashboard/attackers-by-label")
def dashboard_attackers_by_label(db: Session = Depends(get_db)):
    rows = (
        db.query(
            models.Tag.name.label("label"),
            func.count(func.distinct(models.ActorTag.actor_id)).label("attackers"),
        )
        .join(models.ActorTag, models.ActorTag.tag_id == models.Tag.id)
        .join(models.ThreatActor, models.ThreatActor.id == models.ActorTag.actor_id)
        .filter(models.ThreatActor.active == True)
        .group_by(models.Tag.id, models.Tag.name)
        .order_by(func.count(func.distinct(models.ActorTag.actor_id)).desc(), models.Tag.name.asc())
        .all()
    )

    return [
        {
            "label": label,
            "attackers": int(attackers or 0),
        }
        for label, attackers in rows
    ]


@app.get("/dashboard/weekly-comparison")
def weekly_comparison(db: Session = Depends(get_db)):
    now = datetime.utcnow()
    start_this = now - timedelta(days=7)
    start_prev = now - timedelta(days=14)

    this_week_new = (
        db.query(models.IntelligenceEvent)
        .filter(models.IntelligenceEvent.event_type == "NEW")
        .filter(models.IntelligenceEvent.created_at >= start_this)
        .count()
    )
    prev_week_new = (
        db.query(models.IntelligenceEvent)
        .filter(models.IntelligenceEvent.event_type == "NEW")
        .filter(models.IntelligenceEvent.created_at >= start_prev)
        .filter(models.IntelligenceEvent.created_at < start_this)
        .count()
    )

    tactic_rows_this = (
        db.query(models.Technique.tactic)
        .join(models.IntelligenceEvent, models.IntelligenceEvent.technique_id == models.Technique.id)
        .filter(models.IntelligenceEvent.event_type == "NEW")
        .filter(models.IntelligenceEvent.created_at >= start_this)
        .all()
    )
    tactic_rows_prev = (
        db.query(models.Technique.tactic)
        .join(models.IntelligenceEvent, models.IntelligenceEvent.technique_id == models.Technique.id)
        .filter(models.IntelligenceEvent.event_type == "NEW")
        .filter(models.IntelligenceEvent.created_at >= start_prev)
        .filter(models.IntelligenceEvent.created_at < start_this)
        .all()
    )

    def _count_tactics(rows):
        counter = {}
        for (tactic_str,) in rows:
            for t in [x.strip().lower() for x in (tactic_str or "").split(",") if x.strip()]:
                counter[t] = counter.get(t, 0) + 1
        return counter

    this_counter = _count_tactics(tactic_rows_this)
    prev_counter = _count_tactics(tactic_rows_prev)
    all_tactics = sorted(set(this_counter.keys()) | set(prev_counter.keys()))

    by_tactic = [
        {
            "tactic": t,
            "this_week": this_counter.get(t, 0),
            "prev_week": prev_counter.get(t, 0),
            "delta": this_counter.get(t, 0) - prev_counter.get(t, 0)
        }
        for t in all_tactics
    ]
    by_tactic.sort(key=lambda x: x["delta"], reverse=True)

    return {
        "this_week_new": this_week_new,
        "prev_week_new": prev_week_new,
        "delta_new": this_week_new - prev_week_new,
        "by_tactic": by_tactic[:12]
    }


@app.get("/dashboard/tactic-chains")
def tactic_chains(days: int = 7, db: Session = Depends(get_db)):
    days = max(1, min(int(days), 90))
    since = datetime.utcnow() - timedelta(days=days)
    critical = {"initial-access", "privilege-escalation", "command-and-control", "lateral-movement"}

    rows = (
        db.query(models.ThreatActor.name, models.Technique.tactic, models.ActorTechnique.last_seen)
        .join(models.ActorTechnique, models.ActorTechnique.actor_id == models.ThreatActor.id)
        .join(models.Technique, models.Technique.id == models.ActorTechnique.technique_id)
        .filter(models.ThreatActor.active == True)
        .filter(models.ActorTechnique.active == True)
        .filter(models.ActorTechnique.last_seen >= since)
        .all()
    )

    by_actor = {}
    for actor_name, tactic_str, last_seen in rows:
        if actor_name not in by_actor:
            by_actor[actor_name] = {"tactics": set(), "last_seen": last_seen}
        if last_seen and (by_actor[actor_name]["last_seen"] is None or last_seen > by_actor[actor_name]["last_seen"]):
            by_actor[actor_name]["last_seen"] = last_seen
        for t in [x.strip().lower() for x in (tactic_str or "").split(",") if x.strip()]:
            by_actor[actor_name]["tactics"].add(t)

    chains = []
    for actor_name, info in by_actor.items():
        tactics = info["tactics"]
        matched_critical = sorted(list(tactics & critical))
        if len(matched_critical) >= 3:
            chains.append({
                "actor": actor_name,
                "critical_tactics": matched_critical,
                "tactic_count": len(tactics),
                "last_seen": utc_to_bogota(info["last_seen"]).isoformat() if info["last_seen"] else None,
                "risk_level": "HIGH"
            })

    chains.sort(key=lambda x: (len(x["critical_tactics"]), x["tactic_count"]), reverse=True)
    return {"window_days": days, "chains": chains}


@app.get("/dashboard/kpis")
def quality_kpis(days: int = 30, db: Session = Depends(get_db)):
    days = max(7, min(int(days), 365))
    since = datetime.utcnow() - timedelta(days=days)

    new_events = (
        db.query(models.IntelligenceEvent)
        .filter(models.IntelligenceEvent.event_type == "NEW")
        .filter(models.IntelligenceEvent.created_at >= since)
        .all()
    )
    new_total = len(new_events)

    persisted_7d = 0
    confirm_lags = []

    for e in new_events:
        at = (
            db.query(models.ActorTechnique)
            .filter(models.ActorTechnique.actor_id == e.actor_id)
            .filter(models.ActorTechnique.technique_id == e.technique_id)
            .first()
        )
        if not at:
            continue
        if at.last_seen and e.created_at and (at.last_seen - e.created_at).days >= 7:
            persisted_7d += 1
        if at.first_seen and e.created_at:
            lag_hours = (e.created_at - at.first_seen).total_seconds() / 3600.0
            if lag_hours >= 0:
                confirm_lags.append(lag_hours)

    false_noise_avoided = (
        db.query(models.ActorTechnique)
        .filter(models.ActorTechnique.active == True)
        .filter((models.ActorTechnique.sightings_count <= 1) & (models.ActorTechnique.seen_days_count <= 1))
        .count()
    )

    return {
        "window_days": days,
        "new_confirmed_total": new_total,
        "new_confirmed_persist_7d": persisted_7d,
        "persist_ratio": round((persisted_7d / new_total), 3) if new_total else 0.0,
        "avg_hours_first_seen_to_confirmed_new": round(sum(confirm_lags) / len(confirm_lags), 2) if confirm_lags else None,
        "noise_signals_current": false_noise_avoided
    }


@app.get("/dashboard/new-tactics-today")
def new_tactics_today(limit: int = 20, db: Session = Depends(get_db)):
    limit = max(1, min(int(limit), 100))

    now_bogota = datetime.now(BOGOTA_TZ)
    start_bogota = now_bogota.replace(hour=0, minute=0, second=0, microsecond=0)
    end_bogota = start_bogota + timedelta(days=1)

    start_utc = start_bogota.astimezone(timezone.utc).replace(tzinfo=None)
    end_utc = end_bogota.astimezone(timezone.utc).replace(tzinfo=None)

    # Todas las detecciones NEW para construir primera vez histórica por táctica
    historical_rows = (
        db.query(models.Technique.tactic, models.IntelligenceEvent.created_at)
        .join(models.IntelligenceEvent, models.IntelligenceEvent.technique_id == models.Technique.id)
        .filter(models.IntelligenceEvent.event_type == "NEW")
        .all()
    )

    first_seen_by_tactic = {}
    for tactic_str, created_at in historical_rows:
        if not tactic_str or not created_at:
            continue
        tactics = [t.strip().lower() for t in tactic_str.split(",") if t.strip()]
        for t in tactics:
            prev = first_seen_by_tactic.get(t)
            if prev is None or created_at < prev:
                first_seen_by_tactic[t] = created_at

    # Detecciones NEW solo de hoy (hora Bogotá)
    today_rows = (
        db.query(
            models.Technique.tactic,
            models.Technique.tech_id,
            models.Technique.name,
            models.ThreatActor.name,
            models.IntelligenceEvent.created_at
        )
        .join(models.IntelligenceEvent, models.IntelligenceEvent.technique_id == models.Technique.id)
        .join(models.ThreatActor, models.ThreatActor.id == models.IntelligenceEvent.actor_id)
        .filter(models.IntelligenceEvent.event_type == "NEW")
        .filter(models.IntelligenceEvent.created_at >= start_utc)
        .filter(models.IntelligenceEvent.created_at < end_utc)
        .all()
    )

    by_tactic = {}
    for tactic_str, tech_id, tech_name, actor_name, created_at in today_rows:
        if not tactic_str:
            continue
        tactics = [t.strip().lower() for t in tactic_str.split(",") if t.strip()]
        for t in tactics:
            if t not in by_tactic:
                by_tactic[t] = {
                    "tactic": t,
                    "first_seen_at": created_at,
                    "actors": set(),
                    "techniques": {},
                }
            by_tactic[t]["actors"].add(actor_name)
            if tech_id:
                by_tactic[t]["techniques"][tech_id] = tech_name
            if created_at and created_at < by_tactic[t]["first_seen_at"]:
                by_tactic[t]["first_seen_at"] = created_at

    items = []
    for tactic, data in by_tactic.items():
        first_seen = first_seen_by_tactic.get(tactic)
        if not first_seen:
            continue
        # Solo tácticas que históricamente aparecen por primera vez hoy
        if not (start_utc <= first_seen < end_utc):
            continue

        items.append({
            "tactic": tactic,
            "label": " ".join([w.capitalize() for w in tactic.split("-")]),
            "first_seen_at": utc_to_bogota(data["first_seen_at"]).isoformat() if data["first_seen_at"] else None,
            "actor_count": len(data["actors"]),
            "technique_count": len(data["techniques"]),
            "actors": sorted(list(data["actors"]))[:5],
            "techniques": [
                {"technique": k, "name": v}
                for k, v in list(data["techniques"].items())[:5]
            ],
        })

    items.sort(key=lambda x: (x["actor_count"], x["technique_count"]), reverse=True)
    items = items[:limit]

    return {
        "date": now_bogota.strftime("%Y-%m-%d"),
        "new_tactics_count": len(items),
        "new_events_today": len(today_rows),
        "items": items
    }



@app.get("/dashboard/risk-timeline/{country}")
def risk_timeline(country: str, db: Session = Depends(get_db)):

    rows = db.query(models.CountryRiskSnapshot)\
        .filter(models.CountryRiskSnapshot.country == country)\
        .order_by(models.CountryRiskSnapshot.created_at.asc())\
        .limit(200)\
        .all()

    data = [
        {
            "time": utc_to_bogota(r.created_at).strftime("%H:%M") if r.created_at else "",
            "risk": float(r.risk_score)
        }
        for r in rows
    ]

    return data

# =====================================================
# RISK TREND
# =====================================================
@app.get("/dashboard/risk-trend")
def risk_trend(db: Session = Depends(get_db)):

    snapshots = db.query(models.CountryRiskSnapshot)\
        .order_by(models.CountryRiskSnapshot.created_at.asc())\
        .limit(50)\
        .all()

    return [
        {
            "date": utc_to_bogota(s.created_at).isoformat() if s.created_at else None,
            "risk": s.risk_score
        }
        for s in snapshots
    ]


@app.get("/dashboard/timeline")
def dashboard_timeline(days: int = 30, db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=max(1, days))
    events = (
        db.query(models.IntelligenceEvent)
        .filter(models.IntelligenceEvent.created_at >= since)
        .order_by(models.IntelligenceEvent.created_at.asc())
        .all()
    )

    buckets = {}
    for e in events:
        dt = utc_to_bogota(e.created_at)
        if not dt:
            continue
        key = dt.strftime("%Y-%m-%d")
        if key not in buckets:
            buckets[key] = {"date": key, "NEW": 0, "REACTIVATED": 0, "DISAPPEARED": 0}
        if e.event_type in buckets[key]:
            buckets[key][e.event_type] += 1

    return [buckets[k] for k in sorted(buckets.keys())]


@app.get("/dashboard/ttp-scatter")
def ttp_scatter(days: int = 30, limit: int = 200, db: Session = Depends(get_db)):
    limit = max(1, min(int(limit), 500))
    since = datetime.utcnow() - timedelta(days=max(1, days))

    # Base: actor count per technique
    base_rows = (
        db.query(
            models.Technique.id,
            models.Technique.tech_id,
            models.Technique.name,
            func.count(func.distinct(models.ActorTechnique.actor_id)).label("actor_count")
        )
        .join(models.ActorTechnique, models.ActorTechnique.technique_id == models.Technique.id)
        .filter(models.ActorTechnique.active == True)
        .group_by(models.Technique.id)
        .order_by(func.count(func.distinct(models.ActorTechnique.actor_id)).desc())
        .limit(limit)
        .all()
    )

    tech_ids = [r.id for r in base_rows]

    # Alert severity average in last N days
    severity_case = case(
        (models.Alert.severity == "HIGH", 3),
        (models.Alert.severity == "MEDIUM", 2),
        (models.Alert.severity == "LOW", 1),
        else_=0
    )

    alert_rows = (
        db.query(
            models.Technique.id.label("tech_id"),
            func.avg(severity_case).label("severity_avg"),
            func.count(models.Alert.id).label("alert_count")
        )
        .join(models.Alert, models.Alert.technique_id == models.Technique.id)
        .filter(models.Alert.created_at >= since)
        .filter(models.Technique.id.in_(tech_ids))
        .group_by(models.Technique.id)
        .all()
    )

    alert_map = {r.tech_id: {"severity_avg": float(r.severity_avg or 0), "alert_count": int(r.alert_count or 0)} for r in alert_rows}

    result = []
    for r in base_rows:
        meta = alert_map.get(r.id, {"severity_avg": 0, "alert_count": 0})
        result.append({
            "technique": r.tech_id,
            "name": r.name,
            "actor_count": int(r.actor_count or 0),
            "severity_avg": meta["severity_avg"],
            "alert_count": meta["alert_count"]
        })

    return result

# =====================================================
# SCHEDULE CONFIG (GLOBAL)
# =====================================================
@app.get("/schedule")
def get_schedule(db: Session = Depends(get_db)):
    cfg = db.query(models.ScheduleConfig).first()
    if not cfg:
        cfg = models.ScheduleConfig(time_hhmm="06:00", days="mon,tue,wed,thu,fri", enabled=True)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    days = [d for d in (cfg.days or "").split(",") if d]
    return {
        "time_hhmm": cfg.time_hhmm,
        "days": days,
        "enabled": cfg.enabled,
        "last_run_at": utc_to_bogota(cfg.last_run_at).isoformat() if cfg.last_run_at else None
    }


@app.put("/schedule")
def update_schedule(payload: schemas.ScheduleUpdate, db: Session = Depends(get_db)):
    time_hhmm = _parse_time_hhmm((payload.time_hhmm or "").strip())
    if not time_hhmm:
        raise HTTPException(status_code=400, detail="time_hhmm must be in HH:MM 24h format")
    days = ",".join([d.lower() for d in payload.days])

    cfg = db.query(models.ScheduleConfig).first()
    if not cfg:
        cfg = models.ScheduleConfig()
        db.add(cfg)

    cfg.time_hhmm = time_hhmm
    cfg.days = days
    cfg.enabled = bool(payload.enabled)
    cfg.updated_at = datetime.utcnow()
    db.commit()

    return {"status": "ok"}


# =====================================================
# MITRE SYNC (WEEKLY)
# =====================================================
@app.get("/mitre/schedule")
def get_mitre_schedule(db: Session = Depends(get_db)):
    cfg = db.query(models.MitreSyncConfig).first()
    if not cfg:
        cfg = models.MitreSyncConfig(day_of_week="sun", time_hhmm="03:00", enabled=True)
        db.add(cfg)
        db.commit()
        db.refresh(cfg)
    return {
        "day_of_week": cfg.day_of_week,
        "time_hhmm": cfg.time_hhmm,
        "enabled": cfg.enabled,
        "last_run_at": utc_to_bogota(cfg.last_run_at).isoformat() if cfg.last_run_at else None
    }


@app.put("/mitre/schedule")
def update_mitre_schedule(day_of_week: str, time_hhmm: str, enabled: bool = True, db: Session = Depends(get_db)):
    day = (day_of_week or "").lower()
    if day not in ["mon","tue","wed","thu","fri","sat","sun"]:
        raise HTTPException(status_code=400, detail="day_of_week must be mon..sun")
    time_hhmm = _parse_time_hhmm((time_hhmm or "").strip())
    if not time_hhmm:
        raise HTTPException(status_code=400, detail="time_hhmm must be in HH:MM 24h format")

    cfg = db.query(models.MitreSyncConfig).first()
    if not cfg:
        cfg = models.MitreSyncConfig()
        db.add(cfg)

    cfg.day_of_week = day
    cfg.time_hhmm = time_hhmm
    cfg.enabled = bool(enabled)
    cfg.updated_at = datetime.utcnow()
    db.commit()

    return {"status": "ok"}


@app.post("/admin/update-mitre")
def update_mitre_now(db: Session = Depends(get_db)):
    job = _start_job(db, job_type="mitre_sync", trigger="manual", total_items=2)
    try:
        _update_job(db, job.id, processed_items=0, total_items=2, details="load_mitre:start")
        load_mitre(db)
        _update_job(db, job.id, processed_items=1, total_items=2, details="sync_mitre_from_github:start")
        result = sync_mitre_from_github(db)
        _update_job(db, job.id, processed_items=2, total_items=2, details="mitre sync done")
        _finish_job_success(db, job.id, details=f"updated={result.get('updated', 0)} created={result.get('created', 0)}")
        return {"status": "ok", "job_id": job.id, **result}
    except Exception as e:
        _finish_job_error(db, job.id, str(e))
        raise
# =====================================================
# TOP TECHNIQUES
# =====================================================
from sqlalchemy import func

@app.get("/dashboard/top-ttps")
def top_ttps(limit: int = 10, recency_days: int = 30, suppress_noise: bool = True, db: Session = Depends(get_db)):
    limit = max(1, min(int(limit), 50))
    recency_days = max(1, min(int(recency_days), 180))

    tactic_weights = {
        "initial-access": 1.00,
        "privilege-escalation": 1.00,
        "credential-access": 0.95,
        "defense-evasion": 0.90,
        "lateral-movement": 0.90,
        "command-and-control": 0.95,
        "persistence": 0.85,
        "execution": 0.80,
        "impact": 0.85,
        "exfiltration": 0.85,
        "discovery": 0.60,
        "collection": 0.60,
        "reconnaissance": 0.50,
        "resource-development": 0.50
    }

    rows = (
        db.query(
            models.Technique.tech_id,
            models.Technique.name,
            models.Technique.tactic,
            func.count(func.distinct(models.ActorTechnique.actor_id)).label("actor_count"),
            func.sum(
                case(
                    (
                        (models.ActorTechnique.sightings_count >= 2) |
                        (models.ActorTechnique.seen_days_count >= 2),
                        1
                    ),
                    else_=0
                )
            ).label("stable_actor_count"),
            func.count(models.ActorTechnique.id).label("observations"),
            func.max(models.ActorTechnique.last_seen).label("last_seen"),
        )
        .join(models.ActorTechnique, models.ActorTechnique.technique_id == models.Technique.id)
        .filter(models.ActorTechnique.active == True)
        .group_by(models.Technique.id, models.Technique.tech_id, models.Technique.name, models.Technique.tactic)
        .all()
    )

    ranked = []
    for tech_id, name, tactic, actor_count, stable_actor_count, observations, last_seen in rows:
        if suppress_noise and int(stable_actor_count or 0) == 0:
            continue

        tactic_names = [t.strip().lower() for t in (tactic or "").split(",") if t.strip()]
        tactic_weight = max([tactic_weights.get(t, 0.60) for t in tactic_names], default=0.60)

        if last_seen:
            days_since_seen = (datetime.utcnow() - last_seen).days
            recency_score = max(0.0, 1.0 - (days_since_seen / recency_days))
        else:
            recency_score = 0.0

        impact_score = (
            (float(actor_count or 0) * 0.55) +
            (float(observations or 0) * 0.10) +
            (tactic_weight * 2.5) +
            (recency_score * 2.0)
        )

        ranked.append({
            "technique": tech_id,
            "name": name,
            "tactic": tactic,
            "actor_count": int(actor_count or 0),
            "stable_actor_count": int(stable_actor_count or 0),
            "observations": int(observations or 0),
            "last_seen": utc_to_bogota(last_seen).isoformat() if last_seen else None,
            "tactic_weight": round(tactic_weight, 2),
            "recency_score": round(recency_score, 2),
            "impact_score": round(impact_score, 2),
            # compatibilidad con frontend previo
            "count": int(actor_count or 0)
        })

    ranked.sort(key=lambda x: x["impact_score"], reverse=True)
    return ranked[:limit]

# ---------------------------------------------------------
# RISK TIMELINE (grafica principal)
# ---------------------------------------------------------
@app.get("/dashboard/risk-timeline")
def risk_timeline(country: str = "CO", db: Session = Depends(get_db)):

    rows = db.query(models.CountryRiskSnapshot)\
        .filter(models.CountryRiskSnapshot.country == country)\
        .order_by(models.CountryRiskSnapshot.created_at)\
        .all()

    return [
        {
            "date": utc_to_bogota(r.created_at).isoformat() if r.created_at else None,
            "risk": float(r.risk_score)
        }
        for r in rows
    ]

# ---------------------------------------------------------
# TACTICS DISTRIBUTION (heatmap MITRE)
# ---------------------------------------------------------
@app.get("/dashboard/tactics")
def tactics_distribution(country: str = "CO", db: Session = Depends(get_db)):

    actors = db.query(models.ThreatActor)\
        .filter_by(country=country, active=True)\
        .all()

    actor_ids = [a.id for a in actors]

    rows = db.query(models.Technique.tactic)\
        .join(models.ActorTechnique, models.ActorTechnique.technique_id == models.Technique.id)\
        .filter(models.ActorTechnique.actor_id.in_(actor_ids))\
        .filter(models.ActorTechnique.active == True)\
        .all()

    counter = {}

    for (tactic_str,) in rows:

        if not tactic_str:
            continue

        tactics = tactic_str.split(",")

        for t in tactics:
            t = t.strip()

            if t not in counter:
                counter[t] = 0

            counter[t] += 1

    return counter

# =====================================================
# MITRE MATRIX (GLOBAL / BY ACTOR)
# =====================================================
@app.get("/mitre/matrix")
def mitre_matrix(actor_id: int | None = None, limit: int = 200, db: Session = Depends(get_db)):
    limit = max(1, min(int(limit), 500))

    query = (
        db.query(
            models.Technique,
            func.count(func.distinct(models.ActorTechnique.actor_id)).label("actor_count")
        )
        .join(models.ActorTechnique, models.ActorTechnique.technique_id == models.Technique.id)
        .filter(models.ActorTechnique.active == True)
    )

    if actor_id:
        query = query.filter(models.ActorTechnique.actor_id == actor_id)

    rows = (
        query.group_by(models.Technique.id)
        .order_by(func.count(func.distinct(models.ActorTechnique.actor_id)).desc())
        .limit(limit)
        .all()
    )

    items = []
    for technique, actor_count in rows:
        tactics = (technique.tactic or "").split(",")
        for t in tactics:
            t = t.strip().lower()
            if not t:
                continue
            items.append({
                "tactic": t,
                "technique": technique.tech_id,
                "name": technique.name,
                "count": int(actor_count),
                "actor_count": int(actor_count)
            })

    return items


@app.get("/techniques/{tech_id}")
def technique_detail(tech_id: str, db: Session = Depends(get_db)):
    technique = db.query(models.Technique).filter(models.Technique.tech_id == tech_id).first()
    if not technique:
        return {"error": "technique not found"}

    actors = (
        db.query(models.ThreatActor)
        .join(models.ActorTechnique, models.ActorTechnique.actor_id == models.ThreatActor.id)
        .filter(models.ActorTechnique.technique_id == technique.id)
        .filter(models.ActorTechnique.active == True)
        .filter(models.ThreatActor.active == True)
        .all()
    )

    return {
        "technique": {
            "tech_id": technique.tech_id,
            "name": technique.name,
            "tactic": technique.tactic,
            "description": technique.description
        },
        "actors": [
            {
                "id": a.id,
                "name": a.name,
                "country": a.country
            }
            for a in actors
        ]
    }


@app.get("/techniques")
def techniques_list(search: str | None = None, limit: int = 100, db: Session = Depends(get_db)):
    limit = max(1, min(int(limit), 500))
    query = db.query(models.Technique)
    if search:
        q = f"%{search.strip()}%"
        query = query.filter(
            (models.Technique.tech_id.ilike(q)) |
            (models.Technique.name.ilike(q)) |
            (models.Technique.tactic.ilike(q))
        )
    rows = query.order_by(models.Technique.tech_id.asc()).limit(limit).all()
    return [
        {
            "id": t.id,
            "technique": t.tech_id,
            "name": t.name,
            "tactic": t.tactic
        }
        for t in rows
    ]


@app.get("/detections/use-cases")
def list_use_cases(include_disabled: bool = True, db: Session = Depends(get_db)):
    query = db.query(models.DetectionUseCase)
    if not include_disabled:
        query = query.filter(models.DetectionUseCase.enabled == True)
    rows = query.order_by(models.DetectionUseCase.updated_at.desc()).all()
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "severity": r.severity,
            "enabled": r.enabled,
            "country_scope": r.country_scope,
            "created_at": utc_to_bogota(r.created_at).isoformat() if r.created_at else None,
            "updated_at": utc_to_bogota(r.updated_at).isoformat() if r.updated_at else None
        }
        for r in rows
    ]


@app.post("/detections/use-cases")
def create_use_case(payload: dict = Body(...), db: Session = Depends(get_db)):
    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="name is required")

    existing = db.query(models.DetectionUseCase).filter(models.DetectionUseCase.name == name).first()
    if existing:
        raise HTTPException(status_code=409, detail="use case already exists")

    uc = models.DetectionUseCase(
        name=name,
        description=(payload.get("description") or "").strip() or None,
        severity=(payload.get("severity") or "MEDIUM").upper(),
        enabled=bool(payload.get("enabled", True)),
        country_scope=(payload.get("country_scope") or "").strip() or None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.add(uc)
    db.commit()
    db.refresh(uc)
    return {"status": "ok", "id": uc.id}


@app.put("/detections/use-cases/{use_case_id}")
def update_use_case(use_case_id: int, payload: dict = Body(...), db: Session = Depends(get_db)):
    uc = db.query(models.DetectionUseCase).filter(models.DetectionUseCase.id == use_case_id).first()
    if not uc:
        raise HTTPException(status_code=404, detail="use case not found")

    if "name" in payload:
        next_name = (payload.get("name") or "").strip()
        if not next_name:
            raise HTTPException(status_code=400, detail="name cannot be empty")
        other = (
            db.query(models.DetectionUseCase)
            .filter(models.DetectionUseCase.name == next_name)
            .filter(models.DetectionUseCase.id != use_case_id)
            .first()
        )
        if other:
            raise HTTPException(status_code=409, detail="use case name already exists")
        uc.name = next_name

    if "description" in payload:
        uc.description = (payload.get("description") or "").strip() or None
    if "severity" in payload:
        uc.severity = (payload.get("severity") or "MEDIUM").upper()
    if "enabled" in payload:
        uc.enabled = bool(payload.get("enabled"))
    if "country_scope" in payload:
        uc.country_scope = (payload.get("country_scope") or "").strip() or None

    uc.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "ok"}


@app.delete("/detections/use-cases/{use_case_id}")
def delete_use_case(use_case_id: int, db: Session = Depends(get_db)):
    uc = db.query(models.DetectionUseCase).filter(models.DetectionUseCase.id == use_case_id).first()
    if not uc:
        raise HTTPException(status_code=404, detail="use case not found")

    db.query(models.DetectionCondition).filter(models.DetectionCondition.use_case_id == use_case_id).delete(synchronize_session=False)
    db.delete(uc)
    db.commit()
    return {"status": "ok"}


@app.get("/detections/use-cases/{use_case_id}")
def get_use_case(use_case_id: int, db: Session = Depends(get_db)):
    uc = db.query(models.DetectionUseCase).filter(models.DetectionUseCase.id == use_case_id).first()
    if not uc:
        raise HTTPException(status_code=404, detail="use case not found")

    conds = (
        db.query(models.DetectionCondition, models.Technique)
        .outerjoin(models.Technique, models.Technique.id == models.DetectionCondition.technique_id)
        .filter(models.DetectionCondition.use_case_id == use_case_id)
        .order_by(models.DetectionCondition.id.asc())
        .all()
    )

    conditions = []
    for c, t in conds:
        conditions.append({
            "id": c.id,
            "tactic": c.tactic,
            "technique_id": c.technique_id,
            "technique": t.tech_id if t else None,
            "technique_name": t.name if t else None,
            "procedure": c.procedure,
            "min_sightings": c.min_sightings,
            "min_days": c.min_days
        })

    return {
        "id": uc.id,
        "name": uc.name,
        "description": uc.description,
        "severity": uc.severity,
        "enabled": uc.enabled,
        "country_scope": uc.country_scope,
        "conditions": conditions
    }


@app.post("/detections/use-cases/{use_case_id}/conditions")
def create_condition(use_case_id: int, payload: dict = Body(...), db: Session = Depends(get_db)):
    uc = db.query(models.DetectionUseCase).filter(models.DetectionUseCase.id == use_case_id).first()
    if not uc:
        raise HTTPException(status_code=404, detail="use case not found")

    technique_id = payload.get("technique_id")
    if technique_id:
        technique = db.query(models.Technique).filter(models.Technique.id == technique_id).first()
        if not technique:
            raise HTTPException(status_code=400, detail="invalid technique_id")

    cond = models.DetectionCondition(
        use_case_id=use_case_id,
        tactic=(payload.get("tactic") or "").strip().lower() or None,
        technique_id=technique_id,
        procedure=(payload.get("procedure") or "").strip() or None,
        min_sightings=max(1, int(payload.get("min_sightings", 1))),
        min_days=max(1, int(payload.get("min_days", 1))),
        created_at=datetime.utcnow()
    )
    db.add(cond)
    uc.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(cond)
    return {"status": "ok", "id": cond.id}


@app.put("/detections/conditions/{condition_id}")
def update_condition(condition_id: int, payload: dict = Body(...), db: Session = Depends(get_db)):
    cond = db.query(models.DetectionCondition).filter(models.DetectionCondition.id == condition_id).first()
    if not cond:
        raise HTTPException(status_code=404, detail="condition not found")

    if "tactic" in payload:
        cond.tactic = (payload.get("tactic") or "").strip().lower() or None
    if "technique_id" in payload:
        technique_id = payload.get("technique_id")
        if technique_id:
            technique = db.query(models.Technique).filter(models.Technique.id == technique_id).first()
            if not technique:
                raise HTTPException(status_code=400, detail="invalid technique_id")
        cond.technique_id = technique_id
    if "procedure" in payload:
        cond.procedure = (payload.get("procedure") or "").strip() or None
    if "min_sightings" in payload:
        cond.min_sightings = max(1, int(payload.get("min_sightings")))
    if "min_days" in payload:
        cond.min_days = max(1, int(payload.get("min_days")))

    uc = db.query(models.DetectionUseCase).filter(models.DetectionUseCase.id == cond.use_case_id).first()
    if uc:
        uc.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "ok"}


@app.delete("/detections/conditions/{condition_id}")
def delete_condition(condition_id: int, db: Session = Depends(get_db)):
    cond = db.query(models.DetectionCondition).filter(models.DetectionCondition.id == condition_id).first()
    if not cond:
        raise HTTPException(status_code=404, detail="condition not found")
    uc = db.query(models.DetectionUseCase).filter(models.DetectionUseCase.id == cond.use_case_id).first()
    db.delete(cond)
    if uc:
        uc.updated_at = datetime.utcnow()
    db.commit()
    return {"status": "ok"}


@app.get("/detections/use-cases/{use_case_id}/matches")
def use_case_matches(use_case_id: int, db: Session = Depends(get_db)):
    uc = db.query(models.DetectionUseCase).filter(models.DetectionUseCase.id == use_case_id).first()
    if not uc:
        raise HTTPException(status_code=404, detail="use case not found")

    conditions = db.query(models.DetectionCondition).filter(models.DetectionCondition.use_case_id == use_case_id).all()
    if not conditions:
        return {"use_case_id": use_case_id, "matches": []}

    actors_query = db.query(models.ThreatActor).filter(models.ThreatActor.active == True)
    if uc.country_scope:
        actors_query = actors_query.filter(models.ThreatActor.country == uc.country_scope)
    actors = actors_query.all()

    matches = []
    for actor in actors:
        passed = []
        for cond in conditions:
            q = (
                db.query(models.ActorTechnique, models.Technique)
                .join(models.Technique, models.Technique.id == models.ActorTechnique.technique_id)
                .filter(models.ActorTechnique.actor_id == actor.id)
                .filter(models.ActorTechnique.active == True)
            )
            if cond.technique_id:
                q = q.filter(models.ActorTechnique.technique_id == cond.technique_id)
            if cond.tactic:
                q = q.filter(models.Technique.tactic.ilike(f"%{cond.tactic}%"))
            if cond.procedure:
                proc = f"%{cond.procedure}%"
                q = q.filter(
                    (models.Technique.name.ilike(proc)) |
                    (models.Technique.description.ilike(proc))
                )

            rows = q.all()
            ok_rows = []
            for at, t in rows:
                sightings = int(at.sightings_count or 0)
                days = int(at.seen_days_count or 0)
                if sightings >= cond.min_sightings and days >= cond.min_days:
                    ok_rows.append({
                        "technique": t.tech_id if t else None,
                        "technique_name": t.name if t else None,
                        "tactic": t.tactic if t else None,
                        "sightings_count": sightings,
                        "seen_days_count": days,
                        "last_seen": utc_to_bogota(at.last_seen).isoformat() if at.last_seen else None
                    })

            if ok_rows:
                passed.append({
                    "condition_id": cond.id,
                    "tactic": cond.tactic,
                    "technique_id": cond.technique_id,
                    "procedure": cond.procedure,
                    "min_sightings": cond.min_sightings,
                    "min_days": cond.min_days,
                    "evidence": ok_rows[:5]
                })

        if len(passed) == len(conditions):
            matches.append({
                "actor_id": actor.id,
                "actor": actor.name,
                "country": actor.country,
                "matched_conditions": len(passed),
                "total_conditions": len(conditions),
                "details": passed
            })

    matches.sort(key=lambda x: x["matched_conditions"], reverse=True)
    return {"use_case_id": uc.id, "use_case_name": uc.name, "matches": matches}

# ---------------------------------------------------------
# TOP TECHNIQUES (últimas 24h)
# ---------------------------------------------------------
@app.get("/dashboard/top-techniques")
def top_techniques(country: str = "CO", db: Session = Depends(get_db)):

    since = datetime.utcnow() - timedelta(hours=24)

    rows = db.query(
        models.Technique.tech_id,
        func.count(models.Alert.id)
    )\
    .join(models.Technique, models.Alert.technique_id == models.Technique.id)\
    .join(models.ThreatActor, models.Alert.actor_id == models.ThreatActor.id)\
    .filter(models.ThreatActor.country == country)\
    .filter(models.Alert.created_at >= since)\
    .group_by(models.Technique.tech_id)\
    .order_by(func.count(models.Alert.id).desc())\
    .limit(10)\
    .all()

    result = []

    for tech_id, count in rows:
        result.append({
            "technique": tech_id,
            "alerts": count
        })

    return result

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/actors/{name}")
def actor_details(name: str, db: Session = Depends(get_db)):

    actor = db.query(models.ThreatActor)\
        .filter(models.ThreatActor.name == name)\
        .first()

    if not actor:
        return {"error": "actor not found"}

    rows = (
        db.query(models.ActorTechnique, models.Technique)
        .join(models.Technique, models.Technique.id == models.ActorTechnique.technique_id)
        .filter(models.ActorTechnique.actor_id == actor.id)
        .filter(models.ActorTechnique.active == True)
        .order_by(models.ActorTechnique.last_seen.desc())
        .all()
    )

    last_seen = None
    result = []
    tactics_summary = {}

    for at, t in rows:
        if at.last_seen and (last_seen is None or at.last_seen > last_seen):
            last_seen = at.last_seen

        result.append({
            "technique": t.tech_id,
            "tech_id": t.tech_id,
            "name": t.name,
            "tactic": t.tactic,
            "first_seen": utc_to_bogota(at.first_seen).isoformat() if at.first_seen else None,
            "last_seen": utc_to_bogota(at.last_seen).isoformat() if at.last_seen else None,
            "sightings_count": int(at.sightings_count or 0),
            "seen_days_count": int(at.seen_days_count or 0),
        })

        for tactic in [x.strip().lower() for x in (t.tactic or "").split(",") if x.strip()]:
            if tactic not in tactics_summary:
                tactics_summary[tactic] = {
                    "tactic": tactic,
                    "first_seen": at.first_seen,
                    "last_seen": at.last_seen,
                    "techniques": set(),
                }
            if at.first_seen and (tactics_summary[tactic]["first_seen"] is None or at.first_seen < tactics_summary[tactic]["first_seen"]):
                tactics_summary[tactic]["first_seen"] = at.first_seen
            if at.last_seen and (tactics_summary[tactic]["last_seen"] is None or at.last_seen > tactics_summary[tactic]["last_seen"]):
                tactics_summary[tactic]["last_seen"] = at.last_seen
            tactics_summary[tactic]["techniques"].add(t.tech_id)

    tactics_items = []
    for _, v in tactics_summary.items():
        tactics_items.append({
            "tactic": v["tactic"],
            "first_seen": utc_to_bogota(v["first_seen"]).isoformat() if v["first_seen"] else None,
            "last_seen": utc_to_bogota(v["last_seen"]).isoformat() if v["last_seen"] else None,
            "technique_count": len(v["techniques"])
        })

    tactics_items.sort(key=lambda x: x["last_seen"] or "", reverse=True)

    return {
        "actor": {
            "id": actor.id,
            "name": actor.name,
            "country": actor.country,
            "last_seen": utc_to_bogota(last_seen).isoformat() if last_seen else None,
            "aliases": actor.aliases,
            "source": actor.source
        },
        "techniques": result,
        "tactics": tactics_items
    }


@app.get("/actors/{actor_id}/timeline")
def actor_timeline_events(actor_id: int, days: int = 30, db: Session = Depends(get_db)):
    since = datetime.utcnow() - timedelta(days=max(1, days))
    events = (
        db.query(models.IntelligenceEvent, models.Technique)
        .join(models.Technique, models.Technique.id == models.IntelligenceEvent.technique_id)
        .filter(models.IntelligenceEvent.actor_id == actor_id)
        .filter(models.IntelligenceEvent.created_at >= since)
        .order_by(models.IntelligenceEvent.created_at.desc())
        .limit(500)
        .all()
    )

    return [
        {
            "date": utc_to_bogota(e.created_at).isoformat() if e.created_at else None,
            "event_type": e.event_type,
            "technique": t.tech_id if t else None,
            "technique_name": t.name if t else None,
            "tactic": t.tactic if t else None
        }
        for (e, t) in events
    ]


@app.get("/actors/{actor_id}/recent-techniques")
def actor_recent_techniques(actor_id: int, limit: int = 5, db: Session = Depends(get_db)):
    limit = max(1, min(int(limit), 50))
    rows = (
        db.query(models.ActorTechnique, models.Technique)
        .join(models.Technique, models.Technique.id == models.ActorTechnique.technique_id)
        .filter(models.ActorTechnique.actor_id == actor_id)
        .order_by(models.ActorTechnique.last_seen.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "technique": t.tech_id if t else None,
            "technique_name": t.name if t else None,
            "tactic": t.tactic if t else None,
            "last_seen": utc_to_bogota(at.last_seen).isoformat() if at.last_seen else None
        }
        for (at, t) in rows
    ]


@app.get("/actors/{actor_id}/evidence")
def actor_evidence(actor_id: int, limit: int = 50, db: Session = Depends(get_db)):
    limit = max(1, min(int(limit), 200))
    rows = (
        db.query(models.TechniqueEvidence, models.Technique)
        .join(models.Technique, models.Technique.id == models.TechniqueEvidence.technique_id)
        .filter(models.TechniqueEvidence.actor_id == actor_id)
        .order_by(models.TechniqueEvidence.observed_at.desc())
        .limit(limit)
        .all()
    )

    return [
        {
            "technique": t.tech_id if t else None,
            "technique_name": t.name if t else None,
            "sample_hash": ev.sample_hash,
            "source": ev.source,
            "observed_at": utc_to_bogota(ev.observed_at).isoformat() if ev.observed_at else None
        }
        for (ev, t) in rows
    ]
