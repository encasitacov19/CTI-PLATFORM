from pydantic import BaseModel
from datetime import datetime
from pydantic import BaseModel


class ActorCreate(BaseModel):
    name: str
    gti_id: str
    country: str
    aliases: str | None = None
    source: str | None = None


class ActorOut(BaseModel):
    id: int
    name: str
    gti_id: str
    country: str
    active: bool = True
    aliases: str | None = None
    last_scan_at: datetime | None = None
    source: str | None = None

    class Config:
        orm_mode = True

class TimelineEvent(BaseModel):
    technique: str
    tactic: str | None
    event_type: str
    date: datetime

    class Config:
        from_attributes = True


class HeatmapItem(BaseModel):
    technique: str
    name: str
    tactic: str | None
    score: int

    class Config:
        from_attributes = True


class ScheduleUpdate(BaseModel):
    time_hhmm: str
    days: list[str]
    enabled: bool = True


class ClientCreate(BaseModel):
    name: str


class ClientOut(BaseModel):
    id: int
    name: str
    projects_count: int = 0

    class Config:
        orm_mode = True


class ClientProjectCreate(BaseModel):
    name: str


class ClientProjectOut(BaseModel):
    id: int
    client_id: int
    client_name: str
    name: str

    class Config:
        orm_mode = True


class ActorProjectTagCreate(BaseModel):
    project_id: int
    label: str | None = None
    note: str | None = None


class ActorProjectTagOut(BaseModel):
    id: int
    actor_id: int
    actor_name: str
    project_id: int
    project_name: str
    client_id: int
    client_name: str
    label: str
    note: str | None = None
    created_at: datetime | None = None

    class Config:
        orm_mode = True


class TagCreate(BaseModel):
    name: str


class TagOut(BaseModel):
    id: int
    name: str

    class Config:
        orm_mode = True


class ActorTagAssign(BaseModel):
    tag_id: int


class ActorTagOut(BaseModel):
    actor_id: int
    actor_name: str
    tag_id: int
    tag_name: str
    created_at: datetime | None = None

    class Config:
        orm_mode = True
