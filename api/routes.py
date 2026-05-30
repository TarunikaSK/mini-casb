from ruamel.yaml import YAML
from api.models import Event, get_session
from inspector.pipeline import inspect as run_pipeline
from policy.engine import PolicyEngine
from pydantic import BaseModel
from typing import Optional
import base64
import hashlib
from fastapi import APIRouter, Depends, Query, Request
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select, func
from pathlib import Path as FilePath

router = APIRouter()
_yaml = YAML(typ='safe', pure=True)

class InspectRequest(BaseModel):
    filename: str
    destination: str
    user_ip: str
    body_b64: str                         # the file content will arrive as base64 encoded text

class InspectResult(BaseModel):
    action: str                           # (BLOCK, ALLOW, DRY_RUN)
    category: str
    confidence: float
    policy_name: Optional[str] = None
    bypass_flag: bool

@router.post("/inspect", response_model=InspectResult)
def inspect(request: InspectRequest, session: Session = Depends(get_session)):
    
    # 1. Decoding body
    body = base64.b64decode(request.body_b64)

    # 2. Hashing body
    body_hash = hashlib.sha256(body).hexdigest()

    # 3. Run the full pipeline (regex → YARA → Ollama + bypass detector)
    result = run_pipeline(request.filename, body)

    # 4. Run policy engine
    engine = PolicyEngine()
    action, policy_name = engine.evaluate(
        result["category"],
        result["confidence"],
        request.destination,
        result["bypass_flag"]
    )

    event = Event(
    user_ip=request.user_ip,
    destination=request.destination,
    filename=request.filename,
    category=result["category"],
    confidence=result["confidence"],
    action=action,
    detected_by=result["detected_by"],
    policy_name=policy_name or "",
    bypass_flag=result["bypass_flag"],
    body_hash=body_hash
    )

    session.add(event)
    session.commit()

    return InspectResult(
        action=action,
        category=result["category"],
        confidence=result["confidence"] ,
        policy_name=policy_name,
        bypass_flag=result["bypass_flag"]
    )



# ─── GET /api/events ────────────────────────────────────────────────────────

@router.get("/api/events")
def get_events(
    limit: int = Query(default=50, le=200),
    action: str = Query(default=None),
    category: str = Query(default=None),
    session: Session = Depends(get_session)
):
    statement = select(Event)

    if action:
        statement = statement.where(Event.action == action.upper())
    if category:
        statement = statement.where(Event.category == category.lower())

    statement = statement.order_by(Event.ts.desc()).limit(limit)
    events = session.exec(statement).all()
    return events


# ─── GET /api/stats ─────────────────────────────────────────────────────────

@router.get("/api/stats")
def get_stats(session: Session = Depends(get_session)):
    all_events = session.exec(select(Event)).all()

    total = len(all_events)
    blocked = sum(1 for e in all_events if e.action == "BLOCK")
    allowed = sum(1 for e in all_events if e.action == "ALLOW")
    dry_run = sum(1 for e in all_events if e.action == "DRY_RUN")
    bypass_attempts = sum(1 for e in all_events if e.bypass_flag)

    by_category = {}
    for event in all_events:
        by_category[event.category] = by_category.get(event.category, 0) + 1

    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "dry_run": dry_run,
        "bypass_attempts": bypass_attempts,
        "by_category": by_category
    }


# ─── GET /api/events/recent ──────────────────────────────────────────────────

@router.get("/api/events/recent")
def get_recent_events(session: Session = Depends(get_session)):
    statement = select(Event).order_by(Event.ts.desc()).limit(10)
    events = session.exec(statement).all()
    return events

@router.get("/api/policies")
def get_policies():
    with open("policy/policies.yaml") as f:
        data = _yaml.load(f)
    return data["policies"]

@router.get("/api/rules/yara")
def get_yara_rules():
    import glob
    rules = []
    for path in glob.glob("rules/*.yar"):
        with open(path) as f:
            content = f.read()
        name = FilePath(path).stem
        category = name  # default to filename
        for line in content.splitlines():
            if 'category' in line and '=' in line:
                category = line.split('=')[-1].strip().strip('"')
                break
        rules.append({"name": name, "category": category, "content": content})
    return rules

@router.get("/api/rules/regex")
def get_regex_rules():
    with open("inspector/regex_rules.yaml") as f:
        data = _yaml.load(f)
    return data["rules"]

# templates = Jinja2Templates(directory="dashboard/templates")

# @router.get("/api/events/rows")
# def get_event_rows(
#     request: Request,
#     action: str = Query(default=None),
#     session: Session = Depends(get_session)
# ):
#     statement = select(Event)
#     if action:
#         statement = statement.where(Event.action == action.upper())
#     statement = statement.order_by(Event.ts.desc()).limit(50)
#     events = session.exec(statement).all()

#     return templates.TemplateResponse(
#         request=request,
#         name="partials/rows.html",
#         context={"events": events} 
#     )