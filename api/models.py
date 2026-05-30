from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field, create_engine, Session

class Event(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)     # primary key, auto-incremented
    ts: datetime = Field(default_factory=datetime.utcnow)         # timestamp, auto-set to now
    user_ip: str
    destination: str                                              # (e.g. googleapis.com)
    filename: str
    category: str                                                 # (e.g. source_code, pii, credentials, clean)
    confidence: float                                             # float between 0 and 1
    action: str
    detected_by: str                                                # (BLOCK, ALLOW, DRY_RUN)
    policy_name: Optional[str] = Field(default=None)              # string, nullable
    bypass_flag: bool = Field(default=False)                      # boolean, default False
    body_hash: str

sqlite_file_name = "casb.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

engine = create_engine(sqlite_url, echo=True)

def init_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session