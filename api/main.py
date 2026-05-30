from api.models import init_db
from api.routes import router
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(lifespan=lifespan)
app.include_router(router)

templates = Jinja2Templates(directory="dashboard/templates")

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.get("/")
def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "traceback": traceback.format_exc()}
    )

# Imports and calls init_db on startup using FastAPI's lifespan event
# Has a single health check route GET /health that returns {"status": "ok"}