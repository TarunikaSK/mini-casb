import uvicorn
from fastapi import FastAPI, Request

app = FastAPI()

@app.post("/upload")
async def upload(request: Request):
    body = await request.body()
    return {
        "received_bytes": len(body),
        "status": "ok"
    }

uvicorn.run(app, port=9000)