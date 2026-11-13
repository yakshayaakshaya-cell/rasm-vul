"""FastAPI server: JSON API under /api, static frontend at /."""
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from rasm import Engine

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"
state = {}


@asynccontextmanager
async def lifespan(app):
    state["engine"] = Engine()
    yield


app = FastAPI(title="RASM-Vul", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=os.getenv("ALLOWED_ORIGINS", "*").split(","),
                   allow_methods=["*"], allow_headers=["*"])


class AnalyzeRequest(BaseModel):
    code: str = Field(min_length=10, max_length=20000)


@app.get("/api/health")
def health():
    return {"status": "ok", **state["engine"].info()}


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest):
    try:
        return state["engine"].analyze(req.code)
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))


if FRONTEND.exists():
    app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="frontend")
