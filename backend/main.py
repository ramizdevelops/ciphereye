"""
CipherEye CTF Workbench — FastAPI Backend
"""

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import os
import pathlib

from routers import stego, osint, geoint

# Use /tmp on Render (writable), local uploads/ in dev
UPLOAD_DIR = pathlib.Path(os.getenv("UPLOAD_DIR", "/tmp/uploads"))

@asynccontextmanager
async def lifespan(app: FastAPI):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    yield

app = FastAPI(
    title="CipherEye API",
    description="OSINT, GEOINT, and Steganography analysis engine",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict after deployment confirmed
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(stego.router, prefix="/api/stego", tags=["Steganography"])
app.include_router(osint.router, prefix="/api/osint", tags=["OSINT"])
app.include_router(geoint.router, prefix="/api/geoint", tags=["GEOINT"])

@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}

@app.get("/api/health")
async def api_health():
    return {"status": "ok"}