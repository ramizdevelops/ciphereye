"""
CTF OSINT & Steganography Workbench — FastAPI Backend
"""

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import os
import pathlib

from routers import stego, osint, geoint


UPLOAD_DIR = pathlib.Path("/app/uploads")


@asynccontextmanager
async def lifespan(app: FastAPI):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    yield


app = FastAPI(
    title="CTF Workbench API",
    description="OSINT, GEOINT, and Steganography analysis engine for CTF competitions",
    version="1.0.0",
    lifespan=lifespan,
)


@app.get("/health")
def health():
    return {"status": "ok"}


app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(stego.router, prefix="/api/stego", tags=["Steganography"])
app.include_router(osint.router, prefix="/api/osint", tags=["OSINT"])
app.include_router(geoint.router, prefix="/api/geoint", tags=["GEOINT"])


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}
