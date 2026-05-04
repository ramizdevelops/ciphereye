"""
CipherEye CTF Workbench — FastAPI Backend
"""

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import os
import pathlib

from routers import stego, osint, geoint

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

# CORS — must be first middleware, before everything else
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["*"],
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

# Global error handler — ensures CORS headers are on error responses too
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": str(exc)},
        headers={"Access-Control-Allow-Origin": "*"},
    )