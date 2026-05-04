"""
Steganography & Forensics Router
Handles: EXIF extraction, LSB decode, strings dump, hex dump, file carving, magic bytes
"""

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
import pathlib, uuid, shutil, subprocess, os

from services.stego_service import (
    extract_exif,
    lsb_decode_all_channels,
    extract_strings,
    get_hex_dump,
    detect_file_type,
    run_binwalk,
    extract_steghide,
    zsteg_analysis,
    compute_hashes,
)

router = APIRouter()
UPLOAD_DIR = pathlib.Path(os.getenv("UPLOAD_DIR", "/tmp/uploads"))


def save_upload(file: UploadFile) -> pathlib.Path:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    ext = pathlib.Path(file.filename).suffix if file.filename else ""
    dest = UPLOAD_DIR / f"{uuid.uuid4().hex}{ext}"
    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)
    return dest


@router.post("/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """Full forensics pipeline — runs all analysis modules on the uploaded file."""
    saved = save_upload(file)
    try:
        results = {
            "filename": file.filename,
            "hashes": compute_hashes(saved),
            "file_type": detect_file_type(saved),
            "exif": extract_exif(saved),
            "strings": extract_strings(saved),
            "hex_dump": get_hex_dump(saved, lines=64),
            "lsb": lsb_decode_all_channels(saved),
            "binwalk": run_binwalk(saved),
            "zsteg": zsteg_analysis(saved),
        }
        return JSONResponse(content=results)
    finally:
        saved.unlink(missing_ok=True)


@router.post("/exif")
async def exif_only(file: UploadFile = File(...)):
    saved = save_upload(file)
    try:
        return {"exif": extract_exif(saved)}
    finally:
        saved.unlink(missing_ok=True)


@router.post("/lsb")
async def lsb_only(file: UploadFile = File(...)):
    saved = save_upload(file)
    try:
        return {"lsb": lsb_decode_all_channels(saved)}
    finally:
        saved.unlink(missing_ok=True)


@router.post("/strings")
async def strings_only(file: UploadFile = File(...)):
    saved = save_upload(file)
    try:
        return {"strings": extract_strings(saved)}
    finally:
        saved.unlink(missing_ok=True)


@router.post("/hex")
async def hex_only(file: UploadFile = File(...), lines: int = 64):
    saved = save_upload(file)
    try:
        return {"hex": get_hex_dump(saved, lines=lines)}
    finally:
        saved.unlink(missing_ok=True)


@router.post("/binwalk")
async def binwalk_only(file: UploadFile = File(...)):
    saved = save_upload(file)
    try:
        return {"binwalk": run_binwalk(saved)}
    finally:
        saved.unlink(missing_ok=True)


@router.post("/steghide")
async def steghide_extract(file: UploadFile = File(...), passphrase: str = ""):
    saved = save_upload(file)
    try:
        return {"steghide": extract_steghide(saved, passphrase)}
    finally:
        saved.unlink(missing_ok=True)