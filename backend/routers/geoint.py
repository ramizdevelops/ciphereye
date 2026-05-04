"""
GEOINT Router
Extracts GPS coordinates from image EXIF and returns structured location data for Leaflet.
"""

from fastapi import APIRouter, UploadFile, File
from fastapi.responses import JSONResponse
import pathlib, uuid, shutil, os

from services.geoint_service import extract_gps_from_image, batch_extract_gps

router = APIRouter()
UPLOAD_DIR = pathlib.Path(os.getenv("UPLOAD_DIR", "/tmp/uploads"))


def save_upload(file: UploadFile) -> pathlib.Path:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    ext = pathlib.Path(file.filename).suffix if file.filename else ""
    dest = UPLOAD_DIR / f"{uuid.uuid4().hex}{ext}"
    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)
    return dest


@router.post("/extract")
async def extract_coordinates(file: UploadFile = File(...)):
    """
    Extract GPS coordinates from a single image's EXIF metadata.
    Returns lat/lon + full EXIF location tags.
    """
    saved = save_upload(file)
    try:
        result = extract_gps_from_image(saved)
        result["filename"] = file.filename
        return JSONResponse(content=result)
    finally:
        saved.unlink(missing_ok=True)


@router.post("/batch")
async def batch_extract(files: list[UploadFile] = File(...)):
    """
    Process multiple images and return all extracted GPS points for map rendering.
    """
    saved_paths = []
    names = []
    for f in files:
        p = save_upload(f)
        saved_paths.append(p)
        names.append(f.filename)

    try:
        results = batch_extract_gps(saved_paths, names)
        return JSONResponse(content={"locations": results})
    finally:
        for p in saved_paths:
            p.unlink(missing_ok=True)
            