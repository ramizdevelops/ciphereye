"""
GEOINT Service
Extracts GPS coordinates from image EXIF metadata for Leaflet map rendering.
"""

import pathlib
import re
from typing import Any

import exifread
from PIL import Image
import piexif


def _rational_to_float(rational) -> float:
    """Convert IFDRational or tuple (num, den) to float."""
    if hasattr(rational, "num") and hasattr(rational, "den"):
        return float(rational.num) / float(rational.den) if rational.den else 0.0
    if isinstance(rational, tuple) and len(rational) == 2:
        return float(rational[0]) / float(rational[1]) if rational[1] else 0.0
    return float(rational)


def _parse_exifread_gps(tags: dict) -> tuple[float, float] | None:
    """Parse GPS from exifread tag dict."""
    lat_tag = tags.get("GPS GPSLatitude")
    lat_ref = tags.get("GPS GPSLatitudeRef")
    lon_tag = tags.get("GPS GPSLongitude")
    lon_ref = tags.get("GPS GPSLongitudeRef")

    if not (lat_tag and lon_tag):
        return None

    def to_decimal(tag, ref):
        vals = tag.values
        deg = _rational_to_float(vals[0])
        mins = _rational_to_float(vals[1])
        secs = _rational_to_float(vals[2])
        decimal = deg + mins / 60 + secs / 3600
        if str(ref) in ("S", "W"):
            decimal = -decimal
        return decimal

    try:
        lat = to_decimal(lat_tag, lat_ref)
        lon = to_decimal(lon_tag, lon_ref)
        return lat, lon
    except Exception:
        return None


def _parse_piexif_gps(exif_dict: dict) -> tuple[float, float] | None:
    """Parse GPS from piexif dict."""
    gps = exif_dict.get("GPS", {})
    if not gps:
        return None
    try:
        def to_deg(vals):
            return (
                _rational_to_float(vals[0])
                + _rational_to_float(vals[1]) / 60
                + _rational_to_float(vals[2]) / 3600
            )

        lat_ref = gps.get(piexif.GPSIFD.GPSLatitudeRef, b"N").decode()
        lat = to_deg(gps[piexif.GPSIFD.GPSLatitude])
        lon_ref = gps.get(piexif.GPSIFD.GPSLongitudeRef, b"E").decode()
        lon = to_deg(gps[piexif.GPSIFD.GPSLongitude])

        if lat_ref == "S":
            lat = -lat
        if lon_ref == "W":
            lon = -lon
        return lat, lon
    except Exception:
        return None


def extract_gps_from_image(path: pathlib.Path) -> dict[str, Any]:
    """
    Try multiple methods to extract GPS coordinates from an image.
    Returns structured result with lat/lon and all GPS-related EXIF tags.
    """
    result: dict[str, Any] = {
        "has_gps": False,
        "lat": None,
        "lon": None,
        "altitude": None,
        "gps_tags": {},
        "all_exif": {},
    }

    # Method 1: exifread
    try:
        with open(path, "rb") as f:
            tags = exifread.process_file(f, details=True)

        # Collect all GPS tags
        gps_tags = {k: str(v) for k, v in tags.items() if "GPS" in k}
        result["gps_tags"] = gps_tags

        # All EXIF
        result["all_exif"] = {k: str(v) for k, v in tags.items()}

        coords = _parse_exifread_gps(tags)
        if coords:
            result["has_gps"] = True
            result["lat"], result["lon"] = coords

        # Altitude
        alt_tag = tags.get("GPS GPSAltitude")
        if alt_tag:
            try:
                result["altitude"] = _rational_to_float(alt_tag.values[0])
            except Exception:
                pass
    except Exception:
        pass

    # Method 2: piexif fallback
    if not result["has_gps"]:
        try:
            exif_dict = piexif.load(str(path))
            coords = _parse_piexif_gps(exif_dict)
            if coords:
                result["has_gps"] = True
                result["lat"], result["lon"] = coords
        except Exception:
            pass

    return result


def batch_extract_gps(
    paths: list[pathlib.Path],
    names: list[str],
) -> list[dict[str, Any]]:
    """Extract GPS from multiple images and return list of map-ready location objects."""
    locations = []
    for path, name in zip(paths, names):
        data = extract_gps_from_image(path)
        if data["has_gps"]:
            locations.append({
                "filename": name,
                "lat": data["lat"],
                "lon": data["lon"],
                "altitude": data["altitude"],
                "gps_tags": data["gps_tags"],
            })
    return locations
