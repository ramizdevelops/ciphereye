"""
Steganography & Forensics Service — CipherEye CTF Workbench
Fully improved: EXIF (dual-engine), pure-Python binwalk, enhanced LSB,
strings, hex dump, file carving, metadata, hash computation, and more.
"""

import pathlib
import struct
import re
import hashlib
import io
from typing import Any

try:
    import exifread
except ImportError:
    exifread = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    import numpy as np
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False


# ─── File hashing ─────────────────────────────────────────────────────────────

def compute_hashes(path: pathlib.Path) -> dict:
    data = path.read_bytes()
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
        "size_kb": round(len(data) / 1024, 2),
    }


# ─── Magic signatures ─────────────────────────────────────────────────────────

MAGIC_SIGNATURES = [
    (b"\xff\xd8\xff",           "JPEG Image",              "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n",     "PNG Image",               "image/png"),
    (b"GIF87a",                 "GIF87a Image",            "image/gif"),
    (b"GIF89a",                 "GIF89a Image",            "image/gif"),
    (b"BM",                     "BMP Image",               "image/bmp"),
    (b"RIFF",                   "RIFF Container",          "audio/wav"),
    (b"PK\x03\x04",            "ZIP Archive",             "application/zip"),
    (b"Rar!\x1a\x07\x00",      "RAR Archive v4",          "application/x-rar"),
    (b"Rar!\x1a\x07\x01\x00",  "RAR Archive v5",          "application/x-rar"),
    (b"\x1f\x8b\x08",         "GZIP Stream",             "application/gzip"),
    (b"BZh",                    "BZIP2 Stream",            "application/x-bzip2"),
    (b"\xfd7zXZ\x00",          "XZ Stream",               "application/x-xz"),
    (b"7z\xbc\xaf\x27\x1c",    "7-Zip Archive",           "application/x-7z-compressed"),
    (b"%PDF",                   "PDF Document",            "application/pdf"),
    (b"\x7fELF",               "ELF Executable",          "application/x-elf"),
    (b"MZ",                     "PE/DOS Executable",       "application/x-dosexec"),
    (b"\xca\xfe\xba\xbe",      "Mach-O Fat Binary",       "application/x-mach-binary"),
    (b"OggS",                   "OGG Container",           "audio/ogg"),
    (b"fLaC",                   "FLAC Audio",              "audio/flac"),
    (b"ID3",                    "MP3 (ID3 Tag)",           "audio/mpeg"),
    (b"SQLite format 3\x00",    "SQLite Database",         "application/x-sqlite3"),
    (b"-----BEGIN",             "PEM Certificate/Key",     "text/plain"),
    (b"ustar",                  "TAR Archive",             "application/x-tar"),
    (b"<!DOCTYPE",              "HTML Document",           "text/html"),
    (b"<?xml",                  "XML Document",            "text/xml"),
    (b"II*\x00",               "TIFF Image (LE)",         "image/tiff"),
    (b"MM\x00*",               "TIFF Image (BE)",         "image/tiff"),
    (b"\xd0\xcf\x11\xe0",      "MS Office (OLE)",         "application/msword"),
    (b"wOFF",                   "WOFF Font",               "font/woff"),
    (b"wOF2",                   "WOFF2 Font",              "font/woff2"),
    (b"dex\n",                  "Android DEX",             "application/x-dex"),
    (b"\x00\x00\x01\x00",      "ICO Icon",                "image/x-icon"),
]


# ─── File type detection ──────────────────────────────────────────────────────

def detect_file_type(path: pathlib.Path) -> dict:
    result: dict[str, Any] = {}
    with open(path, "rb") as f:
        header = f.read(32)
    result["magic_bytes"] = header.hex()
    result["magic_bytes_ascii"] = "".join(chr(b) if 32 <= b < 127 else "." for b in header)
    result["file_size_bytes"] = path.stat().st_size
    result["file_size_kb"] = round(path.stat().st_size / 1024, 2)

    matched_desc = "Unknown / Binary"
    matched_mime = "application/octet-stream"
    for sig, desc, mime in MAGIC_SIGNATURES:
        if header[:len(sig)] == sig:
            matched_desc = desc
            matched_mime = mime
            break

    if MAGIC_AVAILABLE:
        try:
            result["mime"] = magic.from_file(str(path), mime=True)
            result["description"] = magic.from_file(str(path))
        except Exception:
            result["mime"] = matched_mime
            result["description"] = matched_desc
    else:
        result["mime"] = matched_mime
        result["description"] = matched_desc

    result["signature_match"] = matched_desc
    return result


# ─── EXIF helpers ─────────────────────────────────────────────────────────────

def _rational_to_float(val) -> float:
    if isinstance(val, tuple) and len(val) == 2:
        return val[0] / val[1] if val[1] != 0 else 0.0
    try:
        return float(val)
    except Exception:
        return 0.0


def _parse_gps_coord(coord_vals, ref: str):
    try:
        d = _rational_to_float(coord_vals[0])
        m = _rational_to_float(coord_vals[1])
        s = _rational_to_float(coord_vals[2])
        decimal = d + m / 60 + s / 3600
        if ref in ("S", "W"):
            decimal = -decimal
        return round(decimal, 8)
    except Exception:
        return None


def _safe_str(val) -> str:
    if isinstance(val, bytes):
        try:
            return val.decode("utf-8", errors="replace").strip("\x00")
        except Exception:
            return val.hex()
    if isinstance(val, tuple):
        if len(val) == 2 and isinstance(val[0], int) and isinstance(val[1], int):
            if val[1] == 0:
                return "0"
            r = val[0] / val[1]
            return str(int(r)) if r == int(r) else f"{r:.5f}".rstrip("0").rstrip(".")
        return str(val)
    return str(val)


# ─── EXIF extraction ──────────────────────────────────────────────────────────

def extract_exif(path: pathlib.Path) -> dict:
    result: dict[str, Any] = {
        "basic": {},
        "gps": {},
        "camera": {},
        "settings": {},
        "dates": {},
        "thumbnail": {},
        "raw_tags": {},
    }
    gps_decimal: dict[str, Any] = {}

    # Engine 1: Pillow
    if PIL_AVAILABLE:
        try:
            img = Image.open(path)
            result["basic"]["Format"]     = img.format or "Unknown"
            result["basic"]["Mode"]       = img.mode
            result["basic"]["Width"]      = img.width
            result["basic"]["Height"]     = img.height
            result["basic"]["Resolution"] = f"{img.width}x{img.height}"

            exif_data = img._getexif()
            if exif_data:
                gps_ifd: dict = {}
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, f"Tag_{tag_id}")
                    if tag_name == "GPSInfo" and isinstance(value, dict):
                        gps_ifd = value
                        continue
                    sv = _safe_str(value)
                    if tag_name in ("Make","Model","Software","LensMake","LensModel",
                                    "BodySerialNumber","LensSerialNumber","CameraOwnerName"):
                        result["camera"][tag_name] = sv
                    elif tag_name in ("DateTime","DateTimeOriginal","DateTimeDigitized",
                                      "SubSecTime","SubSecTimeOriginal","OffsetTime","OffsetTimeOriginal"):
                        result["dates"][tag_name] = sv
                    elif tag_name in ("ExposureTime","FNumber","ISOSpeedRatings","ShutterSpeedValue",
                                      "ApertureValue","ExposureBiasValue","MaxApertureValue",
                                      "MeteringMode","Flash","FocalLength","ExposureMode",
                                      "WhiteBalance","DigitalZoomRatio","FocalLengthIn35mmFilm",
                                      "SceneCaptureType","Contrast","Saturation","Sharpness",
                                      "BrightnessValue","LightSource","ExposureProgram"):
                        result["settings"][tag_name] = sv
                    elif tag_name in ("ImageWidth","ImageLength","BitsPerSample","Compression",
                                      "XResolution","YResolution","ResolutionUnit","ColorSpace",
                                      "PixelXDimension","PixelYDimension","Orientation","YCbCrPositioning"):
                        result["basic"][tag_name] = sv
                    elif tag_name in ("ThumbnailOffset","ThumbnailLength"):
                        result["thumbnail"][tag_name] = sv
                    else:
                        result["raw_tags"][tag_name] = sv

                if gps_ifd:
                    for gid, gval in gps_ifd.items():
                        gtag = GPSTAGS.get(gid, f"GPS_{gid}")
                        result["gps"][gtag] = _safe_str(gval)
                    try:
                        lat = _parse_gps_coord(gps_ifd.get(2,[]), gps_ifd.get(1,"N"))
                        lon = _parse_gps_coord(gps_ifd.get(4,[]), gps_ifd.get(3,"E"))
                        if lat is not None and lon is not None:
                            gps_decimal["latitude"]    = lat
                            gps_decimal["longitude"]   = lon
                            gps_decimal["google_maps"] = f"https://maps.google.com/?q={lat},{lon}"
                            alt_t = gps_ifd.get(6)
                            if alt_t:
                                alt = _rational_to_float(alt_t)
                                ref = gps_ifd.get(5, 0)
                                gps_decimal["altitude_m"] = round(alt if ref == 0 else -alt, 2)
                    except Exception:
                        pass
        except Exception as e:
            result["raw_tags"]["_PIL_error"] = str(e)

    # Engine 2: exifread
    if exifread is not None:
        try:
            with open(path, "rb") as f:
                tags = exifread.process_file(f, details=True, strict=False)
            for key, val in tags.items():
                clean = key.replace("EXIF ","").replace("Image ","").replace("GPS ","GPS_")
                already = any(
                    clean in result[sec]
                    for sec in ("basic","camera","settings","dates","raw_tags")
                )
                if not already:
                    result["raw_tags"][f"[exifread] {clean}"] = str(val)
        except Exception as e:
            result["raw_tags"]["_exifread_error"] = str(e)

    if gps_decimal:
        result["gps"]["_decimal"] = gps_decimal

    total = sum(len(v) for v in result.values() if isinstance(v, dict))
    result["_summary"] = {
        "total_tags": total,
        "has_gps": bool(result["gps"]),
        "has_camera_info": bool(result["camera"]),
        "note": "" if total > 5 else "No EXIF metadata found. File may have been stripped or is not an image.",
    }
    return result


# ─── Pure-Python Binwalk ──────────────────────────────────────────────────────

EMBEDDED_SIGNATURES = [
    (b"\xff\xd8\xff",          "JPEG Image"),
    (b"\x89PNG\r\n\x1a\n",    "PNG Image"),
    (b"GIF87a",                "GIF87a Image"),
    (b"GIF89a",                "GIF89a Image"),
    (b"PK\x03\x04",           "ZIP Archive"),
    (b"Rar!\x1a\x07",         "RAR Archive"),
    (b"\x1f\x8b\x08",        "GZIP Stream"),
    (b"BZh",                   "BZIP2 Stream"),
    (b"\xfd7zXZ\x00",         "XZ Stream"),
    (b"7z\xbc\xaf\x27\x1c",   "7-Zip Archive"),
    (b"%PDF",                  "PDF Document"),
    (b"\x7fELF",              "ELF Executable"),
    (b"MZ",                    "PE/DOS Executable"),
    (b"SQLite format 3\x00",   "SQLite Database"),
    (b"OggS",                  "OGG Audio"),
    (b"fLaC",                  "FLAC Audio"),
    (b"ID3",                   "MP3 ID3 Tag"),
    (b"RIFF",                  "RIFF Container"),
    (b"-----BEGIN",            "PEM Key/Certificate"),
    (b"ustar",                 "TAR Archive"),
    (b"<!DOCTYPE",             "HTML Document"),
    (b"<?xml",                 "XML Document"),
    (b"\xca\xfe\xba\xbe",     "Mach-O Binary"),
    (b"dex\n",                 "Android DEX"),
    (b"ssh-rsa",               "SSH RSA Public Key"),
    (b"ssh-ed25519",           "SSH Ed25519 Key"),
    (b"wOFF",                  "WOFF Font"),
    (b"wOF2",                  "WOFF2 Font"),
]


def run_binwalk(path: pathlib.Path) -> dict:
    """Pure-Python embedded file scanner — no external tools needed."""
    try:
        data = path.read_bytes()
        file_size = len(data)
        findings = []
        seen: set[int] = set()

        for sig, desc in EMBEDDED_SIGNATURES:
            start = 0
            while True:
                idx = data.find(sig, start)
                if idx == -1:
                    break
                if idx not in seen:
                    seen.add(idx)
                    is_start = idx == 0
                    note = "File header" if is_start else "Embedded signature — possible hidden file"
                    if not is_start:
                        if b"PK" in sig:
                            note = "Embedded ZIP — try: 7z x / unzip"
                        elif b"\x1f\x8b" in sig:
                            note = "Embedded GZIP — extract with gunzip"
                        elif sig in (b"\xff\xd8\xff", b"\x89PNG\r\n\x1a\n"):
                            note = "Image embedded inside file"
                    findings.append({
                        "offset_decimal": idx,
                        "offset_hex": f"0x{idx:08x}",
                        "description": desc,
                        "is_file_start": is_start,
                        "note": note,
                    })
                start = idx + 1
                if start >= file_size:
                    break

        findings.sort(key=lambda x: x["offset_decimal"])

        # Check for appended data after EOF
        appended = []
        if data[:3] == b"\xff\xd8\xff":
            eof = data.rfind(b"\xff\xd9")
            if eof != -1 and eof + 2 < file_size:
                trailing = file_size - (eof + 2)
                appended.append({
                    "type": "JPEG trailing data",
                    "eof_offset": f"0x{eof+2:08x}",
                    "trailing_bytes": trailing,
                    "preview_hex": data[eof+2:eof+34].hex(),
                    "note": f"{trailing} bytes after JPEG EOF — likely steganography",
                })
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            iend = data.rfind(b"IEND\xaeB`\x82")
            if iend != -1 and iend + 8 < file_size:
                trailing = file_size - (iend + 8)
                appended.append({
                    "type": "PNG trailing data",
                    "eof_offset": f"0x{iend+8:08x}",
                    "trailing_bytes": trailing,
                    "preview_hex": data[iend+8:iend+40].hex(),
                    "note": f"{trailing} bytes after PNG IEND — likely steganography",
                })

        # PNG chunk analysis
        png_chunks = []
        known_chunks = {b"IHDR",b"PLTE",b"IDAT",b"IEND",b"tEXt",b"zTXt",
                        b"iTXt",b"cHRM",b"gAMA",b"sRGB",b"bKGD",b"hIST",
                        b"tIME",b"pHYs",b"sPLT",b"eXIf"}
        if data[:8] == b"\x89PNG\r\n\x1a\n":
            offset = 8
            while offset + 8 <= file_size:
                try:
                    length = struct.unpack(">I", data[offset:offset+4])[0]
                    chunk_type = data[offset+4:offset+8]
                    chunk_name = chunk_type.decode("ascii", errors="replace")
                    if chunk_type not in known_chunks:
                        png_chunks.append({
                            "offset": f"0x{offset:08x}",
                            "type": chunk_name,
                            "length": length,
                            "suspicious": True,
                            "note": f"Non-standard chunk '{chunk_name}' — may hide data",
                        })
                    elif chunk_type == b"tEXt" and length > 0:
                        content = data[offset+8:offset+8+min(length,256)].decode("latin-1","replace")
                        png_chunks.append({
                            "offset": f"0x{offset:08x}",
                            "type": chunk_name,
                            "length": length,
                            "content": content,
                            "suspicious": False,
                        })
                    offset += 4 + 4 + length + 4
                except Exception:
                    break

        return {
            "file_size": file_size,
            "file_size_kb": round(file_size/1024, 2),
            "findings": findings,
            "total_signatures_found": len(findings),
            "appended_data": appended,
            "png_chunks": png_chunks,
            "has_suspicious": bool(appended) or any(not f["is_file_start"] for f in findings),
            "engine": "Pure-Python (no external tools required)",
        }
    except Exception as e:
        return {"error": str(e), "findings": [], "appended_data": []}


# ─── LSB decode ──────────────────────────────────────────────────────────────

def lsb_decode_all_channels(path: pathlib.Path, num_bytes: int = 512) -> dict:
    if not PIL_AVAILABLE:
        return {"error": "Pillow not installed"}
    try:
        img = Image.open(path)
        mode = img.mode
        if mode not in ("RGB","RGBA","L"):
            img = img.convert("RGB"); mode = "RGB"
        arr = np.array(img)

        results: dict[str, Any] = {}
        channel_map = {}
        if mode in ("RGB","RGBA"):
            channel_map = {"red":0,"green":1,"blue":2}
            if mode == "RGBA":
                channel_map["alpha"] = 3
        else:
            channel_map = {"gray": 0}

        for ch_name, ch_idx in channel_map.items():
            ch_data = arr[:,:,ch_idx] if arr.ndim == 3 else arr
            ch_result: dict[str, Any] = {}
            for bit_plane in range(3):
                bits = ((ch_data >> bit_plane) & 1).flatten()
                byte_list = []
                for i in range(0, min(num_bytes*8, len(bits)), 8):
                    chunk = bits[i:i+8]
                    if len(chunk) < 8: break
                    byte_list.append(int("".join(str(b) for b in chunk), 2))
                raw = bytes(byte_list)
                text = raw.decode("utf-8", errors="replace")
                printable = sum(1 for c in text if c.isprintable() and c != "\ufffd")
                ratio = printable / max(len(text), 1)
                embedded = next((desc for sig,desc,_ in MAGIC_SIGNATURES if raw[:len(sig)]==sig), None)
                flag = re.search(r'(?:flag|ctf|HTB|THM|picoCTF|FLAG)\{[^}]{1,100}\}', text, re.I)
                ch_result[f"bit{bit_plane}"] = {
                    "hex": raw.hex(),
                    "text": text[:300],
                    "printable_ratio": round(ratio,3),
                    "likely_hidden": ratio > 0.75 or embedded is not None or bool(flag),
                    "embedded_file": embedded,
                    "flag_found": flag.group(0) if flag else None,
                }
            results[ch_name] = ch_result

        # Combined RGB
        if arr.ndim == 3:
            all_bits = (arr[:,:,:3] & 1).flatten()
            combined = []
            for i in range(0, min(num_bytes*8, len(all_bits)), 8):
                chunk = all_bits[i:i+8]
                if len(chunk) < 8: break
                combined.append(int("".join(str(b) for b in chunk), 2))
            raw = bytes(combined)
            text = raw.decode("utf-8", errors="replace")
            printable = sum(1 for c in text if c.isprintable() and c != "\ufffd")
            ratio = printable / max(len(text), 1)
            embedded = next((desc for sig,desc,_ in MAGIC_SIGNATURES if raw[:len(sig)]==sig), None)
            flag = re.search(r'(?:flag|ctf|HTB|THM|picoCTF|FLAG)\{[^}]{1,100}\}', text, re.I)
            results["combined_rgb"] = {"bit0": {
                "hex": raw.hex(), "text": text[:300],
                "printable_ratio": round(ratio,3),
                "likely_hidden": ratio > 0.75 or embedded is not None or bool(flag),
                "embedded_file": embedded,
                "flag_found": flag.group(0) if flag else None,
            }}

        return results
    except Exception as e:
        return {"error": str(e)}


# ─── Strings extraction ───────────────────────────────────────────────────────

def extract_strings(path: pathlib.Path, min_len: int = 4) -> dict:
    try:
        data = path.read_bytes()
        ascii_strings, unicode_strings = [], []

        # ASCII
        current: list[int] = []
        for byte in data:
            if 0x20 <= byte <= 0x7e:
                current.append(byte)
            else:
                if len(current) >= min_len:
                    ascii_strings.append(bytes(current).decode("ascii"))
                current = []
        if len(current) >= min_len:
            ascii_strings.append(bytes(current).decode("ascii"))

        # UTF-16 LE
        i = 0
        while i < len(data) - 1:
            if data[i+1] == 0 and 0x20 <= data[i] <= 0x7e:
                chars, j = [], i
                while j+1 < len(data) and data[j+1] == 0 and 0x20 <= data[j] <= 0x7e:
                    chars.append(chr(data[j])); j += 2
                if len(chars) >= min_len:
                    s = "".join(chars)
                    if s not in ascii_strings:
                        unicode_strings.append(s)
                i = j
            else:
                i += 1

        all_strings = ascii_strings + unicode_strings

        # Categorize
        interesting: dict[str, list[str]] = {
            "flags": [], "urls": [], "emails": [], "ips": [],
            "base64_candidates": [], "file_paths": [], "crypto_keys": [],
        }
        url_re   = re.compile(r'https?://[^\s"\'<>]{4,}')
        email_re = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
        ip_re    = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        flag_re  = re.compile(r'(?:flag|ctf|HTB|THM|picoCTF|FLAG)\{[^}]{1,100}\}', re.I)
        b64_re   = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        path_re  = re.compile(r'(?:/[a-zA-Z0-9_.\-]+){2,}|[A-Z]:\\[^\s"]{4,}')
        key_re   = re.compile(r'-----BEGIN [A-Z ]+-----|[0-9a-fA-F]{40,}')

        for s in all_strings:
            if flag_re.search(s):  interesting["flags"].extend(flag_re.findall(s))
            if url_re.search(s):   interesting["urls"].extend(url_re.findall(s))
            if email_re.search(s): interesting["emails"].extend(email_re.findall(s))
            for ip in ip_re.findall(s):
                if all(0 <= int(p) <= 255 for p in ip.split(".")):
                    interesting["ips"].append(ip)
            if b64_re.search(s) and len(s) >= 20:
                interesting["base64_candidates"].append(s[:80])
            if path_re.search(s):  interesting["file_paths"].extend(path_re.findall(s))
            if key_re.search(s):   interesting["crypto_keys"].append(s[:120])

        for k in interesting:
            interesting[k] = list(dict.fromkeys(interesting[k]))[:20]

        return {
            "ascii_count": len(ascii_strings),
            "unicode_count": len(unicode_strings),
            "total_count": len(all_strings),
            "strings": all_strings[:1000],
            "truncated": len(all_strings) > 1000,
            "interesting": interesting,
            "has_flags": bool(interesting["flags"]),
            "has_urls": bool(interesting["urls"]),
        }
    except Exception as e:
        return {"error": str(e)}


# ─── Hex dump ─────────────────────────────────────────────────────────────────

def get_hex_dump(path: pathlib.Path, lines: int = 64) -> dict:
    try:
        data = path.read_bytes()
        total_bytes = len(data)
        output = []
        for i in range(0, min(lines*16, total_bytes), 16):
            chunk = data[i:i+16]
            hex_l = " ".join(f"{b:02x}" for b in chunk[:8])
            hex_r = " ".join(f"{b:02x}" for b in chunk[8:])
            ascii_part = "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)
            output.append(f"{i:08x}:  {hex_l:<23}  {hex_r:<23}  |{ascii_part}|")
        total_lines = (total_bytes + 15) // 16
        return {
            "dump": "\n".join(output),
            "total_lines": total_lines,
            "total_bytes": total_bytes,
            "truncated": total_lines > lines,
            "showing_bytes": min(lines*16, total_bytes),
        }
    except Exception as e:
        return {"error": str(e)}


# ─── zsteg-style analysis ─────────────────────────────────────────────────────

def zsteg_analysis(path: pathlib.Path) -> dict:
    if not PIL_AVAILABLE:
        return {"error": "Pillow not installed", "findings": []}
    try:
        img = Image.open(path)
        if img.mode not in ("RGB","RGBA"):
            img = img.convert("RGB")
        arr = np.array(img)
        findings = []
        checked = 0
        channels = {"r":0,"g":1,"b":2}

        for order in ("lsb","msb"):
            for bit in range(1, 5):
                for ch_name, ch_idx in channels.items():
                    checked += 1
                    plane = (arr[:,:,ch_idx] >> (bit-1)) & 1 if order=="lsb" else (arr[:,:,ch_idx] >> (8-bit)) & 1
                    bits_flat = plane.flatten()
                    byte_list = []
                    for i in range(0, min(256*8, len(bits_flat)), 8):
                        chunk = bits_flat[i:i+8]
                        if len(chunk) < 8: break
                        byte_list.append(int("".join(str(b) for b in chunk), 2))
                    raw = bytes(byte_list)
                    text = raw.decode("latin-1", errors="replace")
                    printable = sum(1 for c in text if c.isprintable())
                    ratio = printable / max(len(text), 1)
                    embedded = next((desc for sig,desc,_ in MAGIC_SIGNATURES if raw[:len(sig)]==sig), None)
                    flag = re.search(r'(?:flag|ctf|HTB|THM|picoCTF|FLAG)\{[^}]{1,100}\}', text, re.I)
                    if ratio > 0.65 or embedded or flag:
                        findings.append({
                            "description": f"b{bit},{order},{ch_name}",
                            "hex": raw.hex()[:128],
                            "text": text[:120],
                            "printable_ratio": round(ratio,3),
                            "embedded_file": embedded,
                            "flag_found": flag.group(0) if flag else None,
                            "suspicious": ratio > 0.80 or embedded is not None or bool(flag),
                        })

        # Column-order check
        for ch_name, ch_idx in channels.items():
            checked += 1
            col_bits = (arr[:,:,ch_idx] & 1).T.flatten()
            byte_list = []
            for i in range(0, min(128*8, len(col_bits)), 8):
                chunk = col_bits[i:i+8]
                if len(chunk) < 8: break
                byte_list.append(int("".join(str(b) for b in chunk), 2))
            raw = bytes(byte_list)
            text = raw.decode("latin-1", errors="replace")
            printable = sum(1 for c in text if c.isprintable())
            ratio = printable / max(len(text), 1)
            if ratio > 0.70:
                findings.append({
                    "description": f"col-order,lsb,{ch_name}",
                    "hex": raw.hex()[:128],
                    "text": text[:120],
                    "printable_ratio": round(ratio,3),
                    "embedded_file": None,
                    "flag_found": None,
                    "suspicious": ratio > 0.80,
                })

        return {
            "findings": sorted(findings, key=lambda x: x["printable_ratio"], reverse=True),
            "total_checked": checked,
            "suspicious_count": sum(1 for f in findings if f["suspicious"]),
        }
    except Exception as e:
        return {"error": str(e), "findings": []}


# ─── Steghide ────────────────────────────────────────────────────────────────

def extract_steghide(path: pathlib.Path, passphrase: str = "") -> dict:
    import subprocess, tempfile
    try:
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as out:
            out_path = out.name
        result = subprocess.run(
            ["steghide","extract","-sf",str(path),"-p",passphrase,"-f","-xf",out_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            with open(out_path,"rb") as f:
                content = f.read()
            pathlib.Path(out_path).unlink(missing_ok=True)
            try:
                text = content.decode("utf-8")
            except Exception:
                text = content.hex()
            return {"success": True, "content": text, "hex": content.hex()}
        return {"success": False, "error": result.stderr.strip() or "Wrong passphrase or no data"}
    except FileNotFoundError:
        return {"error": "steghide not installed. Linux only: apt install steghide"}
    except Exception as e:
        return {"error": str(e)}