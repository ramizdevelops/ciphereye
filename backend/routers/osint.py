"""
OSINT Reconnaissance Router
Handles: IP geolocation, domain recon, username hunting, hash/URL analysis
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.osint_service import (
    geolocate_ip,
    domain_recon,
    hunt_username,
    virustotal_hash,
    virustotal_url,
    shodan_lookup,
)

router = APIRouter()


class IPRequest(BaseModel):
    ip: str


class DomainRequest(BaseModel):
    domain: str


class UsernameRequest(BaseModel):
    username: str


class HashRequest(BaseModel):
    hash: str


class URLRequest(BaseModel):
    url: str


@router.post("/ip")
async def analyze_ip(req: IPRequest):
    """GeoIP + Shodan infrastructure lookup for an IP address."""
    result = await geolocate_ip(req.ip)
    shodan = await shodan_lookup(req.ip)
    return {**result, "shodan": shodan}


@router.post("/domain")
async def analyze_domain(req: DomainRequest):
    """WHOIS + DNS records for a domain."""
    return await domain_recon(req.domain)


@router.post("/username")
async def analyze_username(req: UsernameRequest):
    """Cross-platform username search via Sherlock."""
    return await hunt_username(req.username)


@router.post("/hash")
async def analyze_hash(req: HashRequest):
    """VirusTotal hash lookup (MD5/SHA1/SHA256)."""
    return await virustotal_hash(req.hash)


@router.post("/url")
async def analyze_url(req: URLRequest):
    """VirusTotal URL reputation scan."""
    return await virustotal_url(req.url)
