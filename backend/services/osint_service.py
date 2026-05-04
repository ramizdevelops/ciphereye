"""
OSINT Service
IP geolocation, domain recon (WHOIS/DNS), username hunting, VirusTotal, Shodan.
"""

import os
import asyncio
import httpx
import dns.resolver
import whois
from typing import Any


def SHODAN_KEY(): return os.getenv("SHODAN_API_KEY", "")
def VT_KEY(): return os.getenv("VIRUSTOTAL_API_KEY", "")


async def geolocate_ip(ip: str) -> dict:
    """
    Query ip-api.com for geolocation, ASN, ISP, and reverse DNS.
    Free, no key required for reasonable CTF usage.
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={
                    "fields": "status,message,country,countryCode,region,regionName,"
                              "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query"
                }
            )
            data = resp.json()
            if data.get("status") == "fail":
                return {"error": data.get("message", "IP lookup failed")}
            return data
    except Exception as e:
        return {"error": str(e)}


async def shodan_lookup(ip: str) -> dict:
    """Query Shodan host API for open ports and banner data."""
    if not SHODAN_KEY():
        return {"info": "Shodan API key not configured. Add SHODAN_API_KEY to .env"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": SHODAN_KEY()}
            )
            if resp.status_code == 404:
                return {"info": "No Shodan data for this IP"}
            data = resp.json()
            # Extract useful fields only
            return {
                "os": data.get("os"),
                "ports": data.get("ports", []),
                "vulns": list(data.get("vulns", {}).keys()),
                "tags": data.get("tags", []),
                "hostnames": data.get("hostnames", []),
                "domains": data.get("domains", []),
                "country": data.get("country_name"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "last_update": data.get("last_update"),
                "services": [
                    {
                        "port": s.get("port"),
                        "transport": s.get("transport"),
                        "product": s.get("product"),
                        "version": s.get("version"),
                        "banner": (s.get("data") or "")[:200],
                    }
                    for s in data.get("data", [])[:10]
                ],
            }
    except Exception as e:
        return {"error": str(e)}


async def domain_recon(domain: str) -> dict:
    """WHOIS + full DNS record enumeration for a domain."""
    result: dict[str, Any] = {"domain": domain}

    # WHOIS
    try:
        w = whois.whois(domain)
        result["whois"] = {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "org": w.org,
            "country": w.country,
        }
    except Exception as e:
        result["whois"] = {"error": str(e)}

    # DNS records
    dns_records: dict[str, Any] = {}
    resolver = dns.resolver.Resolver()
    for rtype in ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=5)
            dns_records[rtype] = [str(r) for r in answers]
        except Exception:
            dns_records[rtype] = []

    result["dns"] = dns_records
    return result


async def hunt_username(username: str) -> dict:
    """
    Cross-platform username search.
    Checks a curated list of platforms directly with false-positive detection.
    Platforms like Instagram/Twitter return 200 even for missing users,
    so we also check response body for not-found indicators.
    """
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter/X": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}",
        "Reddit": f"https://reddit.com/user/{username}",
        "TikTok": f"https://tiktok.com/@{username}",
        "LinkedIn": f"https://linkedin.com/in/{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "Twitch": f"https://twitch.tv/{username}",
        "Medium": f"https://medium.com/@{username}",
        "Keybase": f"https://keybase.io/{username}",
        "HackerNews": f"https://news.ycombinator.com/user?id={username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Pastebin": f"https://pastebin.com/u/{username}",
        "Gravatar": f"https://gravatar.com/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "DevTo": f"https://dev.to/{username}",
        "Replit": f"https://replit.com/@{username}",
        "HackTheBox": f"https://app.hackthebox.com/profile/{username}",
        "Discord": f"https://discord.com/users/{username}",
    }

    # Phrases that indicate a "not found" page even when status is 200
    NOT_FOUND_PATTERNS: dict[str, list[str]] = {
        "Instagram": ["sorry, this page", "isn't available"],
        "Twitter/X": ["this account doesn't exist", "page doesn't exist", "account suspended"],
        "TikTok": ["couldn't find this account", "this account is private"],
        "LinkedIn": ["page not found", "this page doesn't exist", "profile not found"],
        "Reddit": ["nobody on reddit goes by that name", "page not found"],
        "Medium": ["page not found", "this page doesn't exist"],
        "YouTube": ["this page isn't available", "404"],
        "Steam": ["the specified profile could not be found", "an error was encountered"],
        "Pastebin": ["not found"],
        "Gravatar": ["page not found", "no profile"],
        "Twitch": ["sorry. unless you've got a time machine"],
        "DevTo": ["page not found", "404"],
        "Replit": ["page not found", "we couldn't find"],
        "Discord": ["unknown user", "page not found", "404"],
    }

    found = []
    not_found = []

    async def check(name: str, url: str):
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=True) as client:
                resp = await client.get(url, headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                })
                body = resp.text.lower()

                # Check body for not-found phrases (catches false 200s)
                patterns = NOT_FOUND_PATTERNS.get(name, [])
                false_positive = any(p in body for p in patterns)

                if resp.status_code == 200 and not false_positive:
                    found.append({"platform": name, "url": url, "status": "found"})
                else:
                    reason = "not found" if false_positive else str(resp.status_code)
                    not_found.append({"platform": name, "url": url, "status": reason})
        except Exception:
            not_found.append({"platform": name, "url": url, "status": "error"})

    await asyncio.gather(*[check(n, u) for n, u in platforms.items()])

    return {
        "username": username,
        "found": sorted(found, key=lambda x: x["platform"]),
        "not_found": sorted(not_found, key=lambda x: x["platform"]),
        "total_checked": len(platforms),
    }


async def virustotal_hash(hash_value: str) -> dict:
    """Check file hash against VirusTotal."""
    if not VT_KEY():
        return {"info": "VirusTotal API key not configured. Add VIRUSTOTAL_API_KEY to .env"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{hash_value}",
                headers={"x-apikey": VT_KEY()}
            )
            if resp.status_code == 404:
                return {"info": "Hash not found in VirusTotal database"}
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "hash": hash_value,
                "name": attrs.get("meaningful_name", ""),
                "type": attrs.get("type_description", ""),
                "size": attrs.get("size"),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "first_seen": attrs.get("first_submission_date"),
                "last_seen": attrs.get("last_analysis_date"),
                "tags": attrs.get("tags", []),
                "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN",
            }
    except Exception as e:
        return {"error": str(e)}


async def virustotal_url(url: str) -> dict:
    """Submit URL for VirusTotal analysis."""
    if not VT_KEY():
        return {"info": "VirusTotal API key not configured"}
    import base64
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VT_KEY()}
            )
            if resp.status_code == 404:
                # Submit for scanning
                post = await client.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers={"x-apikey": VT_KEY()},
                    data={"url": url}
                )
                return {"info": "URL submitted for scanning", "id": post.json().get("data", {}).get("id")}
            data = resp.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "categories": attrs.get("categories", {}),
                "verdict": "MALICIOUS" if stats.get("malicious", 0) > 0 else "CLEAN",
            }
    except Exception as e:
        return {"error": str(e)}
    