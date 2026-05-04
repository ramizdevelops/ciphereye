#  CipherEye CTF Workbench

**A full-stack OSINT, GEOINT & Steganography analysis platform built for CTF competitions**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-ciphereye.pages.dev-38bdf8?style=flat-square&logo=cloudflare)](https://ciphereye.pages.dev)
[![Frontend](https://img.shields.io/badge/Frontend-React%20+%20TypeScript-61dafb?style=flat-square&logo=react)](https://react.dev)
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20+%20Python-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/License-MIT-a78bfa?style=flat-square)](LICENSE)

<p align="center">
  <img src="img/ciphereye web interface.png" alt="ciphereye web interface" width="500">
  <br>
</p>

</div>

---

##  Features

###  GEOINT — Geospatial Intelligence
- Extract GPS coordinates from image EXIF metadata
- Pin locations on an interactive Leaflet map
- 8 map styles — Satellite, Dark, Voyager, Topo, National Geographic, Ocean and more
- Batch upload multiple images at once

###  Stego & Forensics
- **EXIF Extraction** — Dual-engine (Pillow + exifread) for maximum tag coverage
- **LSB Decode** — Multi-channel, multi-bit-plane steganography detection
- **Binwalk** — Pure-Python embedded file scanner, no external tools needed
- **zsteg-style Analysis** — Bit plane analysis across RGB channels
- **Strings** — ASCII + Unicode extraction with auto-categorization (flags, URLs, IPs, emails)
- **Hex Dump** — xxd-style hex viewer
- **File Hashes** — MD5, SHA1, SHA256 for VirusTotal lookups
- **Steghide** — Passphrase-based extraction support

###  OSINT — Open Source Intelligence
- **IP Analysis** — GeoIP, ASN, ISP, reverse DNS + Shodan integration
- **Domain Recon** — WHOIS, DNS records (A, AAAA, MX, TXT, NS, CNAME)
- **Username Hunt** — Cross-platform search across 17 platforms with false-positive detection
- **VirusTotal** — File hash and URL malware scanning

---

##  Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS |
| Backend | FastAPI, Python 3.11, uvicorn |
| Maps | Leaflet.js, react-leaflet |
| Image Analysis | Pillow, exifread, numpy |
| OSINT APIs | Shodan, VirusTotal, ip-api.com |
| Deployment | Cloudflare Pages + Render |

---

##  Getting Started

### Prerequisites
- Python 3.11+
- Node.js 18+

### Local Development

**1. Clone the repo**
```bash
git clone https://github.com/ramizdevelops/ciphereye.git
cd ciphereye
```

**2. Backend setup**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**3. Create `.env` file in backend/**
```env
SHODAN_API_KEY=your_shodan_key
VIRUSTOTAL_API_KEY=your_virustotal_key
```

**4. Start backend**
```bash
python -m uvicorn main:app --reload --port 8000
```

**5. Frontend setup**
```bash
cd ../frontend
npm install
npm run dev
```

**6. Open** `http://localhost:5173`

---

##  API Keys (Optional)

| Service | Get Key | Used For |
|---------|---------|---------|
| Shodan | [account.shodan.io](https://account.shodan.io) | Port scanning, vulnerability data |
| VirusTotal | [virustotal.com](https://www.virustotal.com/gui/my-apikey) | Malware scanning |

All API keys are optional — the tool works without them with limited features.

---

##  Project Structure

```
ciphereye/
├── frontend/                  # React + TypeScript
│   ├── src/
│   │   ├── pages/             # GEOINT, Stego, OSINT pages
│   │   ├── components/        # Shared UI components
│   │   ├── utils/             # API client
│   │   └── types/             # TypeScript interfaces
│   └── package.json
│
└── backend/                   # FastAPI + Python
    ├── routers/               # API route handlers
    │   ├── geoint.py
    │   ├── stego.py
    │   └── osint.py
    ├── services/              
    │   ├── stego_service.py   # Forensics engine
    │   ├── osint_service.py   # OSINT engine
    │   └── geoint_service.py  # GPS extraction
    ├── main.py
    └── requirements.txt
```

---

##  Deployment

| Service | Platform |
|---------|----------|
| Frontend | Cloudflare Pages |
| Backend | Render |

---

##  License

This project is licensed under the [MIT License](LICENSE).

---

##  Author

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Ramiz_Shaikh-0a66c2?style=flat-square&logo=linkedin)](https://linkedin.com/in/ramiz-shaikh2004/)
[![GitHub](https://img.shields.io/badge/GitHub-ramizdevelops-white?style=flat-square&logo=github)](https://github.com/ramizdevelops)
