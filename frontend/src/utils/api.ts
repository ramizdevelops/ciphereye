import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: 120_000, // 2 min for large file analysis
})

export default api

// Stego endpoints
export const stegoAPI = {
  analyze: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post('/api/stego/analyze', fd)
  },
  lsb: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post('/api/stego/lsb', fd)
  },
  strings: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post('/api/stego/strings', fd)
  },
  hex: (file: File, lines = 64) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post(`/api/stego/hex?lines=${lines}`, fd)
  },
  binwalk: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post('/api/stego/binwalk', fd)
  },
  steghide: (file: File, passphrase: string) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post(`/api/stego/steghide?passphrase=${encodeURIComponent(passphrase)}`, fd)
  },
}

// OSINT endpoints
export const osintAPI = {
  ip: (ip: string) => api.post('/api/osint/ip', { ip }),
  domain: (domain: string) => api.post('/api/osint/domain', { domain }),
  username: (username: string) => api.post('/api/osint/username', { username }),
  hash: (hash: string) => api.post('/api/osint/hash', { hash }),
  url: (url: string) => api.post('/api/osint/url', { url }),
}

// GEOINT endpoints
export const geointAPI = {
  extract: (file: File) => {
    const fd = new FormData()
    fd.append('file', file)
    return api.post('/api/geoint/extract', fd)
  },
  batch: (files: File[]) => {
    const fd = new FormData()
    files.forEach(f => fd.append('files', f))
    return api.post('/api/geoint/batch', fd)
  },
}
