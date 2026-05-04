// ─── Stego & Forensics ────────────────────────────────────────────────────────

export interface FileTypeResult {
  mime: string
  description: string
  magic_bytes: string
  magic_bytes_ascii?: string
  signature_match?: string
  file_size_bytes?: number
  file_size_kb?: number
  error?: string
}

export interface HashesResult {
  md5: string
  sha1: string
  sha256: string
  size_bytes: number
  size_kb: number
  error?: string
}

export interface ExifSummary {
  total_tags: number
  has_gps: boolean
  has_camera_info: boolean
  note?: string
}

export interface GpsDecimal {
  latitude: number
  longitude: number
  google_maps: string
  altitude_m?: number
}

export interface ExifData {
  basic: Record<string, string | number>
  gps: Record<string, any>
  camera: Record<string, string>
  settings: Record<string, string>
  dates: Record<string, string>
  thumbnail: Record<string, string>
  raw_tags: Record<string, string>
  _summary: ExifSummary
}

export interface LsbBitResult {
  hex: string
  text: string
  printable_ratio: number
  likely_hidden: boolean
  embedded_file: string | null
  flag_found: string | null
}

export interface LsbChannelResult {
  bit0?: LsbBitResult
  bit1?: LsbBitResult
  bit2?: LsbBitResult
}

export interface LsbResult {
  red?: LsbChannelResult
  green?: LsbChannelResult
  blue?: LsbChannelResult
  alpha?: LsbChannelResult
  gray?: LsbChannelResult
  combined_rgb?: LsbChannelResult
  error?: string
}

export interface StringsInteresting {
  flags: string[]
  urls: string[]
  emails: string[]
  ips: string[]
  base64_candidates: string[]
  file_paths: string[]
  crypto_keys: string[]
}

export interface StringsResult {
  ascii_count: number
  unicode_count: number
  total_count: number
  strings: string[]
  truncated: boolean
  interesting: StringsInteresting
  has_flags: boolean
  has_urls: boolean
  error?: string
}

export interface HexResult {
  dump: string
  total_lines?: number
  total_bytes?: number
  truncated: boolean
  showing_bytes?: number
  error?: string
}

export interface BinwalkFinding {
  offset_decimal: number
  offset_hex: string
  description: string
  is_file_start: boolean
  note: string
}

export interface AppendedData {
  type: string
  eof_offset: string
  trailing_bytes: number
  preview_hex: string
  note: string
}

export interface PngChunk {
  offset: string
  type: string
  length: number
  suspicious: boolean
  note?: string
  content?: string
}

export interface BinwalkResult {
  file_size?: number
  file_size_kb?: number
  findings: BinwalkFinding[]
  total_signatures_found?: number
  appended_data?: AppendedData[]
  png_chunks?: PngChunk[]
  has_suspicious?: boolean
  engine?: string
  error?: string
}

export interface ZstegFinding {
  description: string
  hex: string
  text: string
  printable_ratio: number
  embedded_file: string | null
  flag_found: string | null
  suspicious: boolean
}

export interface ZstegResult {
  findings: ZstegFinding[]
  total_checked: number
  suspicious_count?: number
  error?: string
}

export interface StegoAnalysisResult {
  filename: string
  hashes?: HashesResult
  file_type: FileTypeResult
  exif: ExifData
  strings: StringsResult
  hex_dump: HexResult
  lsb: LsbResult
  binwalk: BinwalkResult
  zsteg: ZstegResult
}

// ─── GEOINT ───────────────────────────────────────────────────────────────────

export interface GpsLocation {
  filename: string
  lat: number
  lon: number
  altitude: number | null
  gps_tags: Record<string, string>
  has_gps?: boolean
  all_exif?: Record<string, string>
}

// ─── OSINT — IP ───────────────────────────────────────────────────────────────

export interface IpResult {
  status?: string
  country?: string
  countryCode?: string
  region?: string
  regionName?: string
  city?: string
  zip?: string
  lat?: number
  lon?: number
  timezone?: string
  isp?: string
  org?: string
  as?: string
  asname?: string
  reverse?: string
  query?: string
  shodan?: ShodanResult
  error?: string
}

export interface ShodanService {
  port: number
  transport: string
  product: string
  version: string
  banner: string
}

export interface ShodanResult {
  os?: string
  ports?: number[]
  vulns?: string[]
  tags?: string[]
  hostnames?: string[]
  domains?: string[]
  country?: string
  org?: string
  isp?: string
  last_update?: string
  services?: ShodanService[]
  error?: string
  info?: string
}

// ─── OSINT — Domain ───────────────────────────────────────────────────────────

export interface WhoisResult {
  registrar?: string
  creation_date?: string
  expiration_date?: string
  name_servers?: string[]
  status?: string | string[]
  emails?: string | string[]
  org?: string
  country?: string
  error?: string
}

export interface DnsResult {
  A?: string[]
  AAAA?: string[]
  MX?: string[]
  TXT?: string[]
  NS?: string[]
  CNAME?: string[]
  SOA?: string[]
}

export interface DomainResult {
  domain: string
  whois: WhoisResult
  dns: DnsResult
}

// ─── OSINT — Username ─────────────────────────────────────────────────────────

export interface UsernameHit {
  platform: string
  url: string
  status: string
}

export interface UsernameResult {
  username: string
  found: UsernameHit[]
  not_found: UsernameHit[]
  total_checked: number
}

// ─── OSINT — VirusTotal ───────────────────────────────────────────────────────

export interface VtResult {
  hash?: string
  url?: string
  name?: string
  type?: string
  size?: number
  malicious: number
  suspicious: number
  harmless: number
  undetected?: number
  first_seen?: number
  last_seen?: number
  tags?: string[]
  verdict: 'MALICIOUS' | 'CLEAN'
  categories?: Record<string, string>
  info?: string
  error?: string
}