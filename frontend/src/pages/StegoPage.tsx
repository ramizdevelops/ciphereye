import { useState } from 'react'
import { stegoAPI } from '../utils/api'
import type { StegoAnalysisResult, LsbChannelResult } from '../types'
import FileDropzone from '../components/shared/FileDropzone'
import Card from '../components/shared/Card'
import Spinner from '../components/shared/Spinner'
import clsx from 'clsx'
import { AlertTriangle, Flag, Link, Hash } from 'lucide-react'

type ActiveTab = 'filetype' | 'hashes' | 'exif' | 'lsb' | 'strings' | 'hex' | 'binwalk' | 'zsteg'

export default function StegoPage() {
  const [file, setFile]               = useState<File | null>(null)
  const [result, setResult]           = useState<StegoAnalysisResult | null>(null)
  const [loading, setLoading]         = useState(false)
  const [error, setError]             = useState<string | null>(null)
  const [activeTab, setActiveTab]     = useState<ActiveTab>('filetype')
  const [steghidePass, setSteghidePass] = useState('')
  const [steghideResult, setSteghideResult] = useState<any>(null)

  const handleFile = async (f: File) => {
    setFile(f); setResult(null); setError(null); setSteghideResult(null); setLoading(true)
    try {
      const { data } = await stegoAPI.analyze(f)
      setResult(data)
      // Auto-switch to flags tab if flags found
      if (data?.strings?.has_flags) setActiveTab('strings')
      else if (data?.binwalk?.has_suspicious) setActiveTab('binwalk')
      else setActiveTab('filetype')
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const handleSteghide = async () => {
    if (!file) return
    try {
      const { data } = await stegoAPI.steghide(file, steghidePass)
      setSteghideResult(data)
    } catch (e: any) {
      setSteghideResult({ error: e.message })
    }
  }

  // Build tab badges
  const exifTotal   = result?.exif?._summary?.total_tags ?? 0
  const stringsTotal = result?.strings?.total_count ?? 0
  const binwalkHits = (result?.binwalk?.findings ?? []).filter(f => !f.is_file_start).length +
                      (result?.binwalk?.appended_data?.length ?? 0)
  const zstegHits   = result?.zsteg?.suspicious_count ?? result?.zsteg?.findings?.length ?? 0
  const hasSuspicious = result?.binwalk?.has_suspicious || result?.strings?.has_flags || zstegHits > 0

  const tabs: { id: ActiveTab; label: string; badge?: string; alert?: boolean }[] = [
    { id: 'filetype', label: 'File Type' },
    { id: 'hashes',   label: 'Hashes' },
    { id: 'exif',     label: 'EXIF',    badge: exifTotal > 0 ? String(exifTotal) : undefined },
    { id: 'lsb',      label: 'LSB Decode' },
    { id: 'zsteg',    label: 'zsteg',   badge: zstegHits > 0 ? `${zstegHits} hits` : undefined, alert: zstegHits > 0 },
    { id: 'strings',  label: 'Strings', badge: stringsTotal > 0 ? String(stringsTotal) : undefined, alert: result?.strings?.has_flags },
    { id: 'hex',      label: 'Hex Dump' },
    { id: 'binwalk',  label: 'Binwalk', badge: binwalkHits > 0 ? `${binwalkHits} embedded` : undefined, alert: binwalkHits > 0 },
  ]

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-5">

      {/* Alert banner if suspicious findings */}
      {hasSuspicious && (
        <div className="flex items-center gap-3 p-3 rounded-lg border border-yellow-600/50 bg-yellow-900/20 text-yellow-300 text-xs font-mono">
          <AlertTriangle size={14} className="shrink-0" />
          <span>⚠ Suspicious content detected — check highlighted tabs</span>
        </div>
      )}

      <div className="flex items-start gap-5">
        {/* Dropzone */}
        <div className="flex-1">
          <FileDropzone
            onFile={handleFile}
            label="Drop any file for forensics analysis"
            hint="Images, binaries, archives, documents — anything goes"
          />
          {file && (
            <p className="mt-2 text-xs font-mono text-gray-500">
              Loaded: <span className="text-accent-cyan">{file.name}</span>{' '}
              ({(file.size / 1024).toFixed(1)} KB)
            </p>
          )}
        </div>

        {/* Steghide panel */}
        <Card title="steghide extract" className="w-72">
          <div className="space-y-3">
            <p className="text-xs font-mono text-gray-500">
              Attempt steghide extraction (Linux only — requires steghide installed).
            </p>
            <input
              type="text"
              placeholder="passphrase (optional)"
              value={steghidePass}
              onChange={e => setSteghidePass(e.target.value)}
              className="w-full bg-surface-700 border border-surface-500 rounded px-3 py-1.5 text-xs font-mono text-gray-200 focus:outline-none focus:border-accent-cyan"
            />
            <button
              onClick={handleSteghide}
              disabled={!file}
              className="w-full py-1.5 bg-accent-cyan text-surface-900 rounded text-xs font-mono font-semibold disabled:opacity-40 hover:bg-opacity-80 transition-colors"
            >
              Extract
            </button>
            {steghideResult && (
              <div className={clsx('p-2 rounded text-xs font-mono',
                steghideResult.success ? 'bg-green-900/30 text-green-300' : 'bg-red-900/30 text-red-300'
              )}>
                {steghideResult.success
                  ? <><strong>Found!</strong><br />{steghideResult.content}</>
                  : steghideResult.error || 'Not found / wrong passphrase'}
              </div>
            )}
          </div>
        </Card>
      </div>

      {loading && <Spinner label="Running all forensics modules…" />}
      {error && (
        <div className="p-3 bg-red-900/30 border border-red-800 rounded text-xs font-mono text-red-300">
          Error: {error}
        </div>
      )}

      {result && (
        <div>
          {/* Tabs */}
          <div className="flex gap-1 border-b border-surface-600 mb-4 overflow-x-auto pb-px">
            {tabs.map(t => (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={clsx(
                  'flex items-center gap-2 px-3 py-2 text-xs font-mono whitespace-nowrap border-b-2 transition-colors',
                  activeTab === t.id
                    ? 'border-accent-cyan text-accent-cyan'
                    : 'border-transparent text-gray-500 hover:text-gray-300'
                )}
              >
                {t.alert && <AlertTriangle size={10} className="text-yellow-400" />}
                {t.label}
                {t.badge && (
                  <span className={clsx(
                    'rounded px-1.5 py-0.5 text-xs',
                    t.alert ? 'bg-yellow-900/50 text-yellow-300' : 'bg-surface-600 text-gray-300'
                  )}>
                    {t.badge}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* ── File Type ── */}
          {activeTab === 'filetype' && (
            <Card title="File Signature & Type" mono>
              <div className="space-y-2 text-xs font-mono">
                <Row label="MIME Type"       value={result.file_type?.mime} />
                <Row label="Description"     value={result.file_type?.description} />
                <Row label="Signature Match" value={result.file_type?.signature_match} />
                <Row label="Size"            value={result.file_type?.file_size_kb ? `${result.file_type.file_size_kb} KB (${result.file_type.file_size_bytes} bytes)` : undefined} />
                <Row label="Magic Bytes"     value={result.file_type?.magic_bytes} mono />
                <Row label="ASCII Preview"   value={result.file_type?.magic_bytes_ascii} mono />
              </div>
            </Card>
          )}

          {/* ── Hashes ── */}
          {activeTab === 'hashes' && (
            <Card title="File Hashes" mono>
              {result.hashes?.error ? (
                <p className="text-xs font-mono text-red-400">{result.hashes.error}</p>
              ) : (
                <div className="space-y-2 text-xs font-mono">
                  <div className="flex items-center gap-2 mb-3">
                    <Hash size={12} className="text-accent-cyan" />
                    <span className="text-gray-400">Use these to look up on VirusTotal</span>
                  </div>
                  <Row label="MD5"    value={result.hashes?.md5} mono />
                  <Row label="SHA1"   value={result.hashes?.sha1} mono />
                  <Row label="SHA256" value={result.hashes?.sha256} mono />
                  <Row label="Size"   value={`${result.hashes?.size_kb} KB (${result.hashes?.size_bytes} bytes)`} />
                </div>
              )}
            </Card>
          )}

          {/* ── EXIF ── */}
          {activeTab === 'exif' && (
            <div className="space-y-4">
              {result.exif?._summary?.note && (
                <div className="p-3 bg-surface-700 rounded text-xs font-mono text-gray-400">
                  {result.exif._summary.note}
                </div>
              )}

              {/* GPS section — highlight if present */}
              {result.exif?.gps && Object.keys(result.exif.gps).length > 0 && (
                <Card title="📍 GPS Location" mono badge="GPS Found!" badgeColor="#166534">
                  <div className="space-y-1">
                    {result.exif.gps._decimal && (
                      <div className="mb-3 p-2 bg-green-900/20 border border-green-800/50 rounded">
                        <p className="text-green-300 text-xs font-mono font-bold">
                          {result.exif.gps._decimal.latitude}, {result.exif.gps._decimal.longitude}
                        </p>
                        <a
                          href={result.exif.gps._decimal.google_maps}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-accent-cyan text-xs font-mono flex items-center gap-1 mt-1 hover:underline"
                        >
                          <Link size={10} /> Open in Google Maps
                        </a>
                        {result.exif.gps._decimal.altitude_m && (
                          <p className="text-gray-400 text-xs font-mono mt-1">
                            Altitude: {result.exif.gps._decimal.altitude_m}m
                          </p>
                        )}
                      </div>
                    )}
                    {Object.entries(result.exif.gps).filter(([k]) => k !== '_decimal').map(([k, v]) => (
                      <div key={k} className="flex gap-2 text-xs font-mono border-b border-surface-700 pb-1">
                        <span className="text-gray-500 w-40 shrink-0">{k}</span>
                        <span className="text-gray-200 break-all">{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </Card>
              )}

              {/* Other EXIF sections */}
              {([
                ['Camera Info', result.exif?.camera],
                ['Capture Settings', result.exif?.settings],
                ['Dates & Times', result.exif?.dates],
                ['Image Info', result.exif?.basic],
                ['Thumbnail', result.exif?.thumbnail],
                ['Raw / Maker Notes', result.exif?.raw_tags],
              ] as [string, Record<string, any>][]).map(([title, section]) =>
                section && Object.keys(section).length > 0 ? (
                  <Card key={title} title={title} mono>
                    <div className="space-y-1 max-h-64 overflow-y-auto">
                      {Object.entries(section).map(([k, v]) => (
                        <div key={k} className="flex gap-2 text-xs font-mono border-b border-surface-700 pb-1">
                          <span className="text-gray-500 w-48 shrink-0 truncate">{k}</span>
                          <span className="text-gray-200 break-all">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  </Card>
                ) : null
              )}
            </div>
          )}

          {/* ── LSB ── */}
          {activeTab === 'lsb' && (
            <div className="space-y-4">
              {result.lsb?.error ? (
                <div className="p-3 bg-red-900/30 border border-red-800 rounded text-xs font-mono text-red-300">
                  {result.lsb.error}
                </div>
              ) : (
                Object.entries(result.lsb ?? {}).map(([chName, chData]) => {
                  const ch = chData as LsbChannelResult
                  const bits = Object.entries(ch ?? {})
                  const hasHidden = bits.some(([, b]: any) => b?.likely_hidden)
                  return (
                    <Card
                      key={chName}
                      title={`LSB — ${chName}`}
                      mono
                      badge={hasHidden ? '⚠ suspicious' : undefined}
                      badgeColor={hasHidden ? '#7c1d1d' : undefined}
                    >
                      <div className="space-y-3">
                        {bits.map(([bitLabel, bitData]: any) => (
                          <div key={bitLabel} className={clsx(
                            'p-2 rounded border text-xs font-mono',
                            bitData?.likely_hidden
                              ? 'border-yellow-700/50 bg-yellow-900/10'
                              : 'border-surface-600'
                          )}>
                            <div className="flex items-center gap-3 mb-2">
                              <span className="text-accent-cyan font-semibold">{bitLabel}</span>
                              <span className={bitData?.printable_ratio > 0.7 ? 'text-green-400' : 'text-gray-500'}>
                                printable: {((bitData?.printable_ratio ?? 0) * 100).toFixed(0)}%
                              </span>
                              {bitData?.likely_hidden && (
                                <span className="text-yellow-400 flex items-center gap-1">
                                  <AlertTriangle size={10} /> Hidden data likely
                                </span>
                              )}
                              {bitData?.flag_found && (
                                <span className="text-green-300 flex items-center gap-1 font-bold">
                                  <Flag size={10} /> FLAG: {bitData.flag_found}
                                </span>
                              )}
                              {bitData?.embedded_file && (
                                <span className="text-purple-300">📁 {bitData.embedded_file}</span>
                              )}
                            </div>
                            <pre className="bg-surface-900 p-2 rounded text-gray-300 overflow-x-auto max-h-20 whitespace-pre-wrap break-all text-xs">
                              {bitData?.text?.slice(0, 200) || '(empty)'}
                            </pre>
                            <p className="text-gray-600 mt-1 break-all">{bitData?.hex?.slice(0, 64)}…</p>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )
                })
              )}
            </div>
          )}

          {/* ── zsteg ── */}
          {activeTab === 'zsteg' && (
            <Card title="zsteg — Bit Plane Analysis" mono
              badge={`${result.zsteg?.findings?.length ?? 0} hits / ${result.zsteg?.total_checked ?? 0} checked`}>
              {result.zsteg?.error ? (
                <p className="text-xs font-mono text-red-400">{result.zsteg.error}</p>
              ) : !result.zsteg?.findings?.length ? (
                <p className="text-xs font-mono text-gray-500">
                  No suspicious bit planes found across {result.zsteg?.total_checked ?? 0} combinations checked.
                </p>
              ) : (
                <div className="space-y-3">
                  {result.zsteg.findings.map((f, i) => (
                    <div key={i} className={clsx(
                      'border rounded p-3 text-xs font-mono',
                      f.suspicious ? 'border-yellow-700/60 bg-yellow-900/10' : 'border-surface-600'
                    )}>
                      <div className="flex items-center gap-3 mb-1">
                        <span className="text-accent-cyan font-semibold">{f.description}</span>
                        <span className="text-gray-500">ratio: {(f.printable_ratio * 100).toFixed(0)}%</span>
                        {f.flag_found && (
                          <span className="text-green-300 font-bold flex items-center gap-1">
                            <Flag size={10} /> {f.flag_found}
                          </span>
                        )}
                        {f.embedded_file && (
                          <span className="text-purple-300">📁 {f.embedded_file}</span>
                        )}
                      </div>
                      <pre className="mt-1 text-gray-200 break-all whitespace-pre-wrap">{f.text}</pre>
                      <p className="text-gray-600 mt-1">{f.hex}</p>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}

          {/* ── Strings ── */}
          {activeTab === 'strings' && (
            <div className="space-y-4">
              {result.strings?.error ? (
                <div className="p-3 bg-red-900/30 border border-red-800 rounded text-xs font-mono text-red-300">
                  {result.strings.error}
                </div>
              ) : (
                <>
                  {/* Summary */}
                  <div className="grid grid-cols-4 gap-3">
                    {[
                      { label: 'ASCII', value: result.strings?.ascii_count ?? 0 },
                      { label: 'Unicode', value: result.strings?.unicode_count ?? 0 },
                      { label: 'Total', value: result.strings?.total_count ?? 0 },
                      { label: 'Flags 🚩', value: result.strings?.interesting?.flags?.length ?? 0, highlight: true },
                    ].map(s => (
                      <div key={s.label} className={clsx(
                        'p-3 rounded border text-center font-mono text-xs',
                        s.highlight && (s.value as number) > 0
                          ? 'border-green-700/60 bg-green-900/20 text-green-300'
                          : 'border-surface-600 text-gray-400'
                      )}>
                        <div className="text-lg font-bold text-gray-200">{s.value}</div>
                        {s.label}
                      </div>
                    ))}
                  </div>

                  {/* CTF Flags — most important */}
                  {(result.strings?.interesting?.flags?.length ?? 0) > 0 && (
                    <Card title="🚩 CTF Flags Found!" mono badge="HIGH VALUE" badgeColor="#166534">
                      {result.strings.interesting.flags.map((flag, i) => (
                        <div key={i} className="p-2 mb-1 bg-green-900/30 border border-green-700/50 rounded text-green-300 font-mono text-sm font-bold">
                          {flag}
                        </div>
                      ))}
                    </Card>
                  )}

                  {/* Interesting categories */}
                  {(['urls','emails','ips','crypto_keys','base64_candidates','file_paths'] as const).map(cat => {
                    const items = result.strings?.interesting?.[cat] ?? []
                    if (!items.length) return null
                    const labels: Record<string, string> = {
                      urls: '🌐 URLs', emails: '📧 Emails', ips: '🌍 IP Addresses',
                      crypto_keys: '🔑 Crypto Keys / Hashes',
                      base64_candidates: '🔒 Base64 Candidates',
                      file_paths: '📂 File Paths',
                    }
                    return (
                      <Card key={cat} title={labels[cat]} mono badge={String(items.length)}>
                        <div className="space-y-1 max-h-40 overflow-y-auto">
                          {items.map((item, i) => (
                            <p key={i} className="text-xs font-mono text-gray-300 break-all border-b border-surface-700 pb-1">
                              {item}
                            </p>
                          ))}
                        </div>
                      </Card>
                    )
                  })}

                  {/* Raw strings */}
                  <Card title="All Strings" mono badge={result.strings?.truncated ? 'truncated at 1000' : undefined}>
                    <pre className="text-xs font-mono text-gray-300 max-h-96 overflow-y-auto whitespace-pre-wrap break-all bg-surface-900 p-3 rounded">
                      {(result.strings?.strings ?? []).join('\n')}
                    </pre>
                  </Card>
                </>
              )}
            </div>
          )}

          {/* ── Hex Dump ── */}
          {activeTab === 'hex' && (
            <Card title="Hex Dump" mono
              badge={result.hex_dump?.truncated
                ? `showing ${result.hex_dump.showing_bytes} / ${result.hex_dump.total_bytes} bytes`
                : `${result.hex_dump?.total_bytes} bytes`}>
              {result.hex_dump?.error ? (
                <p className="text-xs font-mono text-red-400">{result.hex_dump.error}</p>
              ) : (
                <pre className="text-xs font-mono text-accent-green max-h-[60vh] overflow-y-auto bg-surface-900 p-3 rounded leading-5">
                  {result.hex_dump?.dump}
                </pre>
              )}
            </Card>
          )}

          {/* ── Binwalk ── */}
          {activeTab === 'binwalk' && (
            <div className="space-y-4">
              <div className="flex items-center gap-3 text-xs font-mono text-gray-500 p-2 bg-surface-800 rounded border border-surface-600">
                <span>Engine:</span>
                <span className="text-accent-cyan">{result.binwalk?.engine ?? 'Pure-Python'}</span>
                <span className="ml-auto">File size: {result.binwalk?.file_size_kb} KB</span>
              </div>

              {result.binwalk?.error ? (
                <div className="p-3 bg-red-900/30 border border-red-800 rounded text-xs font-mono text-red-300">
                  {result.binwalk.error}
                </div>
              ) : (
                <>
                  {/* Appended data — most suspicious */}
                  {(result.binwalk?.appended_data?.length ?? 0) > 0 && (
                    <Card title="⚠ Appended Data After EOF" mono badge="SUSPICIOUS" badgeColor="#7c1d1d">
                      {result.binwalk.appended_data!.map((a, i) => (
                        <div key={i} className="mb-3 p-3 border border-yellow-700/50 bg-yellow-900/10 rounded text-xs font-mono">
                          <p className="text-yellow-300 font-bold mb-1">{a.type}</p>
                          <Row label="EOF Offset"     value={a.eof_offset} mono />
                          <Row label="Trailing Bytes" value={String(a.trailing_bytes)} />
                          <Row label="Preview Hex"    value={a.preview_hex} mono />
                          <p className="text-yellow-400 mt-1">{a.note}</p>
                        </div>
                      ))}
                    </Card>
                  )}

                  {/* PNG chunks */}
                  {(result.binwalk?.png_chunks?.length ?? 0) > 0 && (
                    <Card title="PNG Chunk Analysis" mono badge={String(result.binwalk!.png_chunks!.length)}>
                      {result.binwalk!.png_chunks!.map((c, i) => (
                        <div key={i} className={clsx(
                          'mb-2 p-2 rounded border text-xs font-mono',
                          c.suspicious ? 'border-yellow-700/50 bg-yellow-900/10' : 'border-surface-700'
                        )}>
                          <div className="flex gap-3">
                            <span className="text-accent-cyan">{c.offset}</span>
                            <span className={c.suspicious ? 'text-yellow-300 font-bold' : 'text-gray-300'}>{c.type}</span>
                            <span className="text-gray-500">{c.length} bytes</span>
                            {c.suspicious && <span className="text-yellow-400">⚠ suspicious</span>}
                          </div>
                          {c.note && <p className="text-gray-400 mt-1">{c.note}</p>}
                          {c.content && <p className="text-gray-300 mt-1 break-all">{c.content}</p>}
                        </div>
                      ))}
                    </Card>
                  )}

                  {/* All signature findings */}
                  <Card title="Signature Scan" mono
                    badge={`${result.binwalk?.total_signatures_found ?? 0} found`}>
                    {!result.binwalk?.findings?.length ? (
                      <p className="text-xs font-mono text-gray-500">No file signatures found.</p>
                    ) : (
                      <div className="space-y-1 max-h-96 overflow-y-auto">
                        {result.binwalk.findings.map((f, i) => (
                          <div key={i} className={clsx(
                            'flex gap-3 text-xs font-mono border-b border-surface-700 pb-2 py-1',
                            !f.is_file_start && 'bg-yellow-900/5'
                          )}>
                            <span className="text-accent-cyan w-24 shrink-0">{f.offset_hex}</span>
                            <span className="text-gray-500 w-20 shrink-0">{f.offset_decimal}</span>
                            <div className="flex-1">
                              <span className={f.is_file_start ? 'text-gray-300' : 'text-yellow-300 font-semibold'}>
                                {f.description}
                              </span>
                              <span className="text-gray-600 ml-2 text-xs">{f.note}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </Card>
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function Row({ label, value, mono }: { label: string; value?: string; mono?: boolean }) {
  return (
    <div className="flex gap-2 border-b border-surface-700 pb-1 text-xs font-mono">
      <span className="text-gray-500 w-36 shrink-0">{label}:</span>
      <span className={clsx('break-all', mono ? 'text-accent-green' : 'text-gray-200')}>{value || '—'}</span>
    </div>
  )
}