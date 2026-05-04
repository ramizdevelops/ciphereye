import { useState } from 'react'
import { osintAPI } from '../utils/api'
import type { DomainResult } from '../types'
import Card from '../components/shared/Card'
import Spinner from '../components/shared/Spinner'
import { Globe } from 'lucide-react'

export default function OsintDomainPage() {
  const [domain, setDomain] = useState('')
  const [result, setResult] = useState<DomainResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const analyze = async () => {
    if (!domain.trim()) return
    setLoading(true); setError(null); setResult(null)
    try {
      const { data } = await osintAPI.domain(domain.trim())
      setResult(data)
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <Card title="Domain Recon — WHOIS + DNS" mono>
        <div className="flex gap-3">
          <input
            type="text"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && analyze()}
            placeholder="example.com"
            className="flex-1 bg-surface-700 border border-surface-500 rounded px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:border-accent-cyan"
          />
          <button
            onClick={analyze}
            disabled={loading || !domain.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-accent-cyan text-surface-900 rounded text-sm font-mono font-semibold disabled:opacity-40"
          >
            <Globe size={14} /> Recon
          </button>
        </div>
      </Card>

      {loading && <Spinner label="Running WHOIS & DNS…" />}
      {error && <div className="p-3 bg-red-900/30 border border-red-800 rounded text-xs font-mono text-red-300">{error}</div>}

      {result && (
        <div className="grid grid-cols-2 gap-4">
          <Card title="WHOIS" mono>
            <div className="space-y-1 text-xs font-mono">
              {result.whois.error
                ? <p className="text-red-400">{result.whois.error}</p>
                : <>
                  <KV k="Registrar" v={result.whois.registrar} />
                  <KV k="Created" v={result.whois.creation_date} />
                  <KV k="Expires" v={result.whois.expiration_date} />
                  <KV k="Org" v={result.whois.org} />
                  <KV k="Country" v={result.whois.country} />
                  <KV k="Emails" v={Array.isArray(result.whois.emails) ? result.whois.emails.join(', ') : result.whois.emails} />
                  <div className="pt-1">
                    <p className="text-gray-500 mb-1">Name servers:</p>
                    {result.whois.name_servers?.map((ns, i) => (
                      <p key={i} className="text-accent-green">{ns}</p>
                    ))}
                  </div>
                </>
              }
            </div>
          </Card>

          <Card title="DNS Records" mono>
            <div className="space-y-3 text-xs font-mono">
              {Object.entries(result.dns).map(([rtype, records]) => (
                records && records.length > 0 && (
                  <div key={rtype}>
                    <p className="text-accent-cyan mb-1">{rtype}</p>
                    {records.map((r, i) => (
                      <p key={i} className="text-gray-300 pl-2">{r}</p>
                    ))}
                  </div>
                )
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

function KV({ k, v }: { k: string; v?: string | null }) {
  return (
    <div className="flex gap-2 border-b border-surface-700 pb-1">
      <span className="text-gray-500 w-24 shrink-0">{k}:</span>
      <span className="text-gray-200 break-all">{v || '—'}</span>
    </div>
  )
}
