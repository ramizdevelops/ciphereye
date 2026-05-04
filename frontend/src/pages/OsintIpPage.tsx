import { useState } from 'react'
import { osintAPI } from '../utils/api'
import type { IpResult } from '../types'
import Card from '../components/shared/Card'
import Spinner from '../components/shared/Spinner'
import { Search } from 'lucide-react'

export default function OsintIpPage() {
  const [ip, setIp] = useState('')
  const [result, setResult] = useState<IpResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const analyze = async () => {
    if (!ip.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const { data } = await osintAPI.ip(ip.trim())
      setResult(data)
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      {/* Input */}
      <Card title="IP / Infrastructure Analysis" mono>
        <div className="flex gap-3">
          <input
            type="text"
            value={ip}
            onChange={e => setIp(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && analyze()}
            placeholder="Enter IP address (e.g. 1.1.1.1)"
            className="flex-1 bg-surface-700 border border-surface-500 rounded px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:border-accent-cyan"
          />
          <button
            onClick={analyze}
            disabled={loading || !ip.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-accent-cyan text-surface-900 rounded text-sm font-mono font-semibold disabled:opacity-40 hover:bg-opacity-80"
          >
            <Search size={14} /> Analyze
          </button>
        </div>
      </Card>

      {loading && <Spinner label="Querying GeoIP & Shodan…" />}
      {error && (
        <div className="p-3 bg-red-900/30 border border-red-800 rounded text-xs font-mono text-red-300">
          {error}
        </div>
      )}

      {result && (
        <div className="grid grid-cols-2 gap-4">
          {/* Geo info */}
          <Card title="Geolocation" mono>
            <div className="space-y-1 text-xs font-mono">
              <KV k="IP" v={result.query} />
              <KV k="Country" v={`${result.country} (${result.countryCode})`} />
              <KV k="Region" v={result.regionName} />
              <KV k="City" v={result.city} />
              <KV k="Timezone" v={result.timezone} />
              <KV k="Coordinates" v={result.lat != null ? `${result.lat}, ${result.lon}` : '—'} accent />
            </div>
          </Card>

          {/* Network info */}
          <Card title="Network / ASN" mono>
            <div className="space-y-1 text-xs font-mono">
              <KV k="ISP" v={result.isp} />
              <KV k="Org" v={result.org} />
              <KV k="ASN" v={result.as} />
              <KV k="AS Name" v={result.asname} />
              <KV k="Reverse DNS" v={result.reverse} accent />
            </div>
          </Card>

          {/* Shodan */}
          {result.shodan && !('info' in result.shodan) && !('error' in result.shodan) && (
            <>
              <Card title="Shodan — Open Ports" mono badge={`${result.shodan.ports?.length || 0} ports`}>
                <div className="flex flex-wrap gap-2">
                  {result.shodan.ports?.map(p => (
                    <span key={p} className="bg-surface-700 text-accent-orange px-2 py-0.5 rounded text-xs font-mono">
                      {p}
                    </span>
                  ))}
                </div>
                {result.shodan.vulns && result.shodan.vulns.length > 0 && (
                  <div className="mt-3">
                    <p className="text-xs font-mono text-red-400 mb-1">⚠ CVEs</p>
                    <div className="flex flex-wrap gap-1">
                      {result.shodan.vulns.map(v => (
                        <span key={v} className="text-xs font-mono text-red-300 bg-red-900/30 px-2 py-0.5 rounded">
                          {v}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </Card>

              <Card title="Shodan — Services" mono>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {result.shodan.services?.map((s, i) => (
                    <div key={i} className="text-xs font-mono border-b border-surface-700 pb-2">
                      <span className="text-accent-cyan">{s.port}/{s.transport}</span>
                      {s.product && <span className="text-gray-300 ml-2">{s.product} {s.version}</span>}
                      {s.banner && (
                        <pre className="text-gray-500 mt-1 whitespace-pre-wrap break-all text-xs">
                          {s.banner.slice(0, 120)}
                        </pre>
                      )}
                    </div>
                  ))}
                </div>
              </Card>
            </>
          )}

          {result.shodan && ('info' in result.shodan || 'error' in result.shodan) && (
            <Card title="Shodan" mono>
              <p className="text-xs font-mono text-gray-500">
                {'info' in result.shodan ? result.shodan.info : (result.shodan as any).error}
              </p>
            </Card>
          )}
        </div>
      )}
    </div>
  )
}

function KV({ k, v, accent }: { k: string; v?: string; accent?: boolean }) {
  return (
    <div className="flex gap-2 border-b border-surface-700 pb-1">
      <span className="text-gray-500 w-28 shrink-0">{k}:</span>
      <span className={accent ? 'text-accent-green' : 'text-gray-200'}>{v || '—'}</span>
    </div>
  )
}
