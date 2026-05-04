import { useState } from 'react'
import { osintAPI } from '../utils/api'
import type { UsernameResult } from '../types'
import Card from '../components/shared/Card'
import Spinner from '../components/shared/Spinner'
import { User, CheckCircle, XCircle } from 'lucide-react'

export default function OsintUsernamePage() {
  const [username, setUsername] = useState('')
  const [result, setResult] = useState<UsernameResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const analyze = async () => {
    if (!username.trim()) return
    setLoading(true); setError(null); setResult(null)
    try {
      const { data } = await osintAPI.username(username.trim())
      setResult(data)
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <Card title="Username Cross-Platform Search" mono>
        <p className="text-xs font-mono text-gray-500 mb-3">
          Checks {15} platforms simultaneously for the given username/handle.
        </p>
        <div className="flex gap-3">
          <input
            type="text"
            value={username}
            onChange={e => setUsername(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && analyze()}
            placeholder="target_username"
            className="flex-1 bg-surface-700 border border-surface-500 rounded px-3 py-2 text-sm font-mono text-gray-200 focus:outline-none focus:border-accent-cyan"
          />
          <button
            onClick={analyze}
            disabled={loading || !username.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-accent-cyan text-surface-900 rounded text-sm font-mono font-semibold disabled:opacity-40"
          >
            <User size={14} /> Hunt
          </button>
        </div>
      </Card>

      {loading && <Spinner label="Hunting across platforms (may take ~15s)…" />}
      {error && <div className="p-3 bg-red-900/30 border border-red-800 rounded text-xs font-mono text-red-300">{error}</div>}

      {result && (
        <div className="space-y-4">
          {/* Summary */}
          <div className="flex gap-4 text-sm font-mono">
            <div className="flex items-center gap-2 text-accent-green">
              <CheckCircle size={16} />
              {result.found.length} found
            </div>
            <div className="flex items-center gap-2 text-gray-500">
              <XCircle size={16} />
              {result.not_found.length} not found
            </div>
          </div>

          {/* Found */}
          {result.found.length > 0 && (
            <Card title="Profiles Found" mono badge={String(result.found.length)}>
              <div className="space-y-2">
                {result.found.map(hit => (
                  <div key={hit.platform} className="flex items-center gap-3 text-xs font-mono border-b border-surface-700 pb-2">
                    <CheckCircle size={12} className="text-accent-green shrink-0" />
                    <span className="text-gray-300 w-32 shrink-0">{hit.platform}</span>
                    <a
                      href={hit.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-accent-cyan hover:underline truncate"
                    >
                      {hit.url}
                    </a>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Not found */}
          <Card title="Not Found / Errors" mono>
            <div className="grid grid-cols-3 gap-1">
              {result.not_found.map(hit => (
                <div key={hit.platform} className="text-xs font-mono text-gray-600">
                  {hit.platform}
                </div>
              ))}
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}
