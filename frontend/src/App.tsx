import { useState } from 'react'
import { Map, Search, Image, Shield, Terminal, ChevronLeft, ChevronRight, Eye } from 'lucide-react'
import clsx from 'clsx'
import GeointPage from './pages/GeointPage'
import StegoPage from './pages/StegoPage'
import OsintIpPage from './pages/OsintIpPage'
import OsintDomainPage from './pages/OsintDomainPage'
import OsintUsernamePage from './pages/OsintUsernamePage'

type Tab = 'geoint' | 'stego' | 'osint-ip' | 'osint-domain' | 'osint-username'

const NAV: { id: Tab; label: string; icon: React.ReactNode; group: string; color: string }[] = [
  { id: 'geoint',        label: 'GEOINT Map',      icon: <Map size={15} />,      group: 'Geospatial', color: '#38bdf8' },
  { id: 'stego',         label: 'Stego & Forensics',icon: <Image size={15} />,    group: 'Forensics',  color: '#a78bfa' },
  { id: 'osint-ip',      label: 'IP Analysis',     icon: <Search size={15} />,   group: 'OSINT',      color: '#34d399' },
  { id: 'osint-domain',  label: 'Domain Recon',    icon: <Shield size={15} />,   group: 'OSINT',      color: '#34d399' },
  { id: 'osint-username',label: 'Username Hunt',   icon: <Terminal size={15} />, group: 'OSINT',      color: '#34d399' },
]

const GROUP_COLORS: Record<string, string> = {
  Geospatial: '#38bdf8',
  Forensics:  '#a78bfa',
  OSINT:      '#34d399',
}

export default function App() {
  const [tab, setTab] = useState<Tab>('geoint')
  const [collapsed, setCollapsed] = useState(false)
  const activeNav = NAV.find(n => n.id === tab)!

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: '#080c14', color: '#e2e8f0' }}>

      {/* ── Sidebar ── */}
      <aside
        style={{
          background: 'linear-gradient(180deg, #0d1525 0%, #0a1020 100%)',
          borderRight: '1px solid #1e2d45',
          transition: 'width 220ms cubic-bezier(.4,0,.2,1)',
          width: collapsed ? 56 : 220,
          minWidth: collapsed ? 56 : 220,
        }}
        className="flex flex-col"
      >
        {/* Logo */}
        <div style={{ borderBottom: '1px solid #1e2d45', minHeight: 60 }}
             className="flex items-center gap-3 px-3">
          {/* Eye icon as logo */}
          <div style={{
            width: 32, height: 32, borderRadius: 8, flexShrink: 0,
            background: 'linear-gradient(135deg, #0ea5e9 0%, #7c3aed 100%)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 12px #0ea5e940',
          }}>
            <Eye size={17} color="#fff" />
          </div>
          {!collapsed && (
            <div style={{ lineHeight: 1.15 }}>
              <div style={{ fontFamily: "'Courier New', monospace", fontWeight: 700, fontSize: 13, color: '#f0f6ff', letterSpacing: 1 }}>
                CipherEye
              </div>
              <div style={{ fontFamily: "'Courier New', monospace", fontWeight: 400, fontSize: 10, color: '#38bdf8', letterSpacing: 3 }}>
                CTF Workbench
              </div>
            </div>
          )}
        </div>

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto py-3">
          {['Geospatial', 'Forensics', 'OSINT'].map(group => {
            const items = NAV.filter(n => n.group === group)
            const gc = GROUP_COLORS[group]
            return (
              <div key={group} className="mb-1">
                {!collapsed && (
                  <p style={{
                    fontSize: 9, letterSpacing: 2, fontFamily: 'monospace',
                    color: gc, opacity: 0.7, padding: '8px 14px 4px',
                    textTransform: 'uppercase',
                  }}>
                    {group}
                  </p>
                )}
                {items.map(item => {
                  const active = tab === item.id
                  return (
                    <button
                      key={item.id}
                      onClick={() => setTab(item.id)}
                      title={collapsed ? item.label : undefined}
                      style={{
                        width: '100%', display: 'flex', alignItems: 'center',
                        gap: 10, padding: collapsed ? '10px 0' : '9px 14px',
                        justifyContent: collapsed ? 'center' : 'flex-start',
                        fontFamily: 'monospace', fontSize: 12,
                        background: active ? `${item.color}12` : 'transparent',
                        borderRight: active ? `2px solid ${item.color}` : '2px solid transparent',
                        color: active ? item.color : '#94a3b8',
                        transition: 'all 150ms',
                        cursor: 'pointer', border: 'none',
                        borderLeft: 'none', outline: 'none',
                      }}
                      onMouseEnter={e => { if (!active) (e.currentTarget as HTMLElement).style.color = '#e2e8f0' }}
                      onMouseLeave={e => { if (!active) (e.currentTarget as HTMLElement).style.color = '#94a3b8' }}
                    >
                      <span style={{ flexShrink: 0, opacity: active ? 1 : 0.7 }}>{item.icon}</span>
                      {!collapsed && <span style={{ truncate: 'true' } as any}>{item.label}</span>}
                    </button>
                  )
                })}
              </div>
            )
          })}
        </nav>

        {/* Footer credit */}
        {!collapsed && (
          <div style={{
            borderTop: '1px solid #1e2d45',
            padding: '10px 14px 8px',
            display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8,
          }}>
            <span style={{ fontFamily: 'monospace', fontSize: 10, color: '#475569', letterSpacing: 0.5 }}>
              Made with ❤️ by Ramiz
            </span>
            <div style={{ display: 'flex', gap: 6 }}>
              <a
                href="https://linkedin.com/in/ramiz-shaikh2004"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  padding: '4px 10px', borderRadius: 6,
                  background: '#0a66c215', border: '1px solid #0a66c240',
                  color: '#0a66c2', fontFamily: 'monospace', fontSize: 10,
                  textDecoration: 'none', transition: 'all 150ms',
                }}
                onMouseEnter={e => {
                  (e.currentTarget as HTMLElement).style.background = '#0a66c225'
                  ;(e.currentTarget as HTMLElement).style.borderColor = '#0a66c280'
                }}
                onMouseLeave={e => {
                  (e.currentTarget as HTMLElement).style.background = '#0a66c215'
                  ;(e.currentTarget as HTMLElement).style.borderColor = '#0a66c240'
                }}
              >
                <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6zM2 9h4v12H2z"/><circle cx="4" cy="4" r="2"/>
                </svg>
                LinkedIn
              </a>
              <a
                href="https://github.com/ramizdevelops"
                target="_blank"
                rel="noopener noreferrer"
                style={{
                  display: 'flex', alignItems: 'center', gap: 5,
                  padding: '4px 10px', borderRadius: 6,
                  background: '#f0f6ff10', border: '1px solid #f0f6ff20',
                  color: '#94a3b8', fontFamily: 'monospace', fontSize: 10,
                  textDecoration: 'none', transition: 'all 150ms',
                }}
                onMouseEnter={e => {
                  (e.currentTarget as HTMLElement).style.background = '#f0f6ff18'
                  ;(e.currentTarget as HTMLElement).style.color = '#e2e8f0'
                  ;(e.currentTarget as HTMLElement).style.borderColor = '#f0f6ff40'
                }}
                onMouseLeave={e => {
                  (e.currentTarget as HTMLElement).style.background = '#f0f6ff10'
                  ;(e.currentTarget as HTMLElement).style.color = '#94a3b8'
                  ;(e.currentTarget as HTMLElement).style.borderColor = '#f0f6ff20'
                }}
              >
                <svg width="11" height="11" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
                </svg>
                GitHub
              </a>
            </div>
          </div>
        )}

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(c => !c)}
          style={{
            height: 40, display: 'flex', alignItems: 'center', justifyContent: 'center',
            borderTop: '1px solid #1e2d45', background: 'transparent', border: 'none',
            color: '#475569', cursor: 'pointer', width: '100%',
          }}
          onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = '#94a3b8'}
          onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = '#475569'}
        >
          {collapsed ? <ChevronRight size={15} /> : <ChevronLeft size={15} />}
        </button>
      </aside>

      {/* ── Main ── */}
      <main className="flex-1 overflow-hidden flex flex-col" style={{ minWidth: 0 }}>

        {/* Header */}
        <header style={{
          background: 'linear-gradient(90deg, #0d1525 0%, #080c14 100%)',
          borderBottom: '1px solid #1e2d45',
          minHeight: 60, padding: '0 24px',
          display: 'flex', alignItems: 'center',
        }}>
          {/* Breadcrumb */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
            <span style={{ color: '#475569', fontFamily: 'monospace', fontSize: 12 }}>//</span>
            <span style={{ color: GROUP_COLORS[activeNav.group], fontFamily: 'monospace', fontSize: 11, opacity: 0.8 }}>
              {activeNav.group.toLowerCase()}
            </span>
            <span style={{ color: '#334155', fontFamily: 'monospace', fontSize: 12 }}>/</span>
            <span style={{ color: activeNav.color, fontFamily: 'monospace', fontSize: 13, fontWeight: 600 }}>
              {activeNav.label}
            </span>
          </div>

          {/* Status pills */}
          <div style={{ display: 'flex', gap: 8 }}>
            {[
              { label: 'LIVE', color: '#34d399' },
              { label: 'CTF MODE', color: '#a78bfa' },
            ].map(p => (
              <div key={p.label} style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '3px 10px', borderRadius: 20,
                background: `${p.color}15`, border: `1px solid ${p.color}40`,
                fontFamily: 'monospace', fontSize: 10, color: p.color, letterSpacing: 1,
              }}>
                <span style={{
                  width: 5, height: 5, borderRadius: '50%',
                  background: p.color,
                  boxShadow: `0 0 6px ${p.color}`,
                  animation: 'pulse 2s infinite',
                }} />
                {p.label}
              </div>
            ))}
          </div>
        </header>

        {/* Page */}
        <div className="flex-1 overflow-auto">
          {tab === 'geoint'         && <GeointPage />}
          {tab === 'stego'          && <StegoPage />}
          {tab === 'osint-ip'       && <OsintIpPage />}
          {tab === 'osint-domain'   && <OsintDomainPage />}
          {tab === 'osint-username' && <OsintUsernamePage />}
        </div>
      </main>
    </div>
  )
}