import { useState, useEffect } from 'react'
import { MapContainer, TileLayer, Marker, Popup, useMap } from 'react-leaflet'
import L from 'leaflet'
import { Upload, MapPin, Info, Layers } from 'lucide-react'
import { useDropzone } from 'react-dropzone'
import { geointAPI } from '../utils/api'
import type { GpsLocation } from '../types'
import Spinner from '../components/shared/Spinner'
// @ts-ignore
import 'leaflet/dist/leaflet.css'

delete (L.Icon.Default.prototype as any)._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png',
  iconUrl:       'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png',
  shadowUrl:     'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png',
})

// ── Map styles ────────────────────────────────────────────────────────────────
const MAP_STYLES = [
  {
    id: 'voyager',
    label: 'Voyager',
    emoji: '🗺️',
    url: 'https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png',
    attribution: '&copy; OSM &copy; CARTO',
    preview: '#6ab3e0',
  },
  {
    id: 'dark',
    label: 'Dark Matter',
    emoji: '🌑',
    url: 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',
    attribution: '&copy; OSM &copy; CARTO',
    preview: '#1a1a2e',
  },
  {
    id: 'light',
    label: 'Light',
    emoji: '☀️',
    url: 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',
    attribution: '&copy; OSM &copy; CARTO',
    preview: '#f5f5f0',
  },
  {
    id: 'satellite',
    label: 'Satellite',
    emoji: '🛰️',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}',
    attribution: '&copy; Esri &mdash; Esri, i-cubed, USDA, USGS, AEX, GeoEye, Getmapping, Aerogrid, IGN, IGP, UPR-EGP',
    preview: '#2d4a1e',
  },
  {
    id: 'topo',
    label: 'Topographic',
    emoji: '⛰️',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}',
    attribution: '&copy; Esri &mdash; Esri, DeLorme, NAVTEQ',
    preview: '#c8b97a',
  },
  {
    id: 'osm',
    label: 'OpenStreetMap',
    emoji: '🌍',
    url: 'https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',
    attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
    preview: '#a8d08a',
  },
  {
    id: 'natgeo',
    label: 'National Geo',
    emoji: '🧭',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/NatGeo_World_Map/MapServer/tile/{z}/{y}/{x}',
    attribution: '&copy; Esri &mdash; National Geographic',
    preview: '#b5c9a1',
  },
  {
    id: 'ocean',
    label: 'Ocean',
    emoji: '🌊',
    url: 'https://server.arcgisonline.com/ArcGIS/rest/services/Ocean/World_Ocean_Base/MapServer/tile/{z}/{y}/{x}',
    attribution: '&copy; Esri &mdash; Sources: GEBCO, NOAA',
    preview: '#1a5f8a',
  },
]

// ── FlyTo helper ──────────────────────────────────────────────────────────────
function FlyTo({ locations }: { locations: GpsLocation[] }) {
  const map = useMap()
  useEffect(() => {
    if (locations.length === 1) {
      map.flyTo([locations[0].lat, locations[0].lon], 13, { duration: 1.2 })
    } else if (locations.length > 1) {
      const bounds = L.latLngBounds(locations.map(l => [l.lat, l.lon]))
      map.flyToBounds(bounds, { padding: [40, 40], duration: 1.2 })
    }
  }, [locations, map])
  return null
}

// ── TileLayer switcher (must be inside MapContainer) ─────────────────────────
function DynamicTileLayer({ styleId }: { styleId: string }) {
  const style = MAP_STYLES.find(s => s.id === styleId) ?? MAP_STYLES[0]
  return <TileLayer key={styleId} url={style.url} attribution={style.attribution} />
}

// ── Main component ────────────────────────────────────────────────────────────
export default function GeointPage() {
  const [locations, setLocations] = useState<GpsLocation[]>([])
  const [loading, setLoading]     = useState(false)
  const [error, setError]         = useState<string | null>(null)
  const [selected, setSelected]   = useState<GpsLocation | null>(null)
  const [mapStyle, setMapStyle]   = useState('voyager')
  const [showPicker, setShowPicker] = useState(false)

  const onDrop = async (files: File[]) => {
    if (!files.length) return
    setLoading(true); setError(null)
    try {
      if (files.length === 1) {
        const { data } = await geointAPI.extract(files[0])
        if (data.has_gps) {
          setLocations(prev => [...prev, data as GpsLocation])
          setSelected(data as GpsLocation)
        } else {
          setError(`No GPS data found in "${files[0].name}"`)
        }
      } else {
        const { data } = await geointAPI.batch(files)
        setLocations(prev => [...prev, ...data.locations])
      }
    } catch (e: any) {
      setError(e?.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'image/*': ['.jpg', '.jpeg', '.png', '.tiff', '.heic'] },
    multiple: true,
  })

  const activeStyle = MAP_STYLES.find(s => s.id === mapStyle) ?? MAP_STYLES[0]

  return (
    <div className="flex h-full">

      {/* ── Map ── */}
      <div className="flex-1 relative">
        <MapContainer center={[20, 0]} zoom={2} className="w-full h-full" style={{ background: '#0d1117' }}>
          <DynamicTileLayer styleId={mapStyle} />
          {locations.map((loc, i) => (
            <Marker key={i} position={[loc.lat, loc.lon]} eventHandlers={{ click: () => setSelected(loc) }}>
              <Popup>
                <div className="font-mono text-xs">
                  <strong>{loc.filename}</strong><br />
                  {loc.lat.toFixed(6)}, {loc.lon.toFixed(6)}
                  {loc.altitude != null && <><br />Alt: {loc.altitude.toFixed(1)}m</>}
                </div>
              </Popup>
            </Marker>
          ))}
          <FlyTo locations={locations} />
        </MapContainer>

        {/* ── Map style picker button ── */}
        <div className="absolute top-3 left-3 z-[1000]">
          <button
            onClick={() => setShowPicker(p => !p)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '7px 12px', borderRadius: 8,
              background: '#0d152599', backdropFilter: 'blur(8px)',
              border: '1px solid #1e2d45', color: '#e2e8f0',
              fontFamily: 'monospace', fontSize: 11, cursor: 'pointer',
            }}
          >
            <Layers size={13} />
            {activeStyle.emoji} {activeStyle.label}
            <span style={{ color: '#475569', fontSize: 10 }}>▼</span>
          </button>

          {/* ── Style picker dropdown ── */}
          {showPicker && (
            <div style={{
              position: 'absolute', top: 40, left: 0,
              background: '#0d1525ee', backdropFilter: 'blur(12px)',
              border: '1px solid #1e2d45', borderRadius: 10,
              padding: 8, minWidth: 200, zIndex: 2000,
              boxShadow: '0 8px 32px #00000080',
            }}>
              <p style={{
                fontFamily: 'monospace', fontSize: 9, color: '#475569',
                letterSpacing: 2, padding: '4px 8px 8px', textTransform: 'uppercase',
              }}>
                Map Style
              </p>
              {MAP_STYLES.map(style => (
                <button
                  key={style.id}
                  onClick={() => { setMapStyle(style.id); setShowPicker(false) }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 10,
                    width: '100%', padding: '8px 10px', borderRadius: 6,
                    background: mapStyle === style.id ? '#1e2d45' : 'transparent',
                    border: mapStyle === style.id ? '1px solid #38bdf840' : '1px solid transparent',
                    color: mapStyle === style.id ? '#38bdf8' : '#94a3b8',
                    fontFamily: 'monospace', fontSize: 11, cursor: 'pointer',
                    textAlign: 'left', marginBottom: 2,
                    transition: 'all 120ms',
                  }}
                  onMouseEnter={e => {
                    if (mapStyle !== style.id)
                      (e.currentTarget as HTMLElement).style.background = '#1e2d4580'
                  }}
                  onMouseLeave={e => {
                    if (mapStyle !== style.id)
                      (e.currentTarget as HTMLElement).style.background = 'transparent'
                  }}
                >
                  {/* Color swatch */}
                  <span style={{
                    width: 14, height: 14, borderRadius: 3, flexShrink: 0,
                    background: style.preview, border: '1px solid #ffffff20',
                  }} />
                  <span>{style.emoji} {style.label}</span>
                  {mapStyle === style.id && (
                    <span style={{ marginLeft: 'auto', color: '#38bdf8', fontSize: 12 }}>✓</span>
                  )}
                </button>
              ))}
            </div>
          )}
        </div>

        {/* ── Upload button ── */}
        <div
          {...getRootProps()}
          className={`absolute bottom-4 right-4 z-[1000] flex items-center gap-2 px-4 py-2 rounded-lg cursor-pointer font-mono text-xs transition-all ${
            isDragActive
              ? 'bg-accent-cyan text-surface-900'
              : 'bg-surface-800 border border-surface-500 text-gray-300 hover:border-accent-cyan'
          }`}
          style={{ backdropFilter: 'blur(8px)' }}
        >
          <input {...getInputProps()} />
          <Upload size={14} />
          {isDragActive ? 'Drop images…' : 'Upload images'}
        </div>
      </div>

      {/* ── Side panel ── */}
      <aside className="w-80 bg-surface-800 border-l border-surface-600 flex flex-col overflow-hidden">
        <div className="p-4 border-b border-surface-600">
          <h2 className="text-sm font-mono font-semibold text-accent-cyan flex items-center gap-2">
            <MapPin size={14} /> GEOINT Panel
          </h2>
          <p className="text-xs text-gray-500 mt-1 font-mono">
            Upload images with EXIF GPS data to pin locations on the map.
          </p>
        </div>

        {loading && <div className="p-4"><Spinner label="Extracting coordinates…" /></div>}

        {error && (
          <div className="mx-4 mt-4 p-3 bg-red-900/30 border border-red-800 rounded text-xs font-mono text-red-300">
            {error}
          </div>
        )}

        {/* Location list */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {locations.length === 0 && !loading && (
            <div className="text-center py-8 text-gray-600 text-xs font-mono">
              No locations yet.<br />Upload an image to begin.
            </div>
          )}
          {locations.map((loc, i) => (
            <button
              key={i}
              onClick={() => setSelected(loc)}
              className={`w-full text-left p-3 rounded border font-mono text-xs transition-colors ${
                selected === loc
                  ? 'border-accent-cyan bg-surface-700'
                  : 'border-surface-600 hover:border-surface-500'
              }`}
            >
              <div className="text-gray-300 truncate">{loc.filename}</div>
              <div className="text-accent-green mt-0.5">
                {loc.lat.toFixed(5)}, {loc.lon.toFixed(5)}
              </div>
              {loc.altitude != null && (
                <div className="text-gray-500">Alt: {loc.altitude.toFixed(1)}m</div>
              )}
            </button>
          ))}
        </div>

        {/* Selected detail */}
        {selected && (
          <div className="border-t border-surface-600 p-4 max-h-64 overflow-y-auto">
            <p className="text-xs font-mono text-gray-400 mb-2 flex items-center gap-1">
              <Info size={12} /> EXIF GPS Tags
            </p>
            {Object.entries(selected.gps_tags || {}).map(([k, v]) => (
              <div key={k} className="text-xs font-mono mb-1">
                <span className="text-gray-500">{k.replace('GPS ', '')}:</span>{' '}
                <span className="text-gray-200">{v}</span>
              </div>
            ))}
            {locations.length > 0 && (
              <button
                onClick={() => { setLocations([]); setSelected(null) }}
                className="mt-3 text-xs font-mono text-red-400 hover:text-red-300"
              >
                Clear all markers
              </button>
            )}
          </div>
        )}
      </aside>
    </div>
  )
}