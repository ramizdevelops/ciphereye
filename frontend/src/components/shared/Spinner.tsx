export default function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-3 text-sm font-mono text-gray-400">
      <div className="w-4 h-4 border-2 border-accent-cyan border-t-transparent rounded-full animate-spin" />
      {label || 'Analyzing…'}
    </div>
  )
}
