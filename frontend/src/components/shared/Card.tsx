import clsx from 'clsx'

interface CardProps {
  title?: string
  children: React.ReactNode
  className?: string
  mono?: boolean
  badge?: string
  badgeColor?: string
}

export default function Card({ title, children, className, mono, badge, badgeColor }: CardProps) {
  return (
    <div className={clsx('bg-surface-800 border border-surface-600 rounded-lg overflow-hidden', className)}>
      {title && (
        <div className="flex items-center justify-between px-4 py-2.5 border-b border-surface-600 bg-surface-700">
          <span className={clsx('text-sm font-medium', mono ? 'font-mono text-accent-cyan' : 'text-gray-300')}>
            {title}
          </span>
          {badge && (
            <span
              className="text-xs font-mono px-2 py-0.5 rounded"
              style={{ background: badgeColor || '#21262d', color: '#e6edf3' }}
            >
              {badge}
            </span>
          )}
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  )
}
