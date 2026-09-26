/**
 * AEGIS-SENTINEL — Toast stack (architecture.md §4.4)
 */
import { useUiStore } from '../state/uiStore'

export function Toasts() {
  const toasts = useUiStore((s) => s.toasts)
  return (
    <div className="toast-wrap" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={'toast glass toast-' + t.kind}>
          {t.kind === 'critical' ? '⛔ ' : t.kind === 'success' ? '✓ ' : 'ℹ '}
          {t.text}
        </div>
      ))}
    </div>
  )
}
