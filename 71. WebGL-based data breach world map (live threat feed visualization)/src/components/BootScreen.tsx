/**
 * AEGIS-SENTINEL — Boot screen (architecture.md §4.4 loading state)
 */
import { useUiStore } from '../state/uiStore'

export function BootScreen() {
  const booted = useUiStore((s) => s.booted)
  return (
    <div className={'boot' + (booted ? ' done' : '')} aria-hidden={booted}>
      <div className="boot-ring" />
      <h1>AEGIS-SENTINEL</h1>
      <p>INITIALIZING GLOBE · CONNECTING FEEDS · WARMING AUDIT LEDGER</p>
    </div>
  )
}
