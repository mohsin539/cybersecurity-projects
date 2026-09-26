interface HelpOverlayProps {
  shown: boolean;
  onToggle: () => void;
}

export function HelpOverlay({ shown, onToggle }: HelpOverlayProps) {
  return (
    <>
      <button className="fab-btn help-btn" onClick={onToggle} title="Controls">
        ?
      </button>
      {shown && (
        <div className="help-card" role="dialog" aria-label="Controls help">
          <div className="help-title">
            Controls
            <button className="icon-btn" onClick={onToggle} aria-label="Close help">
              ×
            </button>
          </div>
          <div className="help-grid">
            <div>
              <span className="kbd">Drag</span> Orbit camera
            </div>
            <div>
              <span className="kbd">Scroll</span> Zoom
            </div>
            <div>
              <span className="kbd">Right-drag</span> Pan
            </div>
            <div>
              <span className="kbd">Click</span> Select node / path
            </div>
            <div>
              <span className="kbd">Esc</span> Deselect
            </div>
            <div>
              <span className="kbd">2D</span> Plan view toggle
            </div>
          </div>
          <p className="help-note">
            Selecting a node computes the shortest BloodHound-style attack path toward{' '}
            <strong>DOMAIN ADMINS</strong>. HasSession edges are traversable in both
            directions (session theft <em>and</em> misused credentials).
          </p>
        </div>
      )}
    </>
  );
}