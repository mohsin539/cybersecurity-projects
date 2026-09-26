import { useEffect, useMemo, useState } from 'react';
import { generateBloodHoundGraph } from './lib/graphData';
import { socSim } from './lib/sim/socSim';
import { SocProvider, useSoc } from './state/socStore';
import type { SocModule } from './types';
import { MODULES, NavRail } from './components/NavRail';
import { StreamTicker } from './components/StreamTicker';
import { TopologyModule } from './components/modules/TopologyModule';
import { BlanketMapModule } from './components/modules/BlanketMapModule';
import { AlertWorkbench } from './components/modules/AlertWorkbench';
import { IncidentCenter } from './components/modules/IncidentCenter';
import { QueryStudio } from './components/modules/QueryStudio';
import { ThreatIntelFeed } from './components/modules/ThreatIntelFeed';
import { ComplianceReports } from './components/modules/ComplianceReports';

const model = generateBloodHoundGraph();
socSim.configure(model.nodes, model.edges);
const seedState = socSim.seed();

function Shell() {
  const { state, dispatch } = useSoc();
  const [module, setModule] = useState<SocModule>('topology');

  useEffect(() => {
    const unsubs = [
      socSim.on('alert', (a) => dispatch({ type: 'ADD_ALERT', alert: a })),
      socSim.on('incident', (i) => dispatch({ type: 'ADD_INCIDENT', incident: i })),
      socSim.on('intel', (item) => dispatch({ type: 'ADD_INTEL', item })),
      socSim.on('topology', (t) =>
        dispatch({ type: 'SET_NODE_HEALTH', nodeId: t.nodeId, health: t.health }),
      ),
      socSim.on('traffic', (t) => dispatch({ type: 'SET_TRAFFIC', edges: [t.edgeId] })),
      socSim.on('metric', (m) => dispatch({ type: 'UPDATE_METRICS', metrics: m })),
      socSim.on('region', (r) => dispatch({ type: 'UPDATE_REGION', id: r.id, patch: r.patch })),
      socSim.on('stream', (l) => dispatch({ type: 'PUSH_STREAM', line: l })),
    ];
    socSim.start();
    return () => {
      socSim.stop();
      unsubs.forEach((u) => u());
    };
  }, [dispatch]);

  const openAlerts = useMemo(
    () => state.alerts.filter((a) => a.status === 'new' || a.status === 'triaging' || a.status === 'escalated').length,
    [state.alerts],
  );
  const openIncidents = useMemo(() => state.incidents.filter((i) => i.status !== 'closed').length, [state.incidents]);
  const activeModule = MODULES.find((m) => m.id === module) ?? MODULES[0];
  const critical = useMemo(() => state.alerts.filter((a) => a.severity === 'critical').length, [state.alerts]);

  const goto = (m: SocModule) => setModule(m);

  return (
    <div className="app-main soc-app">
      <header className="topbar soc-topbar">
        <div className="brand">
          <span className="brand-mark">◉</span>
          <span className="brand-title">SOC Command</span>
          <span className="brand-sub">Real-time dashboard · 3D topology</span>
        </div>
        <div className="soc-module-title">
          <span className="soc-module-icon">{activeModule.icon}</span>
          <span>{activeModule.label}</span>
        </div>
        <div className="topbar-actions soc-topbar-actions">
          <span className={`topbar-chip ${critical ? 'danger' : ''}`}>
            <i /> {critical} critical alerts
          </span>
          <span className="topbar-chip">
            <i /> {openIncidents} open incidents
          </span>
          <span className="topbar-chip">
            <i /> {Math.round(state.metrics.eps)} EPS
          </span>
          <span className="user-chip" title="Signed in as analyst-1">
            <span className="user-avatar">A1</span>
            <span>Analyst · Tier 1</span>
          </span>
        </div>
      </header>

      <div className="soc-body">
        <NavRail active={module} onChange={goto} alertCount={openAlerts} incidentCount={openIncidents} />
        <main className="soc-module-view">
          {module === 'topology' && <TopologyModule state={state} />}
          {module === 'blanket' && <BlanketMapModule state={state} onGoto={goto} />}
          {module === 'alerts' && <AlertWorkbench state={state} dispatch={dispatch} />}
          {module === 'incidents' && <IncidentCenter state={state} dispatch={dispatch} />}
          {module === 'query' && <QueryStudio state={state} />}
          {module === 'intel' && <ThreatIntelFeed state={state} />}
          {module === 'compliance' && <ComplianceReports state={state} />}
        </main>
      </div>

      <footer className="statusbar soc-statusbar">
        <StreamTicker
          stream={state.stream}
          metrics={state.metrics}
          epsHistory={state.epsHistory}
          alertRateHistory={state.alertRateHistory}
          onGoto={goto}
        />
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <SocProvider initial={seedState}>
      <Shell />
    </SocProvider>
  );
}