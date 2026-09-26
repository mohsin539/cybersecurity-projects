import { createContext, useContext, useMemo, useReducer } from 'react';
import type { ReactNode } from 'react';
import type {
  Incident,
  IntelItem,
  NodeHealth,
  RegionState,
  SecurityAlert,
  SocMetrics,
  SocState,
  StreamLine,
} from '../types';

export type SocAction =
  | { type: 'SEED'; state: SocState }
  | { type: 'ADD_ALERT'; alert: SecurityAlert }
  | { type: 'UPDATE_ALERT'; id: string; patch: Partial<SecurityAlert> }
  | { type: 'ADD_INCIDENT'; incident: Incident }
  | { type: 'UPDATE_INCIDENT'; id: string; patch: Partial<Incident> }
  | { type: 'TOGGLE_TASK'; incidentId: string; taskId: string }
  | { type: 'ADD_INCIDENT_NOTE'; incidentId: string; actor: string; note: string }
  | { type: 'ADD_INTEL'; item: IntelItem }
  | { type: 'SET_NODE_HEALTH'; nodeId: string; health: NodeHealth }
  | { type: 'SET_TRAFFIC'; edges: string[] }
  | { type: 'UPDATE_METRICS'; metrics: SocMetrics }
  | { type: 'UPDATE_REGION'; id: string; patch: Partial<RegionState> }
  | { type: 'PUSH_STREAM'; line: StreamLine };

const ALERT_CAP = 260;
const INTEL_CAP = 70;
const STREAM_CAP = 18;
const HIST_CAP = 40;

export const initialState: SocState = {
  alerts: [],
  incidents: [],
  intel: [],
  nodeHealth: {},
  stream: [],
  metrics: { eps: 0, alertRate: 0, exposure: 0, coverage: 0 },
  epsHistory: [],
  alertRateHistory: [],
  regions: {},
  trafficEdges: [],
  logs: [],
};

export function socReducer(state: SocState, action: SocAction): SocState {
  switch (action.type) {
    case 'SEED':
      return { ...action.state };
    case 'ADD_ALERT': {
      const alerts = [action.alert, ...state.alerts].slice(0, ALERT_CAP);
      return { ...state, alerts };
    }
    case 'UPDATE_ALERT':
      return {
        ...state,
        alerts: state.alerts.map((a) => (a.id === action.id ? { ...a, ...action.patch } : a)),
      };
    case 'ADD_INCIDENT':
      return {
        ...state,
        incidents: upsertIncident(state.incidents, action.incident),
      };
    case 'UPDATE_INCIDENT':
      return {
        ...state,
        incidents: state.incidents.map((i) =>
          i.id === action.id ? { ...i, ...action.patch, events: i.events } : i,
        ),
      };
    case 'TOGGLE_TASK':
      return {
        ...state,
        incidents: state.incidents.map((i) =>
          i.id === action.incidentId
            ? {
                ...i,
                tasks: i.tasks.map((t) =>
                  t.id === action.taskId ? { ...t, done: !t.done } : t,
                ),
              }
            : i,
        ),
      };
    case 'ADD_INCIDENT_NOTE': {
      const inc = state.incidents.find((i) => i.id === action.incidentId);
      if (!inc) return state;
      return {
        ...state,
        incidents: state.incidents.map((i) =>
          i.id === action.incidentId
            ? {
                ...i,
                events: [
                  ...i.events,
                  { ts: Date.now(), actor: action.actor, action: 'note', note: action.note },
                ],
                notes: action.note,
              }
            : i,
        ),
      };
    }
    case 'ADD_INTEL':
      return {
        ...state,
        intel: [action.item, ...state.intel].slice(0, INTEL_CAP),
      };
    case 'SET_NODE_HEALTH':
      return {
        ...state,
        nodeHealth: { ...state.nodeHealth, [action.nodeId]: action.health },
      };
    case 'SET_TRAFFIC':
      return { ...state, trafficEdges: action.edges };
    case 'UPDATE_METRICS':
      return {
        ...state,
        metrics: action.metrics,
        epsHistory: pushCap(state.epsHistory, action.metrics.eps, HIST_CAP),
        alertRateHistory: pushCap(state.alertRateHistory, action.metrics.alertRate, HIST_CAP),
      };
    case 'UPDATE_REGION': {
      const regions: Record<string, RegionState> = { ...state.regions };
      const cur = regions[action.id];
      regions[action.id] = cur ? { ...cur, ...action.patch } : { ...(action.patch as RegionState) };
      return { ...state, regions };
    }
    case 'PUSH_STREAM':
      return { ...state, stream: pushCap(state.stream, action.line, STREAM_CAP) };
    default:
      return state;
  }
}

function pushCap<T>(arr: T[], value: T, cap: number): T[] {
  const next = [value, ...arr];
  if (next.length > cap) next.length = cap;
  return next;
}

function upsertIncident(list: Incident[], inc: Incident): Incident[] {
  const idx = list.findIndex((i) => i.id === inc.id);
  if (idx === -1) return [inc, ...list].slice(0, 24);
  const next = [...list];
  next[idx] = inc;
  return next;
}

export interface SocStore {
  state: SocState;
  dispatch: React.Dispatch<SocAction>;
}

const SocContext = createContext<SocStore | null>(null);

export function SocProvider({ children, initial }: { children: ReactNode; initial?: SocState }) {
  const [state, dispatch] = useReducer(socReducer, initial ?? initialState);
  const store = useMemo<SocStore>(() => ({ state, dispatch }), [state]);
  return <SocContext.Provider value={store}>{children}</SocContext.Provider>;
}

export function useSoc(): SocStore {
  const ctx = useContext(SocContext);
  if (!ctx) throw new Error('useSoc must be used within SocProvider');
  return ctx;
}