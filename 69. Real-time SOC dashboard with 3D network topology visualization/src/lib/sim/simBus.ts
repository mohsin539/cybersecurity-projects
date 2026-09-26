export type Listener<T> = (payload: T) => void;

export interface SimEventMap {
  alert: import('../../types').SecurityAlert;
  incident: import('../../types').Incident;
  intel: import('../../types').IntelItem;
  topology: { nodeId: string; health: import('../../types').NodeHealth };
  traffic: { sourceId: string; targetId: string; edgeId: string };
  metric: import('../../types').SocMetrics;
  region: { id: string; patch: Partial<import('../../types').RegionState> };
  stream: import('../../types').StreamLine;
}

export class SimBus {
  private listeners = new Map<keyof SimEventMap, Set<Listener<never>>>();

  on<K extends keyof SimEventMap>(type: K, cb: Listener<SimEventMap[K]>): () => void {
    let set = this.listeners.get(type);
    if (!set) {
      set = new Set();
      this.listeners.set(type, set);
    }
    set.add(cb as Listener<never>);
    return () => this.off(type, cb);
  }

  off<K extends keyof SimEventMap>(type: K, cb: Listener<SimEventMap[K]>): void {
    this.listeners.get(type)?.delete(cb as Listener<never>);
  }

  emit<K extends keyof SimEventMap>(type: K, payload: SimEventMap[K]): void {
    const set = this.listeners.get(type);
    if (!set) return;
    for (const cb of [...set]) (cb as Listener<SimEventMap[K]>)(payload);
  }

  clear(): void {
    this.listeners.clear();
  }
}