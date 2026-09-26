/**
 * AEGIS-SENTINEL — UI state store (state.md §4)
 */
import { create } from 'zustand'
import type { Role } from '../security/rbac'

export type ModalKind = 'reports' | 'audit' | 'verify' | 'about' | null

export interface Toast {
  id: number
  kind: 'info' | 'success' | 'critical'
  text: string
}

interface UiState {
  booted: boolean
  perfHud: boolean
  cinematic: boolean
  directorMode: boolean
  role: Role
  modal: ModalKind
  toasts: Toast[]

  setBooted: (v: boolean) => void
  togglePerfHud: () => void
  toggleCinematic: () => void
  toggleDirector: () => void
  setRole: (r: Role) => void
  openModal: (m: ModalKind) => void
  pushToast: (kind: Toast['kind'], text: string) => void
  dismissToast: (id: number) => void
}

let toastSeq = 1

export const useUiStore = create<UiState>((set, get) => ({
  booted: false,
  perfHud: true,
  cinematic: false,
  directorMode: false,
  role: 'analyst',
  modal: null,
  toasts: [],

  setBooted: (v) => set({ booted: v }),
  togglePerfHud: () => set({ perfHud: !get().perfHud }),
  toggleCinematic: () => set({ cinematic: !get().cinematic }),
  toggleDirector: () => set({ directorMode: !get().directorMode }),
  setRole: (r) => set({ role: r }),
  openModal: (m) => set({ modal: m }),
  pushToast: (kind, text) => {
    const id = toastSeq++
    set({ toasts: [...get().toasts, { id, kind, text }].slice(-4) })
    window.setTimeout(() => get().dismissToast(id), 4200)
  },
  dismissToast: (id) => set({ toasts: get().toasts.filter((t) => t.id !== id) }),
}))
