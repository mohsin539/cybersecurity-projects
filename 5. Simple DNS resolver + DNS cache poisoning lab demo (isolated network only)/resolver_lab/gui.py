"""tkinter GUI for the DNS cache poisoning lab.

Threading rule (reference/memory.md pitfall #6): tkinter must live on the main thread.
The lab runs in a worker thread and reports results through a queue drained by
root.after(100, poll).
"""

import queue
import threading
import tkinter as tk
from tkinter import messagebox, ttk

from . import lab
from .scenarios import SCENARIOS

RESULT_COLS = ('Trial', 'Scenario', 'Seed', 'Verdict', 'Target', 'Got', 'Expected',
               'Labels', 'P(win)', 'Note')
CACHE_COLS = ('Name', 'Q', 'Rdata', 'Kind', 'TTL', 'Deadline', 'From', 'Forged')
TIMELINE_COLS = ('Seq', 'Tick', 'Src', 'Dst', 'Summary')


def _bool_str(v):
    return 'ON' if v else 'off'


class LabGUI:
    def __init__(self, root):
        self.root = root
        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.last_result = None
        self.running = False
        root.title('DNS Resolver + Cache Poisoning Lab  (isolated simulated network)')
        root.geometry('1220x780')
        self._build()
        self._poll()

    # ---- UI construction -------------------------------------------------
    def _build(self):
        pad = {'padx': 4, 'pady': 2}
        top = ttk.Frame(self.root, padding=6)
        top.pack(side=tk.TOP, fill=tk.X)
        top.columnconfigure(8, weight=1)

        ttk.Label(top, text='Scenario:').grid(row=0, column=0, sticky='w', **pad)
        self.scen_var = tk.StringVar(value='03_kaminsky')
        self.scen_cb = ttk.Combobox(top, textvariable=self.scen_var, state='readonly',
                                    width=24, values=list(SCENARIOS))
        self.scen_cb.grid(row=0, column=1, sticky='w', **pad)
        self.scen_cb.bind('<<ComboboxSelected>>', lambda e: self._show_desc())

        ttk.Label(top, text='Seed:').grid(row=0, column=2, sticky='e', **pad)
        self.seed_var = tk.StringVar(value='1337')
        ttk.Entry(top, textvariable=self.seed_var, width=8).grid(row=0, column=3, sticky='w', **pad)

        ttk.Label(top, text='Trials:').grid(row=0, column=4, sticky='e', **pad)
        self.trials_var = tk.StringVar(value='3')
        ttk.Spinbox(top, from_=1, to=50, textvariable=self.trials_var, width=5).grid(row=0, column=5, sticky='w', **pad)

        self.run_btn = ttk.Button(top, text='▶ Run trials', command=self._run)
        self.run_btn.grid(row=0, column=6, sticky='w', **pad)
        self.stop_btn = ttk.Button(top, text='■ Stop', command=self._stop, state='disabled')
        self.stop_btn.grid(row=0, column=7, sticky='w', **pad)
        ttk.Button(top, text='Flush cache view', command=self._flush_cache).grid(row=0, column=8, sticky='e', **pad)

        self.desc_var = tk.StringVar(value=SCENARIOS['03_kaminsky'].get('describe', ''))
        ttk.Label(top, textvariable=self.desc_var, wraplength=1180,
                  foreground='#444').grid(row=1, column=0, columnspan=9, sticky='w', **pad)

        # defenses
        df = ttk.LabelFrame(top, text='Defenses on the resolver (scenario may pin some)',
                            padding=4)
        df.grid(row=2, column=0, columnspan=9, sticky='we', **pad)
        self.def_vars = {
            'random_id': tk.BooleanVar(value=True),
            'random_port': tk.BooleanVar(value=False),
            'use_0x20': tk.BooleanVar(value=False),
            'bailiwick_check': tk.BooleanVar(value=True),
        }
        for i, (k, label) in enumerate([
            ('random_id', 'random ID'),
            ('random_port', 'random source port'),
            ('use_0x20', '0x20 case encoding'),
            ('bailiwick_check', 'bailiwick check'),
        ]):
            ttk.Checkbutton(df, text=label, variable=self.def_vars[k]).grid(row=0, column=i, sticky='w', padx=8)
        ttk.Label(df, text='TTL floor:').grid(row=0, column=4, sticky='e', padx=(12, 2))
        self.floor_var = tk.StringVar(value='0')
        ttk.Spinbox(df, from_=0, to=300, textvariable=self.floor_var, width=5).grid(row=0, column=5, sticky='w')

        # main area
        main = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        main.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=6, pady=4)

        nb = ttk.Notebook(main)
        main.add(nb, weight=3)

        # results
        res = ttk.Frame(nb)
        nb.add(res, text='Results')
        self.res_tree = self._tree(res, RESULT_COLS, stretch=(3, 6))
        tag = {'foreground': 'crimson'}
        self.res_tree.tag_configure('poisoned', **tag)
        self.res_tree.tag_configure('blocked', foreground='seagreen')

        # cache
        cache = ttk.Frame(nb)
        nb.add(cache, text='Cache snapshot')
        self.cache_tree = self._tree(cache, CACHE_COLS, stretch=(4, 3, 4))
        self.cache_tree.tag_configure('forged', foreground='crimson')
        self.cache_tree.tag_configure('delegation', foreground='#663')

        # timeline
        tl = ttk.Frame(nb)
        nb.add(tl, text='Packet timeline')
        self.tl_tree = self._tree(tl, TIMELINE_COLS, stretch=(5,))
        self.tl_tree.tag_configure('malformed', foreground='crimson')

        # side panel: attacker/race info + logs
        side = ttk.Frame(main, width=360)
        main.add(side, weight=1)
        ttk.Label(side, text='Race / attacker info').pack(anchor='w', padx=4, pady=(6, 2))
        self.race_txt = tk.Text(side, height=6, state='disabled', wrap='word',
                                background='#fafafa')
        self.race_txt.pack(fill=tk.X, padx=4)
        ttk.Label(side, text='Log').pack(anchor='w', padx=4, pady=(6, 2))
        self.log_txt = tk.Text(side, state='disabled', wrap='word', background='#f7f7f7')
        self.log_txt.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 6))

        self.status = tk.Label(self.root, text='Ready — isolated sim network: 172.16.238.0/24 (tripwire ON)',
                               anchor='w', relief=tk.SUNKEN)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

        self._show_desc()

    def _tree(self, parent, columns, stretch=()):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        vsb = ttk.Scrollbar(frame, orient=tk.VERTICAL)
        hsb = ttk.Scrollbar(frame, orient=tk.HORIZONTAL)
        tree = ttk.Treeview(frame, columns=columns, show='headings', yscrollcommand=vsb.set,
                            xscrollcommand=hsb.set)
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        for i, c in enumerate(columns):
            w = 90
            if i in stretch:
                w = 220
            tree.heading(c, text=c)
            tree.column(c, width=w, minwidth=50)
        return tree

    def _show_desc(self):
        scen = SCENARIOS.get(self.scen_var.get(), {})
        self.desc_var.set(f"{scen.get('title', '')} — {scen.get('describe', '')}")

    def _defenses(self):
        return {
            'random_id': self.def_vars['random_id'].get(),
            'random_port': self.def_vars['random_port'].get(),
            'use_0x20': self.def_vars['use_0x20'].get(),
            'bailiwick_check': self.def_vars['bailiwick_check'].get(),
            'ttl_floor': int(self.floor_var.get() or 0),
        }

    # ---- run control -----------------------------------------------------
    def _run(self):
        if self.running:
            return
        try:
            seed = int(self.seed_var.get())
            trials = max(1, int(self.trials_var.get()))
        except ValueError:
            messagebox.showerror('Input', 'Seed and Trials must be integers.')
            return
        scenario = self.scen_var.get()
        defenses = self._defenses()
        self.stop_event.clear()
        self.running = True
        self.run_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self._log(f'>>> scenario={scenario} seed={seed} trials={trials} defenses={defenses}')
        self.worker = threading.Thread(target=self._run_worker, args=(scenario, seed, trials, defenses),
                                       daemon=True)
        self.worker.start()

    def _run_worker(self, scenario, seed, trials, defenses):
        try:
            for i in range(trials):
                if self.stop_event.is_set():
                    self.queue.put(('status', 'stopped by user'))
                    break
                label = f'{scenario} #{i + 1} (seed {seed + i})' if trials > 1 else scenario
                self.queue.put(('status', f'running {label} ...'))
                res = lab.run_trial(scenario, seed + i, overrides=defenses,
                                    stop_event=self.stop_event)
                if res.get('tripwire'):
                    res['verdict'] = 'TRIPWIRE!'
                self.queue.put(('result', res))
            self.queue.put(('done', None))
        except Exception as exc:
            import traceback
            self.queue.put(('error', f'{type(exc).__name__}: {exc}\n{traceback.format_exc()}'))

    def _stop(self):
        self.stop_event.set()
        self._log('stop requested')

    def _poll(self):
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == 'result':
                    self._on_result(payload)
                elif kind == 'status':
                    self.status.config(text=str(payload))
                    self._log(str(payload))
                elif kind == 'log':
                    self._log(str(payload))
                elif kind == 'done':
                    self.status.config(text='Finished.')
                    self.running = False
                    self.run_btn.config(state='normal')
                    self.stop_btn.config(state='disabled')
                elif kind == 'error':
                    self._log(payload)
                    self.status.config(text='Error — see log.')
                    self.running = False
                    self.run_btn.config(state='normal')
                    self.stop_btn.config(state='disabled')
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _on_result(self, res):
        self.last_result = res
        if res.get('comparison'):
            for idx, row in enumerate(res['comparison'], 1):
                note = f"P={row['race'].get('prob', 0):.4f} attempts={row['race'].get('attempts', 0)} | {row['describe'][:40]}"
                self.res_tree.insert('', 'end',
                                     values=('C' + str(idx), row['scenario'], row['seed'],
                                             row['verdict'].upper(), row['victim'],
                                             ','.join(row['got']) or '—',
                                             row.get('expected', '—'), row['labels_tried'] or '—',
                                             f"{row['race'].get('prob', 0):.4f}", note),
                                     tags=(row['verdict'],))
            self.race_txt.config(state='normal')
            self.race_txt.delete('1.0', tk.END)
            self.race_txt.insert('1.0', '\n'.join(
                f"{c['combo']}: P={c['race']['prob']:.6f} -> {c['verdict']}" for c in res['comparison']))
            self.race_txt.config(state='disabled')
            self._log('defense comparison finished')
            return
        verdict = res.get('verdict', '?')
        got = ','.join(res.get('got', [])) or '—'
        note = f"P={res['race'].get('prob', 0):.4f} labels={res.get('labels_tried', '—')} hit={res.get('deleg_hit', '—')}"
        self.res_tree.insert('', 'end',
                             values=(0, res['scenario'], res['seed'], verdict.upper(),
                                     res['victim'], got, res.get('expected', '—'),
                                     res.get('labels_tried', '—'),
                                     f"{res['race'].get('prob', 0):.4f}", note),
                             tags=(verdict,))
        self._render_cache(res)
        self._render_timeline(res)
        self.race_txt.config(state='normal')
        self.race_txt.delete('1.0', tk.END)
        self.race_txt.insert('1.0', self._race_info(res))
        self.race_txt.config(state='disabled')
        self._log(f"verdict={verdict} got={got} forged={len(res.get('forged', []))} "
                  f"tripwire={res.get('tripwire', 0)} packets={res.get('packets_total', 0)}")

    def _race_info(self, res):
        lines = [
            f"attacker mode : {res.get('mode')}",
            f"race win      : {res['race'].get('win')}  p={res['race'].get('prob', 0):.6f}",
            f"entropy bits  : {res['race'].get('entropy_bits', 0)}  attempts={res['race'].get('attempts', 0)}",
        ]
        if res.get('deleg_hit'):
            lines.append(f"delegation poisoned at: {res['deleg_hit']}")
        return '\n'.join(lines) + '\n'

    def _render_cache(self, res):
        self.cache_tree.delete(*self.cache_tree.get_children())
        for row in res.get('cache', []):
            self.cache_tree.insert('', 'end',
                                   values=(row['name'], row['qtype'], ','.join(row['rdata']) or '—',
                                           row['kind'], row['ttl'], row['deadline'],
                                           row['from_addr'], 'yes' if row.get('forged') else ''),
                                   tags=('forged' if row.get('forged') else row['kind'],))

    def _render_timeline(self, res):
        self.tl_tree.delete(*self.tl_tree.get_children())
        for seq, t, src, dst, summ in res.get('timeline', []):
            self.tl_tree.insert('', 'end', values=(seq, t, src, dst, summ),
                                tags=('malformed' if summ == 'MALFORMED' else ''))

    def _flush_cache(self):
        self.cache_tree.delete(*self.cache_tree.get_children())
        self._log('cache view flushed')

    def _log(self, text):
        self.log_txt.config(state='normal')
        self.log_txt.insert(tk.END, text + '\n')
        self.log_txt.see(tk.END)
        self.log_txt.config(state='disabled')