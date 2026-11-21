"""Lightweight ProScan-class helpers for LinScan-536."""
from __future__ import annotations
from pathlib import Path
import sqlite3

class CallStore:
    def __init__(self, db_path: Path):
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS calls ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, t_short TEXT,"
            "sys TEXT, dept TEXT, chan TEXT, fm TEXT, tgid TEXT,"
            "uid TEXT, dur REAL, clip TEXT, tag TEXT)")
        self.conn.commit()
    def add_call(self, row: tuple, keep: int = 2500):
        self.conn.execute(
            "INSERT INTO calls (ts,t_short,sys,dept,chan,fm,tgid,"
            "uid,dur,clip,tag) VALUES (?,?,?,?,?,?,?,?,?,?,?)", row)
        self.conn.execute(
            "DELETE FROM calls WHERE id NOT IN "
            "(SELECT id FROM calls ORDER BY id DESC LIMIT ?)", (keep,))
        self.conn.commit()
    def recent(self, limit: int = 500) -> list[tuple]:
        q = ("SELECT ts,t_short,sys,dept,chan,fm,tgid,uid,dur,clip,tag "
             "FROM (SELECT * FROM calls ORDER BY id DESC LIMIT ?) ORDER BY id ASC")
        return self.conn.execute(q, (limit,)).fetchall()
    def clear(self):
        self.conn.execute("DELETE FROM calls"); self.conn.commit()
    def close(self):
        try: self.conn.close()
        except Exception: pass
    def add_call(self, row: tuple, keep: int = 2500):
        self.conn.execute(
            "INSERT INTO calls (ts,t_short,sys,dept,chan,fm,tgid,"
            "uid,dur,clip,tag) VALUES (?,?,?,?,?,?,?,?,?,?,?)", row)
        self.conn.execute(
            "DELETE FROM calls WHERE id NOT IN "
            "(SELECT id FROM calls ORDER BY id DESC LIMIT ?)", (keep,))
        self.conn.commit()
    def recent(self, limit: int = 500) -> list[tuple]:
        q = ("SELECT ts,t_short,sys,dept,chan,fm,tgid,uid,dur,clip,tag "
             "FROM (SELECT * FROM calls ORDER BY id DESC LIMIT ?) ORDER BY id ASC")
        return self.conn.execute(q, (limit,)).fetchall()
    def clear(self):
        self.conn.execute("DELETE FROM calls"); self.conn.commit()
    def close(self):
        try: self.conn.close()
        except Exception: pass

def _skey(val: str):
    s = str(val).strip()
    if s.isdigit(): return (0, float(s), "")
    if ":" in s and all(p.isdigit() for p in s.split(":")):
        sec = sum(int(p)*(60**i) for i,p in enumerate(reversed(s.split(":"))))
        return (0, float(sec), "")
    return (1, 0.0, s.lower())

def attach_sorting(tree):
    st = {}
    for col in tree["columns"]:
        def _sort(c=col):
            rev = not st.get(c, False); st[c] = rev
            rows = [(tree.set(k, c), k) for k in tree.get_children("")]
            rows.sort(key=lambda x: _skey(x[0]), reverse=rev)
            for i, (_, k) in enumerate(rows): tree.move(k, "", i)
        tree.heading(col, command=_sort)

def sync_uid_trees(app, uid_key: str):
    disp = app.format_uid_display(uid_key)
    for t in (app.log_tree, app.hist_tree):
        ids = list(t.get_children("")) + list(app._hidden.get(t, []))
        for iid in ids:
            if not t.exists(iid): continue
            v = list(t.item(iid, "values"))
            if len(v) > 6 and (v[6] == uid_key or v[6].endswith(f"({uid_key})")):
                v[6] = disp; t.item(iid, values=v)

def apply_filter(tree, hidden: dict, query: str):
    q = query.strip().lower()
    for iid in list(hidden.get(tree, [])):
        if tree.exists(iid): tree.reattach(iid, "", "end")
    hidden[tree] = []
    if not q: return
    for iid in list(tree.get_children("")):
        if q not in " ".join(str(x) for x in tree.item(iid, "values")).lower():
            tree.detach(iid); hidden[tree].append(iid)

def restore_history(app):
    for i, r in enumerate(app.call_store.recent(500)):
        ts, tsh, sy, dp, ch, fm, tg, uid, dur, clp, tag = r
        k = tg if tg else (f"{dp}_{ch}" if dp else ch)
        app.call_times[k] = app.call_times.get(k, 0.0) + float(dur or 0)
        app.tg_hits[k] = app.tg_hits.get(k, 0) + 1
        m, s = divmod(int(app.call_times[k]), 60); h, m = divmod(m, 60)
        tt = f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"
        ud = app.format_uid_display(uid)
        rv = (tsh, sy, dp, ch, fm, tg, ud, app.tg_hits[k], tt)
        if app.log_tree.exists(k):
            app.log_tree.item(k, values=rv, tags=(tag,)); app.log_tree.move(k, "", 0)
        else: app.log_tree.insert("", 0, iid=k, values=rv, tags=(tag,))
        _restore_row(app, i, r, ud)

def _restore_row(app, i: int, r: tuple, ud: str):
    ts, tsh, sy, dp, ch, fm, tg, uid, dur, clp, tag = r
    cm, cs = divmod(max(1, int(round(dur or 1))), 60)
    hid = f"DB_{i}"
    cl = f"▶ {Path(clp).name}" if clp and Path(clp).exists() else ""
    hv = (ts, sy, dp, ch, fm, tg, ud, f"{cm:02d}:{cs:02d}", cl)
    app.hist_tree.insert("", 0, iid=hid, values=hv, tags=(tag,))
    if cl: app.history_clips[hid] = clp
    if uid:
        app.uid_hits[uid] = app.uid_hits.get(uid, 0) + 1
        uv = (uid, app.uid_aliases.get(uid, ""), f"{dp} - {ch}".strip(" -"), tsh, app.uid_hits[uid])
        if app.uid_tree.exists(uid):
            app.uid_tree.item(uid, values=uv, tags=(tag,)); app.uid_tree.move(uid, "", 0)
        else: app.uid_tree.insert("", 0, iid=uid, values=uv, tags=(tag,))
