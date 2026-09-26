import os
import sys
import tempfile

os.environ["SECURENOTE_HOME"] = tempfile.mkdtemp(prefix="sn_test_")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from secure_note.app import SecureNoteApp  # noqa: E402

app = SecureNoteApp()
print("data_dir:", app.data_dir)
assert not app.vault.exists, "vault should not exist yet"

# --- setup ------------------------------------------------------------------
r = app.setup("correct horse battery staple", enable_biometric=False)
assert r["ok"], r
assert app.vault.exists
assert app.unlocked
print("setup OK")

# wrong passphrase must fail and trigger exponential-backoff lockout
import time
r = app.unlock(passphrase="bad passphrase")
assert not r["ok"]
r = app.unlock(passphrase="bad passphrase again")
assert not r["ok"] and r.get("locked"), r
assert 0 < app.lockout_remaining()
print(f"wrong pass rejected; lockout active ({app.lockout_remaining()}s) OK")
time.sleep(6)  # let the first-stage backoff elapse

# lock / unlock with correct passphrase
app.lock()
assert not app.unlocked
r = app.unlock(passphrase="correct horse battery staple")
assert r["ok"], r
print("unlock OK")

# --- notes -------------------------------------------------------------------
r = app.add_note("Meeting notes", "Discuss Q3 roadmap and budget.\nVery secret line.", "work,internal")
assert r["ok"]
nid = r["id"]
r = app.add_note("Shopping", "Milk, eggs, bread", "home")
assert r["ok"]
nid2 = r["id"]
lst = app.note_list()
assert len(lst) == 2, lst
app.update_note(nid, "Meeting notes (updated)", "Discuss Q3 roadmap.\nSecret updated line.", "work")
assert app.get_note(nid)["title"] == "Meeting notes (updated)"
assert app.get_note(nid2)["title"] == "Shopping"
app.delete_note(nid2)
assert len(app.note_list()) == 1
print("note CRUD OK")

# --- audit ---------------------------------------------------------------------
v = app.audit_verify()
assert v["ok"], v
assert v["count"] >= 5, v
print("audit chain verified:", v["count"], "events")

# --- reports --------------------------------------------------------------------
res = app.generate_reports(dest_dir=os.path.join(app.data_dir, "reports"))
assert res["ok"], res
for k in ("json", "csv", "zip"):
    assert os.path.exists(res["artifacts"][k]), k
print("reports OK:", sorted(os.path.basename(p) for p in res["artifacts"].values() if p))

# --- change passphrase ------------------------------------------------------------
r = app.change_passphrase("correct horse battery staple", "new passphrase 2026 trustworthy")
assert r["ok"]
app.lock()
r = app.unlock(passphrase="new passphrase 2026 trustworthy")
assert r["ok"]
assert app.vault.notes[0]["id"] == nid
print("passphrase rotation + re-unlock OK")

# --- re-verify chain after more ops -----------------------------------------------
v = app.audit_verify()
assert v["ok"]
print("audit still verified")

# --- autolock setting ---------------------------------------------------------------
app.set_autolock(30)
assert app.vault.settings["autolock_seconds"] == 30
app.lock()

# --- wipe ----------------------------------------------------------------------------
r = app.wipe()
assert r["ok"]
assert not app.vault.exists
print("wipe OK: all local key material deleted")

print("\nALL SMOKE TESTS PASSED")