"""TTPProfiler :: smoke/CI test — imports demo set, builds profile, exports artifacts."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.security import AuditChain  # noqa: E402
from app.services import Importer, ProfilerEngine  # noqa: E402
from app.store import SecureStore  # noqa: E402


def main() -> int:
    demo = ROOT / "samples_demo"
    assert demo.is_dir(), f"missing {demo}"

    with tempfile.TemporaryDirectory() as tmp:
        store = SecureStore(tmp, encrypt_evidence=True if sys.platform.startswith("win") else False)
        audit = AuditChain(store)

        imp = Importer(store, audit, namespace="test")
        res = imp.ingest_directory(demo, "test-set", "CI Sample Set")
        assert len(res.samples) == 3, f"expected 3 samples, got {len(res.samples)}"
        print(f"[1/5] imported {len(res.samples)} samples, errors={res.errors}")

        engine = ProfilerEngine(store, audit)
        profile = engine.build_profile("test-set", namespace="test")
        assert profile is not None
        assert len(profile.techniques) >= 8, f"low technique count: {len(profile.techniques)}"
        assert profile.actor_ranking, "no actor attribution"
        print(f"[2/5] techniques={len(profile.techniques)} tactics={len(profile.tactic_scores)} "
              f"conf={profile.confidence} grade={profile.intel_grade}")
        print(f"[3/5] top actor: {profile.top_actor.name} ({profile.top_actor.confidence}%)")

        from app import reports as R
        out = Path(tmp) / "reports"
        manifest = R.write_all(profile, out, "CI Sample Set", res.samples)
        for name, meta in manifest["files"].items():
            blob = (out / name).read_bytes()
            import hashlib
            if hashlib.sha256(blob).hexdigest() != meta["sha256"]:
                raise AssertionError(f"manifest hash mismatch: {name}")
        print(f"[4/5] exported {len(manifest['files'])} artifacts, hashes verified")

        nav = R.render_navigator_layer(profile)
        assert nav["techniques"]
        bundle = R.render_stix_bundle(profile)
        assert any(o["type"] == "threat-actor" for o in bundle["objects"])

        loaded = store.load_profiles("test-set")
        assert loaded
        print(f"[5/5] persisted profiles in DB: {len(loaded)}")

        store.close()
    print("SMOKE TEST PASSED [OK]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())