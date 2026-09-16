# Scan auto-tuning for MnemoCetus (v0.8.x) -> find the worker count that scans fastest on THIS machine.
#
# The best ThreadPoolExecutor size for persist_scan depends on the machine (cores, disk speed, cache):
# too few threads underuse the disk, too many add GIL / dispatch overhead. Rather than guess a default,
# this builds a small throwaway workspace, times persist_scan across a handful of worker counts, and
# reports the winner. The caller persists it (settings.scan_workers) and passes it back to persist_scan.
#
# It's a heuristic on a synthetic proxy, not a perfect model of the user's real disk -> good enough to
# pick a machine-appropriate default, and re-runnable whenever the environment changes.

import os
import time
import tempfile
import shutil


def _build_probe(root, n_projects=60, files_per=40):
    """Lay down a synthetic workspace that exercises the same phases a real scan does (walk / classify / marks / secret scan)."""
    body = "import os\n\ndef handler():\n    return 1\n\n" + "value = 42\n" * 30
    secretish = 'AWS_KEY = "AKIA' + "A" * 16 + '"\n'      # trips the secret scan on some projects
    for i in range(n_projects):
        p = os.path.join(root, f"proj_{i:04d}")
        os.makedirs(p, exist_ok=True)
        with open(os.path.join(p, "requirements.txt"), "w") as f:
            f.write("flask\nrequests\n")
        with open(os.path.join(p, "app.py"), "w") as f:
            f.write(body + (secretish if i % 6 == 0 else ""))
        for j in range(files_per):
            with open(os.path.join(p, f"mod_{j}.py"), "w") as f:
                f.write(body)


def _candidates(cpu):
    """Worker counts worth trying, capped to something sensible for the core count."""
    cap = max(2, min(16, cpu * 2))
    return sorted({c for c in (1, 2, 4, 6, 8, 12, 16) if c <= cap} | {cap})


def autotune(candidates=None, security=True, repeats=2,
             probe_projects=60, probe_files=40, progress=None):
    """
    Time persist_scan across candidate worker counts on a throwaway workspace.

    Args:
        candidates (list[int]): worker counts to try (default: scaled to the CPU count).
        security (bool): include the secret scan (default True) -> that's where parallelism pays off.
        repeats (int): timed runs per candidate; the best (min) is kept.
        probe_projects / probe_files: size of the synthetic workspace.
        progress (callable): optional progress(done, total) callback, called after each timed run.

    Returns:
        (best_workers, results): results is [(workers, seconds), ...] sorted by worker count.
    """
    from scanner import persist_scan  # local import -> tuning is optional, keep it off the import path

    cpu = os.cpu_count() or 4
    cands = candidates if candidates else _candidates(cpu)
    total = len(cands) * repeats
    root = tempfile.mkdtemp(prefix="mc_tune_")
    times, done = {}, 0
    try:
        _build_probe(root, probe_projects, probe_files)
        # A warm-up scan primes the FS cache + the shared Scanner, so the first candidate isn't penalised.
        warm = os.path.join(root, "_warm.db")
        persist_scan(root, db_path=warm, security=security, workers=cands[0])
        _rm(warm)
        for w in cands:
            best = None
            for _ in range(repeats):
                dbp = os.path.join(root, f"_t{w}_{done}.db")
                start = time.perf_counter()
                persist_scan(root, db_path=dbp, security=security, workers=w)
                dt = time.perf_counter() - start
                _rm(dbp)
                best = dt if best is None else min(best, dt)
                done += 1
                if progress:
                    progress(done, total)
            times[w] = best
    finally:
        shutil.rmtree(root, ignore_errors=True)
    best_workers = min(times, key=times.get)
    return best_workers, sorted(times.items())


def _rm(path):
    try:
        os.remove(path)
    except OSError:
        pass
