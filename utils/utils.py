# Shared helpers for MnemoCetus (v0.7.x polish) -> the small utilities several modules were each defining their own copy of.
#
#   open_db                 -> open a Database and always close it (a `with` context manager)
#   human_size              -> byte count to a readable string
#   confidence_band /       -> which recognition-confidence band a 0-1 score falls in, and a fresh
#   empty_confidence_counts    {band: 0} tally, so every caller buckets confidence identically
#
# This is the one home for these -> scanner / report / web all import them from here rather than
# repeating them. db_manager is imported lazily inside open_db so importing this module stays cheap
# (the scan engine can pull human_size without dragging in the database layer).

from contextlib import contextmanager


@contextmanager
def open_db(db_path):
    """Open a Database and guarantee it is closed afterwards -> `with open_db(path) as db: ...`."""
    from db_tools import manager as db_manager  # lazy: keeps `import utils` free of the DB layer for callers that only want human_size
    db = db_manager.Database(db_path)
    try:
        yield db
    finally:
        db.close()


def human_size(num_bytes):
    """Turn a byte count into something readable (e.g. 1536 -> '1.5 KB')."""
    size = float(num_bytes or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


# The confidence bands the recogniser's 0-1 score falls into.
# One shared definition -> the dashboard tally and the exported report label the bands identically.
CONFIDENCE_BANDS = ("low (<0.6)", "medium (0.6-0.85)", "high (>0.85)")


def confidence_band(score):
    """Which confidence band a 0-1 score lands in (None -> treated as 0 -> 'low')."""
    c = score or 0
    if c < 0.6:
        return CONFIDENCE_BANDS[0]
    if c <= 0.85:
        return CONFIDENCE_BANDS[1]
    return CONFIDENCE_BANDS[2]


def empty_confidence_counts():
    """A fresh {band: 0} tally, ready to fill in."""
    return {band: 0 for band in CONFIDENCE_BANDS}
