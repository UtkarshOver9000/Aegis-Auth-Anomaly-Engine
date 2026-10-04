import os

# Keep tests deterministic: never fetch the Tor Project's live exit list.
os.environ.setdefault("ALIBI_OFFLINE", "1")
