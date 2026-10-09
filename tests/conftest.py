import os

# Keep tests deterministic: never fetch the Tor Project's live exit list.
os.environ.setdefault("ALIBI_OFFLINE", "1")
# The keyed endpoints need a server-side key; tests use a throwaway one.
os.environ.setdefault("ALIBI_API_KEY", "test-only-key")
