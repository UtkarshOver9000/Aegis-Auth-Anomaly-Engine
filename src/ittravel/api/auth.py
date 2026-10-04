"""
API-key checks. Evaluation endpoints accept the master key or any issued key;
issuing new keys requires the master key.
"""

from __future__ import annotations

from fastapi import HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader

from ..state import store

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _require(api_key: str | None) -> str:
    if not api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API Key header 'X-API-Key'")
    return api_key


async def verify_api_key(api_key: str | None = Security(api_key_header)) -> str:
    key = _require(api_key)
    if not store.is_valid_api_key(key):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or revoked API Key")
    return key


async def verify_master_key(api_key: str | None = Security(api_key_header)) -> str:
    key = _require(api_key)
    if not store.is_master_key(key):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Issuing keys requires the master key")
    return key
