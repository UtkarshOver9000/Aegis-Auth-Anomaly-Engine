"""
Request and response models.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class LoginEvent(BaseModel):
    user_id: str = Field(..., json_schema_extra={"example": "usr_1001"})
    login_ts: str = Field(..., description="ISO-8601 timestamp", json_schema_extra={"example": "2026-08-02T15:30:00Z"})
    ip: str = Field(..., json_schema_extra={"example": "198.51.100.45"})
    device_id: str = Field(..., description="Device fingerprint", json_schema_extra={"example": "dev-macbook-pro"})
    country: str | None = Field(
        None, description="ISO country code from IP geolocation", json_schema_extra={"example": "NO"}
    )
    city: str | None = Field(None, json_schema_extra={"example": "Oslo"})
    asn: int | None = Field(
        None, description="Autonomous system number of the IP", json_schema_extra={"example": 29695}
    )
    lat: float | None = Field(None, description="Latitude, enables the impossible-travel check")
    lon: float | None = Field(None, description="Longitude, enables the impossible-travel check")
    user_agent: str | None = Field(None, description="Full user-agent string (defaults to device_id)")
    browser: str | None = Field(None, json_schema_extra={"example": "Chrome 120.0"})
    os: str | None = Field(None, json_schema_extra={"example": "Windows 10"})
    device_type: str | None = Field(None, json_schema_extra={"example": "desktop"})
    rtt_ms: float | None = Field(None, ge=0, description="Server-measured round-trip time")
    success: bool = Field(True, description="Whether the password check succeeded")


class EvaluationResult(BaseModel):
    user_id: str
    is_anomaly: bool
    risk_score: float = Field(..., description="Percentile (0-100) of real validation logins this login out-scores")
    risk_tier: str = Field(..., description="LOW, MEDIUM, HIGH or CRITICAL")
    recommended_action: str
    ato_probability: float
    attack_ip_probability: float
    ato_percentile: float
    attack_ip_percentile: float
    reasons: list[str]
    network: dict = Field(default_factory=dict, description="Who owns the IP: network, country, Tor / hosting flags")
    features: dict
    velocity_kmph: float
    distance_km: float
    time_delta_hours: float
    previous_location: dict | None = None
    current_location: dict
    timestamp: str


class DemoStory(BaseModel):
    events: list[LoginEvent] = Field(
        ...,
        min_length=1,
        max_length=30,
        description="The account's usual sign-ins, oldest first; the last one is scored",
    )


class APIKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=80)


class APIKeyResponse(BaseModel):
    name: str
    api_key: str
    created_at: str
