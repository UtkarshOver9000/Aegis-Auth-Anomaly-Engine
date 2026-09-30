import pytest
import numpy as np
from ittravel.geo import haversine_km

@pytest.mark.parametrize("lat1,lon1,lat2,lon2,expected", [
    (0, 0, 0, 0, 0),
    (90, 0, -90, 0, 20015),
    (38.8951, -77.0364, 38.8951, -77.0364, 0),
    (51.5074, -0.1278, 48.8566, 2.3522, 343),
    (40.7128, -74.0060, 34.0522, -118.2437, 3935),
    (35.6762, 139.6503, -33.8688, 151.2093, 7825),
])
def test_haversine_bulk(lat1, lon1, lat2, lon2, expected):
    dist = haversine_km(np.array([lat1]), np.array([lon1]), np.array([lat2]), np.array([lon2]))[0]
    if expected == 0:
        assert dist < 1
    else:
        assert abs(dist - expected) / expected < 0.05
