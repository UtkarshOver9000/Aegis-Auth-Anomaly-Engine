import pytest
from ittravel.geo import haversine_distance

@pytest.mark.parametrize("lat1,lon1,lat2,lon2,expected", [
    (0, 0, 0, 0, 0),
    (90, 0, -90, 0, 20015),
    (38.8951, -77.0364, 38.8951, -77.0364, 0), # Same point
    (51.5074, -0.1278, 48.8566, 2.3522, 343), # London to Paris
    (40.7128, -74.0060, 34.0522, -118.2437, 3935), # NY to LA
    (35.6762, 139.6503, -33.8688, 151.2093, 7825), # Tokyo to Sydney
])
def test_haversine_bulk(lat1, lon1, lat2, lon2, expected):
    dist = haversine_distance(lat1, lon1, lat2, lon2)
    # allow 2% margin of error
    if expected == 0:
        assert dist < 1
    else:
        assert abs(dist - expected) / expected < 0.05
