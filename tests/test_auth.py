from drf_gnap.authentication import GNAPAuthentication

def test_auth_class():
    auth = GNAPAuthentication()
    assert auth is not None