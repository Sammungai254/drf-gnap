"""
drf-gnap: Production-ready GNAP (RFC 9635) authentication and
HTTP Message Signatures (RFC 9421) for Django REST Framework.

Designed for Open Payments and modern fintech API integrations.

Quick start:
    # settings.py
    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [
            "drf_gnap.authentication.GNAPAuthentication",
        ],
    }

    GNAP = {
        "AS_URL": "https://auth.example.com",
        "CLIENT_KEY": {...},   # JWK or path to PEM
    }
"""

__version__ = "0.1.0"
__author__ = "Samuel Mungai Owino"
__license__ = "MIT"

default_app_config = "drf_gnap.apps.DRFGNAPConfig"