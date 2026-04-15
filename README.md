# drf-gnap

`drf-gnap` is a Django REST Framework package for GNAP-style authorization and HTTP Message Signatures in Open Payments integrations.

It is designed to make Open Payments security feel native in Django:

- Add one DRF authentication class
- Negotiate GNAP grants from Python
- Attach or verify signed requests
- Reuse the same package in demos, sandboxes, and production APIs

This project is currently an alpha package with a working end-to-end foundation and a clear roadmap toward stronger RFC coverage and Open Payments interoperability.

## Why this project exists

Open Payments is powerful, but the developer experience is still too hard for many backend teams.

Django developers should not need to hand-roll:

- GNAP grant request logic
- token caching and renewal logic
- request signing utilities
- DRF authentication plumbing
- demo APIs just to prove their integration works

`drf-gnap` aims to become the package that removes that friction for Python teams.

## What it does today

The repository already includes:

- A reusable `drf_gnap` Python package
- A DRF authentication class for GNAP-style access handling
- A GNAP client for requesting, continuing, rotating, and revoking grants
- RFC 9421-oriented content digest and signature-base helpers
- Django middleware for `Content-Digest` verification and generation
- Open Payments helper scaffolding
- A demo Django app showing protected endpoints
- A test suite covering core package behavior

## What makes it valuable

This project sits at the intersection of multiple Interledger Foundation grant themes:

1. Python developer tooling for GNAP-enabled integrations
2. HTTP Message Signatures support for Open Payments security flows
3. Better developer experience for teams building on Open Payments

Instead of creating yet another narrow proof-of-concept, `drf-gnap` focuses on something practical: a package that Django and DRF teams can actually install, configure, and use in real APIs.

## Current architecture

### 1. DRF authentication

Use `GNAPAuthentication` as a drop-in DRF authentication class:

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "drf_gnap.authentication.GNAPAuthentication",
    ],
}
```

This allows protected DRF views to accept GNAP-style authorization inputs without writing custom auth glue for every project.

### 2. GNAP client

`GNAPClient` provides a Python interface for:

- initial grant requests
- grant continuation
- token rotation
- token revocation

Example:

```python
from drf_gnap.gnap_client import GNAPClient

client = GNAPClient()
grant = client.request_grant(
    access=[
        {
            "type": "incoming-payment",
            "actions": ["read", "create"],
        }
    ]
)

if grant.access_token:
    token = grant.access_token.value
```

### 3. HTTP Message Signatures utilities

The package includes helpers for:

- computing `Content-Digest`
- verifying `Content-Digest`
- constructing signature bases
- generating signature headers

This is the foundation needed for Open Payments-compatible signing flows.

### 4. Middleware support

`GNAPSignatureMiddleware` can automatically:

- verify inbound `Content-Digest` on mutating requests
- attach `Content-Digest` to responses

### 5. Demo app

A demo Django project is included under [`demo/`](/GNAP/drf-gnap/demo) to show a protected endpoint and make evaluation easy for reviewers.

## Installation

```bash
pip install drf-gnap
```

For local development:

```bash
pip install -e ".[dev]"
```

## Quick start

### 1. Add the app

```python
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "rest_framework",
    "drf_gnap",
]
```

### 2. Configure DRF

```python
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "drf_gnap.authentication.GNAPAuthentication",
    ],
}
```

### 3. Configure GNAP

```python
GNAP = {
    "AS_URL": "https://authorization-server.example/gnap",
    "CLIENT_KEY": {
        "kid": "my-key-1",
        "kty": "EC",
        "crv": "P-256",
    },
    "SIGNATURE_ALGORITHM": "ecdsa-p256-sha256",
    "SIGNATURE_COMPONENTS": [
        "@method",
        "@target-uri",
        "content-digest",
        "authorization",
    ],
    "SIGNATURE_MAX_AGE": 300,
    "TOKEN_CACHE_TTL": 3600,
    "AS_TIMEOUT": 10,
    "AUTO_CONTENT_DIGEST": True,
    "OPEN_PAYMENTS_RS_URL": "https://resource-server.example",
}
```

### 4. Protect a view

```python
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


class PaymentView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({
            "message": "GNAP auth success",
            "user": str(request.user),
            "auth": str(request.auth),
        })
```

## Demo walkthrough

### Run the demo server

```bash
cd demo
python manage.py runserver
```

### Test the public health endpoint

```bash
curl http://127.0.0.1:8000/health/
```

### Test the protected endpoint

Send a GNAP-style authorization header:

```bash
curl http://127.0.0.1:8000/payment/ \
  -H "Authorization: GNAP demo-token-12345"
```

Or use the included demo script:

```bash
python demo/test_signed.py
```

## Grant relevance

This package is a strong fit for the Interledger Foundation SDK grant program because it addresses a real adoption bottleneck:

- Python teams need reusable GNAP tooling
- Django and DRF are widely used for fintech and API products
- Open Payments security is still too low-level for many app developers
- a practical package can unlock much faster experimentation and integration

The long-term vision is to make Python one of the easiest languages for building Open Payments-enabled services.

## Roadmap

The current repository is a strong alpha. The next grant-funded milestones are:

### Phase 1: protocol hardening

- Expand GNAP flow coverage against real RFC 9635 scenarios
- strengthen token validation and introspection paths
- harden error handling and security defaults
- add compatibility testing against Open Payments servers

### Phase 2: RFC 9421 completeness

- complete full HTTP Message Signatures request verification flow
- add richer key handling and algorithm support coverage
- support stricter signature parameter validation
- publish interoperability examples for signed Open Payments requests

### Phase 3: developer experience

- improve package docs and API reference
- publish example Django and DRF integrations
- add Postman and curl examples
- ship production-ready setup guides for resource server and client roles

### Phase 4: ecosystem adoption

- test against Rafiki and related Open Payments tooling
- gather feedback from early adopters
- stabilize the public API
- prepare a `1.0` release

## Why this can win

This proposal is not just an idea. It is already moving:

- package structure exists
- demo app exists
- tests exist
- core security plumbing exists
- the implementation matches the grant's developer tooling focus

That makes the project lower-risk, faster to fund, and easier for reviewers to believe.

## Repository structure

- [`drf_gnap/authentication.py`](/GNAP/drf-gnap/drf_gnap/authentication.py) for DRF auth classes
- [`drf_gnap/gnap_client.py`](/GNAP/drf-gnap/drf_gnap/gnap_client.py) for GNAP client flows
- [`drf_gnap/signatures.py`](/GNAP/drf-gnap/drf_gnap/signatures.py) for signature helpers
- [`drf_gnap/middleware.py`](/GNAP/drf-gnap/drf_gnap/middleware.py) for digest middleware
- [`demo/config/views.py`](/GNAP/drf-gnap/demo/config/views.py) for demo endpoints
- [`tests/`](/GNAP/drf-gnap/tests) for test coverage

## Status

Current status: alpha, actively being prepared for grant-backed hardening and ecosystem adoption.

## License

MIT
