# Grant Proposal: `drf-gnap`

## Project title

`drf-gnap`: Django REST Framework-native GNAP and HTTP Message Signatures toolkit for Open Payments

## Funding theme

Primary fit:

- Software libraries for RFC 9421 HTTP Message Signatures in Python

Secondary fit:

- Support for GNAP in SDK and developer tooling workflows for Python
- Improved developer experience for Open Payments integrations

## Executive summary

`drf-gnap` is an open source Python package that makes GNAP and HTTP Message Signatures practical for Django and Django REST Framework developers building with Open Payments.

Today, Open Payments integration requires developers to understand low-level security details, manually wire authorization flows, and build custom signing logic around every request. This slows adoption and raises the barrier for teams that could otherwise build valuable products on the protocol.

`drf-gnap` solves that problem by providing a Django-native package that packages these concerns into installable, reusable components:

- DRF authentication for GNAP-style protected APIs
- a reusable GNAP client for grant negotiation and lifecycle management
- HTTP Message Signatures helpers aligned with RFC 9421
- middleware and examples that reduce integration effort

The goal is simple: make Python and Django one of the fastest ways to build secure Open Payments applications.

## Problem statement

There is a significant developer experience gap in Open Payments:

- GNAP is still new to many application developers
- HTTP Message Signatures are security-critical but difficult to implement correctly
- Django and DRF teams lack a polished, reusable package for these flows
- many teams must duplicate protocol logic before they can even validate an idea

This creates friction precisely where the ecosystem needs leverage: onboarding developers quickly and safely.

## Proposed solution

Build and harden `drf-gnap` into a production-quality Python package for GNAP-enabled Django APIs and Open Payments integrations.

The package will provide:

1. A Django REST Framework authentication backend for GNAP-based protected resources
2. A reusable GNAP client for grant request, continuation, token rotation, and revocation
3. RFC 9421 HTTP Message Signatures support for signing and verifying requests
4. Middleware and configuration utilities that reduce boilerplate for Django teams
5. Demo apps, examples, and documentation showing real Open Payments flows

## Why this project matters

This project matters because it turns protocol complexity into developer productivity.

Instead of asking every Python team to become protocol experts, `drf-gnap` offers a standard integration path. That has three ecosystem benefits:

- faster experimentation by startups and integrators
- more consistent security implementations
- stronger Python support in the Open Payments ecosystem

## Current progress

The project is already beyond the idea stage. The current repository includes:

- a packaged `drf_gnap` module
- DRF authentication scaffolding
- GNAP client flow primitives
- HTTP signing and digest helpers
- middleware support
- a demo Django application
- a starter automated test suite

This means grant funding accelerates an existing implementation rather than starting from zero.

## Technical scope

The funded work will focus on hardening, interoperability, and developer experience.

### Workstream 1: GNAP support for Python developers

- strengthen request and continuation handling for RFC 9635 flows
- improve token management and validation paths
- support clearer client and resource server usage modes
- document how Django services participate in GNAP-based architectures

### Workstream 2: HTTP Message Signatures support

- complete request signing and verification flows aligned with RFC 9421
- add robust handling for supported signature algorithms
- improve signature component handling and validation
- provide examples for signed Open Payments requests

### Workstream 3: Django and DRF integration quality

- simplify setup through clear settings and install docs
- improve middleware and authentication ergonomics
- publish sample DRF views and integration recipes
- improve testing for real-world Django usage patterns

### Workstream 4: Open Payments interoperability

- test the package against Open Payments-style request flows
- add end-to-end examples for payment-related API interactions
- align examples with ecosystem expectations and implementer needs

## Deliverables

At the end of the grant period, the project will deliver:

1. An open source Python package published for installation and reuse
2. Stable GNAP client utilities for Python applications
3. RFC 9421 HTTP Message Signatures library support for Django and DRF use cases
4. A polished README, setup guide, and example flows
5. Demo application(s) showing secure API access patterns
6. Automated tests covering the main security and integration paths
7. Public documentation explaining how to integrate with Open Payments workflows

## Expected impact

The expected impact is high relative to project size because Django and DRF are widely used for API products.

By making Open Payments integration easier in Python, this project can help:

- backend teams prototype faster
- founders validate Open Payments use cases more quickly
- integrators adopt shared security patterns instead of reinventing them
- the Interledger ecosystem reach a broader developer audience

## Why I am a strong fit

I am a strong fit to execute this project because the work aligns directly with my existing strengths:

- Python
- Django
- Django REST Framework
- PostgreSQL-backed API systems
- API testing and workflow design
- AI-assisted developer tooling and documentation workflows

Most importantly, the project is already in progress. I am not proposing a speculative direction outside my stack; I am extending something I can build and ship efficiently.

## Milestones

### Milestone 1: package hardening

- clean up package structure and public API
- improve configuration validation
- document supported flows and current limitations
- expand tests around core auth and signing behavior

### Milestone 2: protocol coverage

- improve GNAP lifecycle handling
- strengthen token and continuation paths
- add more complete RFC 9421 verification behavior
- validate signed request patterns in realistic examples

### Milestone 3: interoperability and demos

- connect examples to Open Payments-style flows
- publish a demo walkthrough for reviewers and developers
- add sample requests for curl and Postman
- improve error messages and developer guidance

### Milestone 4: release readiness

- finalize docs
- tighten tests
- prepare release artifacts
- collect implementer feedback and refine the package

## Success criteria

The project will be successful if, by the end of the grant:

- a Django developer can install the package and protect a DRF endpoint quickly
- a Python client can request and use GNAP grants with far less custom code
- signed request flows are easier to implement correctly
- Open Payments developers have a credible Python starting point instead of building from scratch

## Budget framing

This proposal is well aligned to the Python HTTP Message Signatures grant theme and can also contribute meaningfully to GNAP tooling for Python developers.

A practical funding framing is:

- submit primarily under the Python RFC 9421 HTTP Message Signatures library track
- position `drf-gnap` as a high-leverage implementation that also improves GNAP developer experience
- emphasize that grant support will harden an existing working alpha into a reusable ecosystem asset

## Open source commitment

`drf-gnap` will be developed openly, with public source code, documentation, and examples so that the broader ecosystem can benefit.

## Closing statement

Open Payments needs developer tooling that meets builders where they already are.

For Python and Django teams, that means a package that makes GNAP and HTTP Message Signatures usable without weeks of protocol plumbing. `drf-gnap` is a practical, ecosystem-aligned solution with working foundations already in place and a clear path to high-impact grant-funded delivery.
