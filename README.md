# ProShield — Rule-Based Security Operations & Blue-Team Learning Platform

**A local-first cybersecurity project focused on deterministic detection, event correlation, evidence-backed investigations, and practical security learning.**

ProShield is a rule-based Security Operations (SOC) platform I am building to understand and automate the repetitive first stages of security investigation. Instead of leaving analysts with disconnected security alerts, it is designed to process events, apply relevant detection rules, correlate related detections, organize investigation evidence, and prepare cases for human review.

The project is currently in **active development and testing**. My priority is to establish a stable, trustworthy security product before considering a wider release or practical cybersecurity labs for students.

## Why I built ProShield

Security events are often fragmented across systems. Investigating them requires understanding the original telemetry, identifying relevant detection rules, determining whether events are related, examining evidence, and deciding what to investigate next.

I built ProShield to explore how a deterministic, explainable pipeline can reduce this initial manual workload while keeping security decisions grounded in evidence.

The project also serves as my practical cybersecurity learning environment, allowing me to study detection engineering, event ingestion, source trust, correlation, false-positive analysis, incident investigation, and security-system integration through implementation and testing rather than theory alone.

## How it works

```text
External Security Source / Test Connector
                  |
                  v
        Source Identity & Trust
                  |
                  v
           Secure Ingestion
                  |
                  v
     Validation & Normalization
                  |
                  v
      Capability-Owned Rules
                  |
                  v
             Detection
                  |
                  v
            Correlation
                  |
                  v
       Investigation Case
                  |
                  v
       Timeline & Evidence
                  |
                  v
        Analyst Review
                  |
                  v
        Reports / Export
```

ProShield separates event ingestion, detection, correlation, and case investigation into distinct stages. This makes it easier to test where an event originated, which rule evaluated it, why a detection was generated, and which evidence supports a resulting investigation.

## Key capabilities

- **Security-event ingestion:** Receives events through a dedicated ingress boundary and validates them against the event model.
- **Source trust and identity:** Uses authenticated source identity and server-derived provenance to help prevent untrusted event data from claiming another source's identity.
- **Deterministic detection:** Applies explicit, testable rules instead of relying on an AI model to decide whether an event is malicious.
- **Capability-owned rules:** Associates detection rules with the relevant security capability and source context.
- **Event correlation:** Groups related detections according to defined correlation logic rather than treating every alert as an independent incident.
- **Investigation workflow:** Organizes cases, related evidence, timelines, and investigation context for analyst review.
- **Security administration:** Includes authentication, role-based permissions, source lifecycle management, rule management, system-health visibility, and audit-related workflows.
- **Local deployment and verification:** Includes a local backend, web interface, database integration, automated tests, verification scripts, and Windows deployment tooling.

## Technology stack

| Layer | Technologies |
|---|---|
| Backend and security logic | Python |
| HTTP application and API boundary | FastAPI / Uvicorn |
| Data validation | Pydantic |
| Persistence | MongoDB |
| Frontend | React, TypeScript, Vite, Tailwind CSS |
| Testing and verification | pytest, integration tests, Playwright-based browser checks |
| Local Windows deployment | Python service/runtime, desktop shell, installer and update tooling |

## Current implementation and scope

ProShield is a **rule-based MVP, not an AI-driven security product**. Its current functionality is deliberately narrower than the long-term vision.

The repository includes NGINX and simulated event connectors, with an initial NGINX-focused detection-rule library. The architecture is intended to accommodate additional integrations, but source types displayed or defined in the system should not be interpreted as fully implemented connectors.

ProShield is not a replacement for a SIEM, EDR, firewall, WAF, or a complete enterprise security platform. It does not automatically detect every possible attack, and an event that does not match an enabled rule is not thereby proven benign.

My focus is on validating the actual end-to-end behavior, including source attribution, detection correctness, correlation, evidence integrity, failure handling, and analyst workflows.

## Running ProShield locally

ProShield is designed for local, self-hosted development and testing. The documented Windows deployment architecture uses a desktop application, a background service, separate analyst and ingestion planes, and a local MongoDB instance.

**Development prerequisites**

- Windows with Python 3.13.
- MongoDB available locally at `127.0.0.1:27017`.
- Node.js and npm when rebuilding the frontend.
- The project's required environment configuration and dependencies.

For the development workflow, the analyst plane is served on `127.0.0.1:8088` and the ingestion plane on `127.0.0.1:8089`. The frontend communicates through the application boundary; it does not access MongoDB directly.

See [`docs/WINDOWS_DEPLOYMENT.md`](docs/WINDOWS_DEPLOYMENT.md) for the Windows build, installation, service, configuration, and verification procedures. Use development credentials and configuration only in an isolated local environment. Never expose the development setup directly to the internet.

## How I am testing and improving it

My approach is to verify behavior across the entire security pipeline rather than treating a passing unit test or a working dashboard as sufficient proof.

Testing includes rule behavior, positive and negative scenarios, source identity, authentication and permissions, persistence, correlation, case creation, timeline evidence, restart behavior, frontend/backend integration, and controlled security tests.

The repository also contains test and verification scripts intended to make results reproducible and to identify defects before they reach a more stable release.

## Roadmap

1. **Stabilize the product:** Continue correcting verified defects, strengthening regression coverage, and validating the complete local workflow.
2. **Improve detection quality:** Expand justified rule coverage, test legitimate activity against suspicious behavior, and investigate false positives and missed detections.
3. **Extend integrations carefully:** Add and validate further security-source connectors instead of assuming that defining a source type makes an integration operational.
4. **Improve practical learning:** Develop controlled cybersecurity scenarios and better documentation so the project can potentially serve as a practical learning lab for cybersecurity students.
5. **Evaluate future enhancements:** Consider additional investigation and automation capabilities only after the deterministic foundation is sufficiently validated.

## What I am learning through this project

ProShield is helping me develop practical experience with security-event processing, detection engineering, source trust, correlation logic, SOC investigation workflows, backend architecture, authentication and authorization, persistence, integration testing, and local deployment.

The objective is to build a stable and explainable security product first, measure its limitations honestly, and expand its capabilities based on evidence.

---

**Project:** [ProShield on GitHub](https://github.com/kallurivishalreddy/proshield-production-)

**Development status:** Active development · Local testing · Not yet presented as production-ready

