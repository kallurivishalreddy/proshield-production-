# PROSHIELD V3 — PHASE 5.0
# ARCHITECTURE, DOMAIN, DATA-LIFECYCLE & IMPLEMENTATION FREEZE

**Document ID:** `PHASE-05-00-V3-ARCHITECTURE-FREEZE`

**Phase:** Phase 5 / V3 / Phase 5.0

**Status:** Architecture Freeze / Implementation Baseline

**Implementation:** No product-code implementation in this phase

**Purpose:** Establish the authoritative high-level architecture and implementation contract that every subsequent V3 implementation phase must follow.

**Authority:** This document is the V3 architectural baseline for Phase 5.1 onward. Later phase documents may refine an implementation detail only when that refinement does not violate the architectural invariants in this document. Any proposed change to an invariant requires an explicit architecture review and a new version of this document.

---

## 1. EXECUTIVE DECISION

ProShield V3 is not a cosmetic continuation of the rule-based MVP. V3 extends ProShield from a functioning security-platform foundation into a more complete **security operations + practical Blue Team environment + human-validated security-data foundation for future AI/ML research**.

The central V3 philosophy is:

> **Build the security system first. Establish trusted evidence and human decisions second. Build AI intelligence on top of those trustworthy foundations later.**

V3 must therefore not become an AI-first product.

The platform must first make the following chain reliable, explainable, auditable, and strongly connected:

```text
External / local security activity
        ↓
Trusted source boundary
        ↓
Canonical SecurityEvent
        ↓
Detection
        ↓
Correlation
        ↓
Case / Investigation
        ↓
Analyst investigation
        ↓
Human resolution / verdict
        ↓
Curated Security Evidence
        ↓
Quality gate
        ↓
Versioned AI Dataset
        ↓
External AI / ML research
```

The V3 Guide/AI component is deliberately **not** part of the security decision path. It is a future controlled intelligence layer and is explicitly held until the underlying domain, workflow, evidence, and dataset foundations are mature.

---

# 2. WHY V3 EXISTS

The completed V2/V4-era foundation already provides the core security workflow: ingestion, source trust, rule-based detection, correlation, cases/incidents, human identifiers, attribution, notes, severity/confidence, notifications, telemetry, timeline, reports, persistence controls, and extensive verification.

V3 is intended to extend that foundation in a disciplined way rather than reimplement it.

V3 addresses the next architectural problems:

1. **Reusable capability architecture** so one processing capability can support many source instances.
2. **Stronger source lifecycle and capability ownership** rather than treating source type strings as the architecture.
3. **Human-authoritative investigation** so a case closure becomes a structured analyst decision instead of a bare state transition.
4. **Explicit temporary-versus-durable security data lifecycle** so ProShield does not have to retain every candidate security object forever.
5. **Security Evidence Archive** that preserves analyst context, provenance, reasoning and evidence rather than storing only a TP/FP label.
6. **AI Dataset system** that is distinct from the evidence archive and supports quality-controlled, reproducible datasets.
7. **Separate learning/lab direction** that can later use ProShield as the security backend without contaminating the main SOC application with unsafe educational/LLM logic.
8. **Future Guide mini-agent** that is workflow-aware and permission-scoped, but is explicitly deferred until the underlying platform and knowledge are sufficiently mature.

The architectural target is therefore larger than a small startup-style dashboard but remains disciplined: the security platform is the primary system of record; learning and AI layers are consumers of the platform, not replacements for it.

---

# 3. PHASE 5.0 PURPOSE AND NON-GOALS

## 3.1 Purpose

Phase 5.0 creates the V3 architectural contract before feature implementation begins.

It must provide implementation agents with enough information to understand:

- what V3 is;
- why each major domain exists;
- which entities are first-class;
- how those entities relate;
- which data is trusted, derived, temporary, curated or dataset-ready;
- where ownership belongs;
- what the backend must guarantee;
- what the database must guarantee;
- what the frontend must represent;
- what the separate learning/lab application will eventually consume;
- what is intentionally deferred;
- how phases 5.1–5.9 depend on one another;
- how each phase must be verified before the next is allowed to begin.

## 3.2 Explicit non-goals

Phase 5.0 does **not**:

- implement Capability Registry code;
- change source implementation code;
- build a learner application;
- build a chatbot;
- integrate an LLM;
- fine-tune a model;
- build a separate learner database;
- create fake AI functionality merely for demonstration;
- redesign the existing V2 security pipeline merely for V3 branding;
- replace human analysts with autonomous AI;
- claim production deployment readiness;
- claim market or research novelty as a proven fact.

---

# 4. CURRENT BASELINE THAT V3 BUILDS UPON

V3 is an extension of the existing ProShield platform, not a replacement.

The existing foundation that should be preserved includes, at minimum:

- SecurityEvent ingestion and persistence;
- source authentication/trust concepts;
- replay protection;
- detection;
- correlation;
- case/incident creation;
- stable human-readable identifiers;
- case attribution;
- analyst notes;
- severity;
- confidence;
- correlation pattern catalogue;
- notifications;
- deep health;
- source telemetry;
- global timeline;
- server-side time-series aggregates;
- report export;
- rule lifecycle;
- database validators and indexes;
- SecureProxy client boundary;
- inbound source trust boundary;
- existing analyst UI and its established workflows.

V3 phases must extend these systems rather than fork them into a second competing implementation.

The latest capability-patch verification established a strong baseline through automated tests, fresh-database checks, live HTTP checks, restart-persistence checks and a real browser journey. Those forms of evidence become the expected quality bar for later V3 phase gates as applicable.

---

# 5. V3 PRODUCT DEFINITION

ProShield V3 is a **local-first, self-hosted security operations and practical Blue Team platform** designed to:

1. receive security telemetry from trusted sources;
2. normalize that telemetry into canonical security events;
3. apply capability-owned detection rules;
4. correlate related detections;
5. create contextualized investigation cases;
6. support human-led investigation;
7. record an explicit analyst verdict and reasoning;
8. preserve selected high-value, provenance-rich security evidence;
9. turn quality-controlled evidence into versioned AI/ML datasets;
10. eventually provide a controlled learning/Guide layer on top of the platform.

The security platform remains the authoritative operational system.

---

# 6. CORE V3 ARCHITECTURE

## 6.1 High-level target

```text
                         PROSHIELD V3
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
       Security Platform   Blue Team Lab    Guide/Learning
             │                │                │
             └────────────────┼────────────────┘
                              │
                       CAPABILITY LAYER
                              │
                       SOURCE INSTANCES
                              │
                           INGRESS
                              │
                       NORMALIZATION
                              │
                         DETECTION
                              │
                        CORRELATION
                              │
                            CASE
                              │
                        INVESTIGATION
                              │
                    TEMPORARY SECURITY DATA
                              │
                       HUMAN AUTHORITY
                              │
                      ANALYST RESOLUTION
                              │
                 ┌────────────┼────────────┐
                 ▼            ▼            ▼
                 TP           FP       UNCERTAIN
                 └────────────┼────────────┘
                              ▼
                   SECURITY EVIDENCE ARCHIVE
                              │
                         QUALITY GATE
                              │
                       DATASET BUILDER
                              │
                       DATASET VERSION
                              │
                    JSONL / CSV / PARQUET
                              │
                          AI / ML
```

## 6.2 Main operational flow

```text
External Source
  → Trusted Source Identity / Ingress
  → SourceRegistry
  → Capability resolution
  → SecurityEventIngestionService
  → SecurityEvent persistence
  → DetectionPipeline
  → DetectionRepository
  → CorrelationEngine
  → CorrelationRepository
  → Case assembly
  → Investigation
  → Analyst Resolution
  → Security Evidence promotion (selected cases only)
  → Dataset eligibility / builder
  → Versioned dataset export
```

Every phase must preserve the distinction between:

- **observed facts**;
- **derived security conclusions**;
- **analyst decisions**;
- **recommendations**;
- **curated evidence**;
- **dataset transformations**.

These must never be silently collapsed into one generic “alert” object.

---

# 7. NON-NEGOTIABLE ARCHITECTURAL INVARIANTS

These rules are mandatory.

## 7.1 Capability and source model

1. One **Capability** may have many **SourceInstances**.
2. There is **no subconnector abstraction** in V3.
3. A source instance is a configured external deployment/integration instance.
4. The source token identifies the source instance.
5. Source identity is distinct from analyst/client identity.
6. A source resolves to a capability.
7. Capability is the reusable implementation/responsibility layer.
8. Source instances must not contain arbitrary executable backend code.
9. Frontend configuration must never become the security implementation itself.
10. A newly registered/enabled capability must become immediately selectable where the contract requires it (sources and rules).

## 7.2 Detection and investigation semantics

11. SecurityEvent ≠ Detection.
12. Detection ≠ Correlation.
13. Correlation ≠ Case.
14. Case ≠ confirmed threat.
15. Detection and correlation are derived security results, not direct human verdicts.
16. Evidence shown in a case must remain traceable to observed or explicitly derived data.
17. The system must distinguish observed facts from derived conclusions and recommendations.

## 7.3 Human authority

18. The analyst is the final authority for case resolution.
19. Closing a case does not automatically make it training data.
20. An analyst label does not automatically make an evidence record dataset-eligible.
21. Human reasoning, confidence and evidence reviewed must be preserved when explicitly recorded by the product.
22. High-impact security decisions remain human-controlled.
23. ProShield's objective is to make analysts faster, not to remove the analyst.

## 7.4 Data lifecycle

24. Candidate investigation data is not automatically durable training data.
25. Temporary investigation data must remain available long enough for the analyst to investigate and label it.
26. Durable archival happens through explicit promotion/governance.
27. Security Evidence Archive ≠ configuration recycle bin.
28. Security Evidence Archive ≠ Dataset.
29. DatasetVersion is a reproducible view of selected evidence, not a second evidence archive.
30. Original provenance must survive evidence promotion and dataset transformation.

## 7.5 AI boundaries

31. The future Guide is not the security decision engine.
32. The future Guide must never be granted unrestricted database access.
33. The future Guide must not receive unrestricted shell/PowerShell execution authority.
34. Tool access must be explicit, scoped and allowlisted.
35. Security telemetry and case content must be treated as untrusted data with respect to model instructions.
36. AI recommendations are advisory unless a future explicitly authorized workflow changes this boundary.
37. V3 must not depend on fine-tuning to function.

---

# 8. TRUST BOUNDARIES

ProShield contains two important logical security boundaries.

## 8.1 External source → ProShield ingress boundary

```text
External Security System
        ↓
Inbound Ingress Trust Boundary
        ↓
Source identity verification
        ↓
Source registry / lifecycle validation
        ↓
Rate / size / replay guards
        ↓
Canonical event ingestion
```

Untrusted source telemetry must not be allowed to self-declare trusted provenance, source identity, or ProShield authority.

## 8.2 Analyst/client → ProShield SecureProxy boundary

```text
Browser / Analyst Client
        ↓
SecureProxy
        ↓
Authentication
        ↓
Authorization
        ↓
Service layer
        ↓
Persistence / engines
```

Client-side visibility does not establish authorization. The backend remains authoritative.

## 8.3 Future learning/Guide boundary

```text
Learning / Guide Application
        ↓
Scoped ProShield APIs
        ↓
Read-only / narrowly controlled operations
        ↓
ProShield Security Platform
```

The learning application is not an alternative admin client and must not bypass SecureProxy/security contracts.

---

# 9. FIRST-CLASS V3 DOMAINS

The V3 domain model introduces or formalizes the following first-class concepts:

- `Capability`
- `SourceInstance`
- `SecurityEvent`
- `Detection`
- `Correlation`
- `Case`
- `CaseResolution`
- `SecurityEvidence`
- `Dataset`
- `DatasetVersion`
- `ConfigurationRecycleBin`
- `ProShieldGuide` (future)
- `KnowledgeItem` (future Guide/learning)
- `OnboardingSession` (future learning application)

The existing V2 entities remain authoritative where already implemented. V3 adds new domains around them rather than replacing them without cause.

---

# 10. DOMAIN RELATIONSHIPS

## 10.1 Capability relationship

```text
Capability
  ├── SourceInstances
  ├── Rules
  └── Correlation Patterns
```

The capability defines reusable security-processing responsibility.

## 10.2 Source relationship

```text
SourceInstance
  └── SecurityEvents
```

A source instance owns the trust identity and configuration for one external integration instance.

## 10.3 Event relationship

```text
SecurityEvent
  └── Detections
```

Events are observed/normalized security facts. They are not analyst conclusions.

## 10.4 Detection relationship

```text
Detection
  └── Correlations
```

Detections are rule/logic-derived results.

## 10.5 Correlation relationship

```text
Correlation
  └── Cases
```

Correlations group related detections under documented patterns and context.

## 10.6 Case relationship

```text
Case
  ├── Investigation context
  ├── Notes
  ├── Evidence references
  └── CaseResolution
```

A case is the operational investigation container.

## 10.7 Resolution relationship

```text
CaseResolution
  └── selected SecurityEvidence promotion
```

A resolution records the human decision. Evidence promotion is a separate governed operation.

## 10.8 Evidence relationship

```text
SecurityEvidence
  └── Dataset membership
```

Only evidence that passes the required quality/eligibility gates can become dataset material.

---

# 11. CAPABILITY ARCHITECTURE — V3 TARGET

## 11.1 Meaning

A capability is the reusable security-processing responsibility associated with a supported external system family or security function.

Examples conceptually include NGINX, WAF, IAM, or SIEM-related capability implementations, but names are not themselves a guarantee that implementation exists.

The architecture must never infer capability support merely because an enum/string exists.

## 11.2 Capability responsibilities

A capability may own or expose:

- supported source configuration schema;
- mapping profiles;
- source-specific normalization behavior;
- rules;
- correlation patterns;
- capability version information;
- supported telemetry expectations;
- health/validation semantics where applicable.

## 11.3 Capability record target fields

At minimum, the design plans for:

- `capability_id`
- `human_id`
- `name`
- `description`
- `responsibility`
- `implementation`
- `version`
- `status`
- `configuration_schema`
- `mapping_profiles`
- `rules`
- `correlation_patterns`
- `created_at`
- `updated_at`

Exact physical representation may be refined in Phase 5.1 after implementation profiling, but the domain semantics are frozen here.

## 11.4 Capability lifecycle

Target administrative lifecycle:

```text
CREATE
  ↓
ENABLE
  ↓
DISABLE
  ↓
RETIRE
  ↓
ARCHIVE
```

Update operations must respect lifecycle/state rules.

## 11.5 Capability registration principle

Capability management must register/enable a trusted installed implementation. It must not become an arbitrary code-upload system.

---

# 12. SOURCE ARCHITECTURE 2.0 — V3 TARGET

V3 keeps source management as a distinct concept from rule management.

**Source Management asks:**

> What external security systems are connected to ProShield?

**Rule Management asks:**

> What security behavior should ProShield detect?

These are not the same domain.

## 12.1 Target source fields

A source instance may contain:

- source identity;
- capability identifier;
- capability version;
- unique credential/token reference;
- configuration;
- mapping profile;
- connection type;
- lifecycle state;
- health/telemetry metadata;
- creation/update metadata.

Secrets must not be exposed to the client.

## 12.2 Source lifecycle

The target V3 lifecycle is:

```text
CREATED
   ↓
CONFIGURED
   ↓
VALIDATED
   ↓
ACTIVE
   ↓
DISABLED
   ↓
RETIRED
   ↓
ARCHIVED
```

Implementation may use the exact existing state names where already contractually established, but semantic behavior must match this model.

## 12.3 Retirement rules

Retiring a source must:

- revoke its token/credential immediately as applicable;
- stop new ingestion;
- preserve source identity references;
- preserve historical evidence;
- preserve event/detection/correlation/case/report history;
- preserve audit lineage.

Retirement must not delete historical security evidence merely because the source configuration is gone.

## 12.4 Six-step source wizard target

The frontend source creation workflow is frozen conceptually as:

1. Identity
2. Capability
3. Connection
4. Credentials
5. Validation
6. Enable & Verify

The wizard must call real backend contracts and may not use local-only fake state as authoritative state.

---

# 13. RULE ARCHITECTURE IN V3

Rules remain separate from source management.

The planned relationship is:

```text
Capability
   ↓
Rules
   ↓
Detection
```

A rule may be associated with a capability and must operate against the canonical event model.

The rule lifecycle remains a backend-governed lifecycle and must stay connected to the live detection path.

A frontend rule entry is not evidence that the live engine can execute it.

A rule must be considered real only when:

- it is persisted where required;
- it is authorized;
- its lifecycle state is respected by the live detection path;
- its capability/source applicability is enforceable;
- its outputs are observable through the real pipeline;
- the behavior is testable.

---

# 14. SECURITY EVENT / DETECTION / CORRELATION / CASE MODEL

## 14.1 SecurityEvent

Represents canonicalized observed security telemetry.

Must retain provenance sufficient to establish where the event came from and how it entered ProShield.

## 14.2 Detection

Represents a derived rule/detection result associated with one or more events according to the existing detection model.

It must not be represented as a confirmed threat without an analyst decision.

## 14.3 Correlation

Represents an explicit grouping/relationship among detections according to a correlation pattern or centralized analytical process.

It must preserve enough context to explain why the detections were grouped.

## 14.4 Case

Represents the operational investigation container built from security context.

It can contain:

- human ID;
- state;
- attribution;
- related events/detections/correlations;
- timeline context;
- analyst notes;
- resolution information;
- evidence references;
- reporting context.

The exact persisted representation is implementation-specific but these semantics are frozen.

---

# 15. HUMAN AUTHORITY / CASE RESOLUTION — V3 TARGET

Case closure is not enough for V3.

V3 introduces the explicit concept of `CaseResolution`.

## 15.1 Planned fields

- `verdict`
- `classification`
- `benign_reason`
- `analyst_confidence`
- `reasoning`
- `evidence_reviewed`
- `detection_assessment`
- `severity_assessment`
- `analyst_id`
- `resolved_at`

## 15.2 Verdict taxonomy

Primary verdicts:

- `TRUE_POSITIVE`
- `FALSE_POSITIVE`
- `BENIGN`
- `SUSPICIOUS`
- `UNDETERMINED`
- `DISPUTED`

## 15.3 TP classification taxonomy

- Credential Attack
- Brute Force
- Credential Stuffing
- Malware
- Command & Scripting
- Privilege Escalation
- Persistence
- Lateral Movement
- Data Exfiltration
- Reconnaissance
- Defense Evasion
- Other

## 15.4 FP / benign reason taxonomy

- Normal User Behavior
- Administrator Activity
- Security Scanner
- Automated System/Service
- Scheduled Job
- Configuration/Deployment
- Testing/Development
- Expected Application Behavior
- Detection Rule Too Broad
- Duplicate/Correlated Noise
- Other

## 15.5 Analyst quality/context fields

The resolution workflow should support:

- analyst confidence: High / Medium / Low;
- resolution notes/reasoning;
- evidence reviewed;
- detection correctness assessment: Too High / Correct / Too Low;
- severity correctness assessment: Too High / Correct / Too Low.

The analyst remains the authority.

---

# 16. TEMPORARY SECURITY DATA LIFECYCLE

This is one of the most important V3 architectural changes.

ProShield should not assume that every piece of telemetry must be retained forever as permanent AI-training material.

## 16.1 Lifecycle classes

```text
LIVE
  ↓
INVESTIGATION
  ↓
CURATED
  ↓
ARCHIVED
  ↓
DATASET
```

These are conceptual lifecycle classes, not necessarily identical to MongoDB collection names.

## 16.2 Candidate investigation data

Initially relevant candidate data may include:

- SecurityEvent
- Detection
- Correlation
- Case
- Timeline context
- original evidence/context needed for investigation.

The candidate investigation state must remain available long enough for a human to investigate and label it.

## 16.3 Promotion flow

```text
Candidate Investigation
        ↓
Analyst Investigation
        ↓
Analyst Verdict
        ↓
Retention / Promotion Decision
        ↓
   ┌────┴────┐
   ↓         ↓
PROMOTE     EXPIRE
```

Promotion may create durable `SecurityEvidence`.

Expiration removes only the data governed by the temporary-retention policy, not historical data that has already become durable evidence or required audit history.

## 16.4 TTL / retention design

Temporary investigation state may use TTL-style retention where appropriate.

The exact physical design must be established after access-pattern and profiling work, but the semantic rule is frozen:

> **Do not expire candidate evidence before the analyst has a reasonable opportunity to investigate and label it.**

---

# 17. SECURITY EVIDENCE ARCHIVE

## 17.1 Purpose

Security Evidence is durable, curated security knowledge selected from investigations under human authority and quality control.

It is not simply a dump of all events and not merely a table containing `TP` or `FP`.

## 17.2 Categories

The archive should support at least:

- Confirmed Threats;
- False Positives;
- Benign Activity;
- Suspicious / Undetermined;
- Disputed.

## 17.3 Planned services

- `SecurityEvidence`
- `EvidenceRepository`
- `EvidenceQualityService`
- `EvidencePromotionService`

## 17.4 Planned record context

Target information includes:

- evidence human ID, e.g. `ARCH-000001`;
- case ID;
- source ID;
- capability ID;
- rule ID;
- rule version;
- detection ID;
- correlation ID;
- event context;
- evidence content;
- verdict;
- classification;
- reason;
- analyst confidence;
- analyst reasoning;
- severity assessment;
- provenance;
- quality state.

## 17.5 Quality state

At minimum:

- `CANDIDATE`
- `REVIEW_REQUIRED`
- `VALIDATED`
- `REJECTED`
- `DATASET_ELIGIBLE`

A critical invariant is:

```text
Analyst labelled
      ≠
Automatically training-ready
```

A separate quality gate is mandatory.

---

# 18. DATASET ARCHITECTURE

Security Evidence and AI Dataset are intentionally different systems.

## 18.1 Dataset objects

Planned components:

- `Dataset`
- `DatasetVersion`
- `DatasetBuilder`
- `DatasetQualityService`
- `DatasetExporter`

## 18.2 Dataset filters

Dataset construction should be filterable by relevant dimensions such as:

- verdict;
- capability;
- source;
- rule;
- rule version;
- classification;
- confidence;
- severity assessment;
- date range;
- analyst;
- evidence quality state.

## 18.3 DatasetVersion semantics

A dataset version should capture:

- included examples;
- excluded examples;
- filters used;
- statistics;
- provenance;
- quality state;
- stable version identity.

The dataset version must make later ML experiments reproducible.

## 18.4 External training principle

Do not label the ProShield button “Train AI”.

Use:

> **Export AI Dataset**

because training initially occurs outside ProShield.

---

# 19. EXPORT ARCHITECTURE

Two distinct export families exist.

## 19.1 Human-facing exports

For:

- investigations;
- reports;
- evidence inspection;
- sharing;
- human review.

Target formats:

- PDF
- CSV
- Markdown

## 19.2 AI/ML exports

For:

- ML experiments;
- data analysis;
- training;
- evaluation.

Target formats:

- JSONL
- CSV
- Parquet

JSONL is especially important for model/dataset workflows; Parquet is useful as the scale grows.

---

# 20. SEPARATION OF SECURITY PLATFORM AND LEARNING/LAB APPLICATION

## 20.1 Architectural decision

The future Blue Team learner/lab product should be a **separate application** that uses ProShield as the security backend through explicit, scoped APIs.

It should not be merged into the main analyst application merely for convenience.

## 20.2 Rationale

This separation:

- keeps the main SOC application professional and security-focused;
- prevents learning-state complexity from polluting the security domain model;
- limits learner privileges;
- avoids giving an LLM/learner environment unnecessary control over security operations;
- allows the learning product to evolve independently;
- allows ProShield to become the real backend behind practical training without duplicating the security pipeline.

## 20.3 Future architecture

```text
                 PROSHIELD SECURITY PLATFORM
        ┌───────────────────────────────────────┐
        │ Auth / RBAC                            │
        │ Capabilities                           │
        │ Sources                                │
        │ Ingress                                │
        │ Events                                 │
        │ Detection                              │
        │ Correlation                            │
        │ Cases / Investigation                  │
        │ Security Evidence                      │
        │ Datasets                               │
        │ Audit / Health                         │
        └──────────────────┬────────────────────┘
                           │ scoped APIs
                           ▼
              PROSHIELD BLUE TEAM LAB
        ┌───────────────────────────────────────┐
        │ learner identity/session              │
        │ learning progress                     │
        │ guided labs                           │
        │ behavior generation                   │
        │ challenges                             │
        │ learning notes                        │
        │ Guide mini-agent (future)             │
        └───────────────────────────────────────┘
```

---

# 21. PHASE 5.3 STATUS — HELD, NOT CANCELLED

Earlier planning described Phase 5.3 as “Beginner Onboarding + Real Lab.” The architecture is retained, but the implementation is intentionally **ON HOLD** in the current V3 execution plan.

The reason is strategic and practical:

- the immediate objective is to strengthen the real ProShield analyst/security platform;
- the platform itself can be used as the developer/analyst learning environment;
- a separate learner product is not required to start learning cybersecurity through ProShield;
- premature construction of an education platform could distract from the security foundation;
- the correct learner UX is better designed after more real hands-on security experience has been accumulated.

## 21.1 Future 5.3 direction

When resumed, 5.3 should build a separate **ProShield Blue Team Lab**.

The long-term learning philosophy is behavior-driven:

```text
Concept
  ↓
Guided simulated lab
  ↓
Guided real behavior creation
  ↓
Self-created behavior
  ↓
Observe telemetry
  ↓
Investigate
  ↓
Build/modify detection
  ↓
Create harder behavior
  ↓
Reason independently
```

The learner should eventually create security behaviors themselves, for example with PowerShell/Linux tools in a controlled environment, rather than only answering pre-scripted simulation questions.

Guided scenarios remain useful as an entry ramp for a zero-knowledge beginner, but independent behavior creation is the intended deeper learning loop.

---

# 22. PHASE 5.9 STATUS — GUIDE MINI-AGENT HELD

Phase 5.9 is also **ON HOLD** in the current execution plan.

The future Guide remains part of the architectural direction, but it must not be introduced into the main security-control path while the system's knowledge, workflow contracts, permission model and safety mechanisms are immature.

## 22.1 Future Guide architecture

The intended future Guide is not a normal website chatbot.

It is a **small, controlled, workflow-aware mini-agent** that can:

- understand user intent;
- retrieve authoritative ProShield knowledge;
- inspect only permitted workflow/state context;
- select explicitly allowed tools;
- explain results;
- guide the user through the next step;
- verify progress;
- adapt depth to learner/operator needs.

Conceptually:

```text
User request
    ↓
Intent understanding
    ↓
Authoritative knowledge retrieval
    ↓
Allowed context inspection
    ↓
Workflow/state reasoning
    ↓
Allowed tool selection
    ↓
Tool/API result
    ↓
Explanation + next action
    ↓
Verification
```

## 22.2 Future Guide boundary

The Guide must not:

- become the detection engine;
- become the correlation engine;
- make the final security verdict;
- receive unrestricted database credentials;
- execute arbitrary shell/PowerShell commands;
- invent unsupported ProShield features;
- turn untrusted event content into system instructions;
- silently modify security state.

Any write/tool operation must be explicitly allowlisted and permission-scoped.

## 22.3 Future model strategy

The initial future Guide should use:

```text
LLM
 +
authoritative ProShield knowledge
 +
workflow definitions
 +
current application state
 +
UI/workflow context
 +
safe tools
```

The planned model does not need to be fine-tuned for the first version.

Fine-tuning, if ever justified, should be considered only after enough real interactions and evaluation data exist.

---

# 23. FUTURE KNOWLEDGE ARCHITECTURE

When the Guide/learning work resumes, knowledge should be structured rather than treated as a pile of prompt text.

Target conceptual structure:

```text
knowledge/
├── architecture/
├── capabilities/
├── sources/
├── rules/
├── investigations/
├── archive/
├── datasets/
├── troubleshooting/
├── learning/
└── workflows/
```

Each knowledge item may carry fields such as:

- concept;
- definition;
- why;
- how;
- next step;
- related entities;
- version;
- status.

The knowledge layer must explicitly distinguish:

- implemented;
- planned;
- unsupported;
- deprecated.

The Guide must never infer an implementation simply because a concept appears in documentation.

---

# 24. FUTURE LEARNER IDENTITY PRINCIPLE

When the learning application is eventually implemented, learner identity must be distinct from normal ProShield operational identities.

Conceptually:

```text
ADMIN
  → platform administration

ANALYST
  → investigation and security operations

INTERNAL SERVICE
  → controlled service operations

LEARNER
  → learning workspace and approved lab operations

INSTRUCTOR (future)
  → learning administration
```

A learner must not automatically inherit analyst/admin privileges.

The learner environment should use scoped APIs and approved operations.

The initial learning direction does not require a second full security database. Learning progress and chat can be portable files/session state while the security backend remains the authoritative security datastore.

---

# 25. DATABASE MASTER DIRECTION

V3 does not require changing the database engine.

The existing V2 collections remain the foundation.

## 25.1 Existing foundation

Conceptually includes:

- `security_events`
- `detections`
- `correlations`
- `incidents`
- `managed_rules`
- `source_instances`
- `reports`
- `notifications`
- `source_telemetry`
- `counters`

## 25.2 Planned V3 additions

The V3 planning targets collections or equivalent persistent structures for:

- `capabilities`
- `capability_versions`
- `case_resolutions`
- `investigation_evidence`
- `security_evidence`
- `evidence_quality`
- `retention_policies`
- `recycle_bin`
- `datasets`
- `dataset_versions`
- `dataset_membership`
- `guide_knowledge` (future)
- `onboarding_sessions` (future)
- `guide_workflows` (future)

These names are implementation targets, not an instruction to create every collection blindly.

The exact normalization/collection layout must be established from domain and access-pattern analysis in the implementation phase.

## 25.3 Database invariants

V3 database changes must maintain the existing defense-in-depth philosophy:

- JSON schema validation where appropriate;
- unique indexes where uniqueness is required;
- lifecycle/state indexes;
- deterministic identifiers where required;
- provenance integrity;
- bounded query patterns;
- correct concurrency semantics;
- restart persistence;
- safe handling of poisoned/legacy data.

---

# 26. CONFIGURATION RECYCLE BIN VS SECURITY EVIDENCE

These domains must remain completely separate.

## Configuration Recycle Bin

Purpose:

- retain removed/retired configuration objects;
- support controlled administrative recovery where specified;
- preserve configuration history.

Examples:

- retired source configuration;
- removed capability configuration;
- removed rules where the product contract supports recovery.

## Security Evidence Archive

Purpose:

- preserve curated security knowledge selected from investigations;
- preserve human verdict, provenance, reasoning and evidence;
- support later research/dataset construction.

Deleting configuration must never silently delete durable security evidence.

---

# 27. FRONTEND ARCHITECTURE TARGET

The main ProShield analyst application remains focused on security operations.

Target high-level navigation:

```text
Overview
│
├── Investigations
│   ├── Incidents
│   └── Case Detail
│
├── Detection Intelligence
│   ├── Detections
│   ├── Correlations
│   └── Timeline
│
├── Sources
│   └── Source Wizard
│
├── Capabilities
│   ├── Capability List
│   └── Capability Detail
│
├── Rules
│
├── Security Evidence
│   ├── Archive
│   ├── TP
│   ├── FP
│   ├── Benign
│   ├── Undetermined
│   └── Disputed
│
├── AI Dataset
│   ├── Dataset Builder
│   ├── Review
│   ├── Versions
│   └── Export
│
├── Configuration Recycle Bin
│
├── Health
│
└── Notifications
```

A future Guide entry should not be implemented in the main analyst application merely because the navigation map contains the concept. The Guide is currently held.

## 27.1 UX principles

The V3 frontend must remain:

- professional;
- security-operator-oriented;
- evidence-aware;
- responsive;
- accessible;
- truthful about backend state;
- free of fake operations;
- stable on desktop and smaller supported viewports.

Where a relationship is important, prefer clear 2D relationship visualization. Purposeful spatial/3D visuals can be considered later only where they add real forensic meaning.

---

# 28. API / BACKEND IMPLEMENTATION PRINCIPLES

All V3 feature implementations must follow the established layering:

```text
Frontend
   ↓
SecureProxy / authorized API boundary
   ↓
Domain Service
   ↓
Repository / Engine
   ↓
Persistence
```

Cross-cutting rules:

1. Backend authorization remains authoritative.
2. Frontend state is never security authority.
3. API operations must be explicit and allowlisted.
4. Invalid state transitions must return structured, truthful errors.
5. Repeated operations must be idempotent only where the contract says so.
6. Duplicate operations that must be rejected should return the documented conflict/error semantics.
7. Unknown objects must not produce fake success.
8. Empty datasets must be represented honestly.
9. Missing derivable fields should be `null`/explicitly unknown, not fabricated.
10. Historical legacy records must not be silently “fixed” by invented values.

---

# 29. PROVENANCE PRINCIPLE

Every security object must make it possible, where the data exists, to answer:

> Where did this information come from?

The conceptual provenance chain is:

```text
Source Instance
   ↓
Security Event
   ↓
Detection
   ↓
Correlation
   ↓
Case
   ↓
Resolution
   ↓
Security Evidence
   ↓
Dataset Version
```

A derived conclusion must not masquerade as an observed fact.

For example:

**Observed fact:** multiple failed authentication events were observed from a source/IP within a time window.

**Derived conclusion:** those events matched a documented correlation pattern.

**Recommendation:** route or prioritize the case for a particular skill/analyst level.

Those statements have different epistemic status and must remain distinguishable.

---

# 30. ROUTING PRINCIPLE IN V3

Routing remains recommendation-oriented unless an explicitly authorized response workflow later extends it.

The target routing concept is:

```text
RIGHT INCIDENT
      ↓
RIGHT SKILL
      ↓
RIGHT ANALYST LEVEL / TEAM
      ↓
RIGHT TIME
```

Routing may consider:

- severity;
- confidence;
- incident category;
- complexity;
- required expertise;
- affected technology;
- affected asset;
- business criticality;
- available skill category information where legitimately provided.

The initial design must not pretend it knows individual analyst availability unless a real authorized source provides that information.

Routing is a recommendation, not an unverified fact.

---

# 31. RESPONSE BOUNDARY

The current ProShield security model remains:

```text
Detect
  → Report
  → Recommend
  → Human Approval
  → Response
```

The V3 architecture must not silently introduce unrestricted autonomous destructive actions.

Examples that remain outside the initial autonomous boundary include:

- account deletion;
- mass session revocation;
- broad firewall modification;
- destructive infrastructure changes.

Future low-risk controlled automation can be considered only after the core detection/investigation workflow is proven.

---

# 32. Dvany RELATIONSHIP

Dvany remains a practical reference environment for developing and validating ProShield capabilities, but ProShield must not become Dvany-dependent.

The correct relationship is:

```text
Dvany Requirements
       ↓
Configuration / Source Examples
       ↓
Rules / Capability Requirements
       ↓
Connector / Capability Implementation
```

Dvany-specific business logic must not be hard-coded into the core ProShield architecture.

---

# 33. V3 IMPLEMENTATION PHASES

The dependency order is frozen as follows.

## Phase 5.0 — Architecture Freeze

**Current phase.**

Output:

- V3 architecture document;
- domain boundaries;
- lifecycle definitions;
- ownership rules;
- implementation dependency map;
- explicit HOLD items;
- testing gates.

## Phase 5.1 — Capability Management

Implement:

- Capability Registry;
- capability persistence;
- validators/indexes;
- capability lifecycle;
- capability admin APIs;
- capability UI;
- immediate availability to source/rule workflows;
- capability/version relationship.

## Phase 5.2 — Source Architecture 2.0

Implement:

- source → capability linkage;
- capability version linkage;
- stronger source configuration model;
- token/credential semantics;
- source lifecycle;
- source wizard;
- retirement/archive semantics;
- telemetry/health integration.

## Phase 5.3 — Blue Team Lab Foundation

**STATUS: HOLD.**

Future target:

- separate learner/lab application;
- scoped learner identity;
- controlled lab workflows;
- guided simulations;
- controlled behavior generation;
- self-created behavior experiments;
- investigation-oriented learner flow.

## Phase 5.4 — Human Authority / Case Resolution

Implement:

- CaseResolution domain;
- verdict taxonomy;
- TP classification;
- FP/benign reason taxonomy;
- confidence/reasoning/evidence reviewed;
- detection/severity correctness assessment;
- closure workflow;
- durable resolution history.

## Phase 5.5 — Temporary Security Data Lifecycle

Implement:

- lifecycle state model;
- investigation retention state;
- TTL/retention mechanisms as appropriate;
- promotion boundary;
- expiration rules;
- auditability of retention/promotion.

## Phase 5.6 — Security Evidence Archive

Implement:

- SecurityEvidence;
- repository;
- promotion service;
- quality service;
- archive UI;
- provenance and analyst context;
- validation/rejection flow;
- dataset eligibility state.

## Phase 5.7 — AI Dataset System

Implement:

- Dataset;
- DatasetVersion;
- DatasetBuilder;
- DatasetQualityService;
- dataset membership;
- filters;
- statistics;
- provenance;
- reproducibility.

## Phase 5.8 — Export / Dataset Versioning

Implement/complete:

- human exports;
- AI dataset exports;
- JSONL/CSV/Parquet support as appropriate;
- deterministic dataset versions;
- export metadata/provenance;
- review/approval/export workflow.

## Phase 5.9 — ProShield Guide Mini-Agent

**STATUS: HOLD.**

Future target:

- controlled LLM integration;
- authoritative knowledge retrieval;
- current workflow state;
- scoped safe tools;
- learner/analyst contexts as separately authorized use cases;
- AI safety gateway;
- prompt-injection resistance;
- tool authorization;
- evaluation harness;
- truthfulness against implemented features.

## Final V3 Adversarial Re-Audit

After the implementable V3 slices are complete, perform a final independent audit across:

- fresh database;
- actual runtime;
- real external-like source;
- real behavioral generation;
- full detection/correlation/case lifecycle;
- human resolution;
- archive promotion;
- dataset generation;
- dataset export;
- browser UI;
- restart/persistence;
- security boundaries;
- adversarial authorization/trust scenarios.

---

# 34. PHASE DEPENDENCY GRAPH

```text
5.0 Architecture Freeze
        ↓
5.1 Capability Management
        ↓
5.2 Source Architecture 2.0
        ↓
     [5.3 HOLD]
        ↓
5.4 Human Authority / Resolution
        ↓
5.5 Temporary Data Lifecycle
        ↓
5.6 Security Evidence
        ↓
5.7 AI Dataset
        ↓
5.8 Export / Versioning
        ↓
     [5.9 HOLD]
        ↓
Final Adversarial Re-Audit
```

The hold states do not invalidate dependency reasoning. They only mean that the learning/AI branches are intentionally deferred until their prerequisites and strategic need are clearer.

---

# 35. TESTING GATE REQUIRED FOR EVERY V3 PHASE

Each phase must follow the same high-confidence verification pattern.

```text
Implementation
      ↓
Unit tests
      ↓
Integration tests
      ↓
Database validator/index tests
      ↓
API contract tests
      ↓
Real runtime
      ↓
Browser / UI verification
      ↓
Adversarial tests
      ↓
Restart / persistence
      ↓
Phase approval
```

A green unit suite alone is insufficient.

A successful screenshot alone is insufficient.

An HTTP 200 alone is insufficient.

A feature is not considered implemented merely because:

- the enum exists;
- a frontend screen exists;
- a handler returns 200;
- a test fixture seeds fake objects;
- a dead implementation path is present;
- documentation says the mechanism exists.

The phase must prove the real workflow at the owning layers.

---

# 36. FAILURE AND SECURITY TESTING EXPECTATIONS

V3 implementation agents must test both positive and negative paths.

Relevant recurring adversarial classes include:

- authentication bypass;
- authorization bypass;
- IDOR/BOLA;
- cross-source impersonation;
- source-token misuse;
- replay;
- concurrent replay;
- disabled/retired source ingestion;
- forged source identity;
- provenance manipulation;
- malformed event data;
- oversized requests;
- rate-limit bypass;
- batch amplification;
- lifecycle races;
- registry/persistence divergence;
- rule lifecycle divergence;
- duplicate event behavior;
- conflicting replay;
- case state conflicts;
- duplicate resolution operations;
- evidence promotion misuse;
- dataset eligibility bypass;
- unauthorized export;
- secret leakage;
- error information leakage;
- unsafe future AI tool use.

The exact threat matrix should be expanded by each phase's implementation-specific risk.

---

# 37. OBSERVABILITY AND OPERATIONAL TRUTH

V3 must preserve truthful operational state.

Health and telemetry must not report “healthy” merely because an object exists.

Examples of truthful behavior:

- no telemetry should remain visibly distinguishable from a source with active telemetry;
- unavailable dependencies must not silently appear healthy;
- empty timelines must be represented explicitly;
- legacy entities lacking new fields must show unknown/null rather than invented values;
- failed ingestion must not silently fabricate SecurityEvents;
- dataset statistics must disclose truncation/bounds where applicable;
- generated reports must reflect persisted state rather than frontend-only state.

---

# 38. LEGACY DATA PRINCIPLE

V3 must be backward-compatible where reasonable without falsifying history.

Existing legacy records may lack newly introduced fields such as human IDs, severity, or confidence.

Do not fabricate values merely to make the UI look complete.

Valid approaches include:

- explicit `null`/unknown state;
- documented display placeholder such as “—”;
- migration only when a deterministic, evidence-backed mapping exists.

The rule is:

> **Never turn missing historical truth into invented historical truth.**

---

# 39. SECURITY DATASET GOVERNANCE PRINCIPLE

The eventual AI dataset is a **research asset**, not a direct mirror of production telemetry.

The intended strategy is:

```text
Observe
  ↓
Detect
  ↓
Correlate
  ↓
Investigate
  ↓
Human verdict
  ↓
Curate selected evidence
  ↓
Quality gate
  ↓
Dataset version
  ↓
Export
  ↓
External ML/AI research
```

This means the data is enriched by the human investigation process.

The platform must preserve enough provenance to later answer:

- which source produced the data;
- which capability interpreted it;
- which rule version fired;
- which detection/correlation contributed;
- which case it belonged to;
- which analyst made the verdict;
- what evidence was reviewed;
- how confident the analyst was;
- what quality gate it passed;
- which dataset version included it.

This provenance chain is a core future AI/ML asset.

---

# 40. NO NOVELTY CLAIM WITHOUT RESEARCH

The architecture may intentionally differ from existing products, SIEMs, SOAR systems, data lakes, UEBA systems, active-learning systems, and cyber-ML pipelines.

However, Phase 5.0 does **not** declare the architecture to be proven novel or “game-changing”.

A defensible current description is:

> ProShield is deliberately building a workflow in which human security investigations and decisions become structured, provenance-rich security knowledge that can later be transformed into versioned AI/ML datasets.

Any stronger novelty claim requires a separate market and literature comparison.

---

# 41. IMPLEMENTATION OWNERSHIP RULE

Every feature must be assigned to the correct layer.

| Feature | Architecture | Backend | Database | Frontend |
|---|---|---|---|---|
| Capability Registry | Major | Major | New | New |
| Capability versions | Major | Major | New/modified | Detail UI |
| Source → Capability | Major | Modify | Modify | Wizard |
| Source credentials | Security architecture | Modify | Modify | Token/config UI |
| Source retirement | Lifecycle | Modify | Modify | Source UI |
| Configuration recycle bin | Lifecycle | New | New | New |
| Temporary investigation | Major | Major | New/modified | Case UI |
| Case resolution | Major | Major | New/modified | Major |
| TP/FP/Benign | Data model | Major | New/modified | Resolution UI |
| Provenance | Major | Major | New/modified | Evidence UI |
| Security Evidence | Major | Major | New | New |
| Evidence quality | Governance | New | New | Review UI |
| AI Dataset | Major | Major | New | New |
| Dataset versions | Major | New | New | New |
| AI exports | Data architecture | New | Reads evidence | New |
| Beginner onboarding | UX/learning architecture | Future APIs | Session state future | Separate app |
| Blue Team Lab | Learning architecture | Future scoped APIs | Future learning state | Separate app |
| ProShield Guide | AI architecture | Future | Knowledge/state future | Separate app initially |
| Existing SOC pages | Preserve | Minor extension | Minor | Visual integration |
| Health | Extend | Modify | Minor | Extend |

When a defect appears, classify its owner correctly. Do not “fix” a backend/data problem by hiding it in the frontend.

---

# 42. IMPLEMENTATION AGENT CONTRACT

Every AI/coding agent implementing Phase 5.1 onward must:

1. Read this document completely before coding.
2. Read the applicable phase specification.
3. Read the repository's project rules and Cline/SpecKit instructions.
4. Inspect the existing implementation before modifying it.
5. Treat the current repository and runtime as higher-confidence evidence than old reports.
6. Preserve existing verified V2 functionality unless the current phase explicitly changes it.
7. Never invent a missing capability.
8. Never weaken authentication, authorization, provenance, validation or lifecycle rules to make tests pass.
9. Build features at the owning architectural layer.
10. Add tests that prove both implementation and integration.
11. Run existing regression tests.
12. Run phase-specific adversarial tests.
13. Verify persistence/restart behavior where relevant.
14. Verify the browser when frontend behavior changes.
15. Produce a phase report with exact files changed, tests run, live/runtime verification, known limitations, risks and next phase.
16. Do not mark a phase complete merely because unit tests pass.

If a required mechanism does not exist, the report must state:

> **THIS MECHANISM DOES NOT EXIST IN THE CURRENT IMPLEMENTATION.**

If a test passes but does not actually prove the requirement, the report must say so.

---

# 43. WHAT V3 MUST NOT BECOME

V3 must not drift into any of the following:

### 43.1 AI-first SOC

Do not place an LLM in front of immature security data and call that the intelligence layer.

### 43.2 Generic chatbot product

The future Guide must not be a generic “ask anything” chatbot with undocumented ProShield behavior.

### 43.3 Arbitrary-code connector platform

Capabilities must be trusted implementations, not frontend-uploaded executable code.

### 43.4 Training-data dump

Do not dump all raw events/cases into an AI dataset.

### 43.5 Fake learning simulator

The future lab should ultimately connect to the real ProShield security backend rather than becoming a disconnected toy.

### 43.6 Duplicate security platform

The learning application must use the ProShield security backend rather than reimplementing detection/correlation/case logic.

### 43.7 Autonomous destructive responder

Do not bypass the human approval boundary without a separately approved architecture.

---

# 44. V3 SUCCESS CONDITION

At the end of the implementable V3 security/data phases, ProShield should be able to demonstrate this real chain:

```text
Trusted source
   ↓
Capability
   ↓
SecurityEvent
   ↓
Detection
   ↓
Correlation
   ↓
Case
   ↓
Investigation
   ↓
Analyst resolution
   ↓
Selected evidence promotion
   ↓
Quality validation
   ↓
Dataset version
   ↓
AI/ML-ready export
```

The chain must be demonstrated with real persisted data, not merely mocked objects.

The later learning/lab and Guide systems, when resumed, must consume this real platform rather than circumventing it.

---

# 45. FINAL V3 ARCHITECTURE DIAGRAM

This is the canonical mental model for every future implementation agent.

```text
                         ┌─────────────────────────┐
                         │   FUTURE GUIDE / LAB    │
                         │  Separate application   │
                         │  Learn / Guide / Lab    │
                         └────────────┬────────────┘
                                      │
                              Scoped APIs only
                                      │
                                      ▼
┌────────────────────────────────────────────────────────────────────┐
│                         PROSHIELD SECURITY                         │
│                                                                    │
│  CAPABILITY ───────────────► SOURCE INSTANCE                      │
│       │                             │                              │
│       │                             ▼                              │
│       ├── RULES ───────────────► INGRESS                          │
│       │                             │                              │
│       │                             ▼                              │
│       └── CORRELATION PATTERNS ► SECURITY EVENT                   │
│                                     │                              │
│                                     ▼                              │
│                                  DETECTION                          │
│                                     │                              │
│                                     ▼                              │
│                                 CORRELATION                         │
│                                     │                              │
│                                     ▼                              │
│                                   CASE                             │
│                                     │                              │
│                                     ▼                              │
│                               INVESTIGATION                        │
│                                     │                              │
│                                     ▼                              │
│                            ANALYST RESOLUTION                       │
│                                     │                              │
│                    ┌────────────────┼────────────────┐              │
│                    ▼                ▼                ▼              │
│                   TP               FP          UNCERTAIN           │
│                    └────────────────┼────────────────┘              │
│                                     ▼                              │
│                           SECURITY EVIDENCE                         │
│                                     │                              │
│                               QUALITY GATE                          │
│                                     │                              │
│                               DATASET BUILDER                       │
│                                     │                              │
│                               DATASET VERSION                       │
│                                     │                              │
│                           JSONL / CSV / PARQUET                     │
│                                     │                              │
│                                AI / ML                             │
└────────────────────────────────────────────────────────────────────┘
```

The human remains the final security authority.

The security platform remains the source of truth.

The future learning/Guide system remains a scoped consumer of the platform.

AI is downstream of trusted security data, not upstream of it.

---

# 46. PHASE 5.0 EXIT CRITERIA

Phase 5.0 is complete only when all of the following are true:

- [x] V3 purpose is defined.
- [x] V3 non-goals are defined.
- [x] Existing V2 foundation is explicitly treated as the baseline.
- [x] First-class V3 domains are defined.
- [x] Domain relationships are defined.
- [x] Capability/source architecture is frozen.
- [x] No-subconnector rule is frozen.
- [x] Detection/correlation/case distinction is frozen.
- [x] Human authority is frozen.
- [x] Temporary security data lifecycle is defined.
- [x] Security Evidence is separated from Dataset.
- [x] Dataset versioning concept is defined.
- [x] Provenance requirements are defined.
- [x] Security trust boundaries are defined.
- [x] Future learning/lab architecture is separated from the main SOC application.
- [x] Phase 5.3 is explicitly marked HOLD.
- [x] Phase 5.9 is explicitly marked HOLD.
- [x] AI/Guide security boundaries are defined before implementation.
- [x] V3 phase ordering is frozen.
- [x] Testing gate is defined for every later phase.
- [x] Implementation-agent behavior is defined.
- [x] “No fake capability” principle is explicit.
- [x] No-production-readiness-overclaim principle is explicit.

No product feature implementation is required to close Phase 5.0.

---

# 47. NEXT AUTHORIZED PHASE

The next authorized implementation phase is:

> **PHASE 5.1 — CAPABILITY MANAGEMENT**

Phase 5.1 must read and obey this document before implementation.

Its responsibility is to turn the frozen Capability domain into a real backend/database/frontend capability registry while preserving the existing V2 detection pipeline and source/rule contracts.

No Phase 5.2+ implementation should silently redefine the Capability architecture established here.

---

# 48. FINAL ARCHITECTURAL STATEMENT

ProShield V3 is intentionally built in this order:

```text
POWERFUL SECURITY FOUNDATION
          ↓
REAL SECURITY WORKFLOW
          ↓
HUMAN INVESTIGATION
          ↓
HUMAN-VERIFIED SECURITY KNOWLEDGE
          ↓
QUALITY-CONTROLLED DATASETS
          ↓
AI / ML RESEARCH
          ↓
FUTURE CONTROLLED LEARNING / GUIDE
```

The system should become intelligent because its underlying security workflow, evidence, provenance and human decisions are strong—not because an LLM was inserted before those foundations were finished.

**Phase 5.0 therefore freezes the architecture before V3 feature implementation begins.**
