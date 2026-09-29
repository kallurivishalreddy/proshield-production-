import {
  Case,
  Detection,
  Correlation,
  TimelineEvent,
  ConnectorCapability,
  SourceInstance,
  Rule,
  HealthSubsystem,
  Report,
  SocNotification
} from '../types/soc';

export const INITIAL_CONNECTOR_CAPABILITIES: ConnectorCapability[] = [
  {
    id: 'conn-nginx',
    name: 'NGINX Access & Security Gateway',
    category: 'WEB',
    description: 'High-throughput HTTP reverse proxy access and error log telemetry with real-time rate tracking.',
    version: 'v2.4.1',
    supportedProtocols: ['HTTPS / Syslog', 'Kafka Streaming', 'Vector Agent'],
    icon: 'Globe',
    activeSourceCount: 3
  },
  {
    id: 'conn-okta',
    name: 'Okta Identity Provider',
    category: 'IDENTITY',
    description: 'Cloud identity audit events, MFA challenges, password resets, and session anomalies.',
    version: 'v3.1.0',
    supportedProtocols: ['REST Webhook', 'EventBridge', 'Syslog RFC5424'],
    icon: 'ShieldCheck',
    activeSourceCount: 1
  },
  {
    id: 'conn-aws',
    name: 'AWS CloudTrail & GuardDuty',
    category: 'CLOUD',
    description: 'Multi-account AWS API audit trails, IAM role assumptions, and GuardDuty threat findings.',
    version: 'v4.0.2',
    supportedProtocols: ['S3 Ingestion', 'SQS Event Notification', 'Kinesis Stream'],
    icon: 'Cloud',
    activeSourceCount: 2
  },
  {
    id: 'conn-crowdstrike',
    name: 'CrowdStrike Falcon EDR',
    category: 'ENDPOINT',
    description: 'Process executions, memory injection detections, persistence hooks, and lateral movement telemetry.',
    version: 'v1.9.8',
    supportedProtocols: ['Falcon Streaming API', 'HEC Splunk Compatible'],
    icon: 'Laptop',
    activeSourceCount: 1
  },
  {
    id: 'conn-suricata',
    name: 'Suricata Network IDS / IPS',
    category: 'NETWORK',
    description: 'Deep packet inspection, TLS fingerprinting, DNS query logs, and network protocol anomaly stream.',
    version: 'v6.0.4',
    supportedProtocols: ['EVE JSON', 'Redis Queue', 'Raw PCAP Stream'],
    icon: 'Activity',
    activeSourceCount: 2
  },
  {
    id: 'conn-postgres',
    name: 'PostgreSQL Audit Engine',
    category: 'DATABASE',
    description: 'PGAudit SQL telemetry, privilege escalations, bulk data exports, and unauthorized table scans.',
    version: 'v2.0.0',
    supportedProtocols: ['TCP / TLS Direct', 'Logstash Pipe'],
    icon: 'Database',
    activeSourceCount: 1
  }
];

export const INITIAL_SOURCES: SourceInstance[] = [
  {
    humanId: 'SRC-01',
    internalUuid: 'src-89a10fc2-4889-4b6e-b31c-7f551b802a41',
    name: 'Production NGINX Gateway',
    description: 'Primary customer-facing reverse proxy and auth ingress cluster.',
    capabilityId: '',
    capabilityName: '',
    capabilityVersion: null,
    mappingProfileId: null,
    capabilityBindingStatus: 'requires_verification',
    capabilityBoundAt: null,
    lifecycleState: 'enabled',
    tokenIssuable: false,
    endpoint: 'https://telemetry.proshield.internal/ingest/v1/nginx-prod',
    tags: ['production', 'web', 'auth-tier', 'dmz'],
    status: 'ENABLED',
    validationState: 'VALID',
    ingestToken: '',
    tokenCreated: '2026-03-01 08:30:00 UTC',
    eventsPerSec: 1420,
    lastActivity: '3 seconds ago',
    metrics: {
      totalEvents24h: 122840900,
      detections24h: 38,
      latencyMs: 14
    }
  },
  {
    humanId: 'SRC-02',
    internalUuid: 'src-29b44aa1-7102-4c22-9df4-0c2188fa90ee',
    name: 'Staging NGINX Gateway',
    description: 'Pre-production staging cluster for release validation.',
    capabilityId: '',
    capabilityName: '',
    capabilityVersion: null,
    mappingProfileId: null,
    capabilityBindingStatus: 'requires_verification',
    capabilityBoundAt: null,
    lifecycleState: 'enabled',
    tokenIssuable: false,
    endpoint: 'https://telemetry.proshield.internal/ingest/v1/nginx-stage',
    tags: ['staging', 'web', 'test-env'],
    status: 'ENABLED',
    validationState: 'VALID',
    ingestToken: '',
    tokenCreated: '2026-03-10 11:20:00 UTC',
    eventsPerSec: 85,
    lastActivity: '12 seconds ago',
    metrics: {
      totalEvents24h: 7340000,
      detections24h: 2,
      latencyMs: 18
    }
  },
  {
    humanId: 'SRC-03',
    internalUuid: 'src-ff038ba9-0931-419b-a320-1e5f88410290',
    name: 'Okta Enterprise SSO',
    description: 'Corporate employee identity, SAML federations, and MFA challenge stream.',
    capabilityId: '',
    capabilityName: '',
    capabilityVersion: null,
    mappingProfileId: null,
    capabilityBindingStatus: 'requires_verification',
    capabilityBoundAt: null,
    lifecycleState: 'enabled',
    tokenIssuable: false,
    endpoint: 'https://telemetry.proshield.internal/ingest/v1/okta-corp',
    tags: ['corp', 'identity', 'sso', 'mfa'],
    status: 'ENABLED',
    validationState: 'VALID',
    ingestToken: '',
    tokenCreated: '2026-02-15 14:00:00 UTC',
    eventsPerSec: 320,
    lastActivity: '1 second ago',
    metrics: {
      totalEvents24h: 27600000,
      detections24h: 14,
      latencyMs: 22
    }
  },
  {
    humanId: 'SRC-04',
    internalUuid: 'src-5510abcd-3389-4911-a889-aa110948b812',
    name: 'AWS CloudTrail Production',
    description: 'US-East-1 and EU-Central-1 production management events and API calls.',
    capabilityId: '',
    capabilityName: '',
    capabilityVersion: null,
    mappingProfileId: null,
    capabilityBindingStatus: 'requires_verification',
    capabilityBoundAt: null,
    lifecycleState: 'enabled',
    tokenIssuable: false,
    endpoint: 'https://telemetry.proshield.internal/ingest/v1/aws-prod',
    tags: ['cloud', 'aws', 'infrastructure', 'audit'],
    status: 'ENABLED',
    validationState: 'VALID',
    ingestToken: '',
    tokenCreated: '2026-01-20 09:00:00 UTC',
    eventsPerSec: 2100,
    lastActivity: 'Just now',
    metrics: {
      totalEvents24h: 181440000,
      detections24h: 22,
      latencyMs: 9
    }
  },
  {
    humanId: 'SRC-05',
    internalUuid: 'src-781190bc-44aa-4902-88ef-910293847566',
    name: 'Falcon EDR Workstation Fleet',
    description: 'Global engineering and operations workstation process telemetry.',
    capabilityId: '',
    capabilityName: '',
    capabilityVersion: null,
    mappingProfileId: null,
    capabilityBindingStatus: 'requires_verification',
    capabilityBoundAt: null,
    lifecycleState: 'enabled',
    tokenIssuable: false,
    endpoint: 'https://telemetry.proshield.internal/ingest/v1/crowdstrike-fleet',
    tags: ['endpoints', 'edr', 'macos', 'windows', 'linux'],
    status: 'WARNING' as any, // Warning due to buffer lag
    validationState: 'VALID',
    ingestToken: '',
    tokenCreated: '2026-02-01 10:00:00 UTC',
    eventsPerSec: 3890,
    lastActivity: '45 seconds ago',
    errorDetails: {
      code: 429,
      message: 'Ingest buffer backlog exceeded 85% capacity for agent sub-cluster #4',
      suggestion: 'Increase buffer partitions or verify agent egress rate limiters.',
      timestamp: '2026-03-30 08:42:15 UTC'
    },
    metrics: {
      totalEvents24h: 336000000,
      detections24h: 19,
      latencyMs: 142
    }
  }
];

export const INITIAL_RULES: Rule[] = [
  {
    humanId: 'RULE-01',
    internalUuid: 'rule-0189fa99-338b-4991-884c-389100fae001',
    name: 'Repeated NGINX Authentication Failure',
    description: 'Detects rapid repeated 401/403 HTTP status responses from a single IP targeting login endpoints.',
    severity: 'HIGH',
    capabilityId: '',
    capabilityName: '',
    scope: ['SRC-01', 'SRC-02'],
    dslType: 'SIGMA',
    logicCode: `title: Repeated NGINX Authentication Failure
status: production
logsource:
  category: webserver
  product: nginx
detection:
  selection:
    http_status: [401, 403]
    uri_path|contains: ['/api/v1/auth/login', '/oauth/token', '/admin/login']
  timeframe: 2m
  condition: selection | count() > 15 by client_ip
level: high`,
    lifecycleStatus: 'ACTIVE',
    lastModified: '2026-03-15 14:20:00 UTC',
    affectedDetectionsCount: 42,
    author: 'Elena Vance (Lead Threat Eng)',
    thresholds: { count: 15, timeframeSec: 120 }
  },
  {
    humanId: 'RULE-02',
    internalUuid: 'rule-0288fa11-449b-4112-990a-110022334455',
    name: 'Okta Impossible Travel & Session Hijack',
    description: 'Flags successful Okta authentications from two geographically incompatible regions within 45 minutes.',
    severity: 'CRITICAL',
    capabilityId: '',
    capabilityName: '',
    scope: ['SRC-03'],
    dslType: 'CEL',
    logicCode: `rule "okta_impossible_travel" {
  events:
    $e1.type == "user.authentication.auth_via_mfa" &&
    $e2.type == "user.authentication.auth_via_mfa" &&
    $e1.user_id == $e2.user_id &&
    geo_distance($e1.ip_location, $e2.ip_location) > 1200km &&
    time_diff($e1.timestamp, $e2.timestamp) < duration("45m")
  condition:
    $e1 and $e2
}`,
    lifecycleStatus: 'ACTIVE',
    lastModified: '2026-03-22 09:15:00 UTC',
    affectedDetectionsCount: 9,
    author: 'Marcus Brody (SecOps Eng)',
    thresholds: { count: 2, timeframeSec: 2700 }
  },
  {
    humanId: 'RULE-03',
    internalUuid: 'rule-0377aa22-550c-4882-aa33-889900112233',
    name: 'AWS CloudTrail Unauthorized IAM Role Assumption',
    description: 'Monitors AssumeRole API calls targeting high-privilege Admin roles from unapproved VPC CIDRs.',
    severity: 'HIGH',
    capabilityId: '',
    capabilityName: '',
    scope: ['SRC-04'],
    dslType: 'SIGMA',
    logicCode: `title: Unauthorized IAM Role Assumption
status: production
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: 'AssumeRole'
    requestParameters.roleArn|contains: ['arn:aws:iam::*:role/AdminRole', 'arn:aws:iam::*:role/SecOpsBreakGlass']
  filter:
    sourceIPAddress|cidr: ['10.0.0.0/8', '172.16.0.0/12']
  condition: selection and not filter
level: high`,
    lifecycleStatus: 'ACTIVE',
    lastModified: '2026-03-18 16:40:00 UTC',
    affectedDetectionsCount: 14,
    author: 'Devon Hayes (Cloud Security)',
    thresholds: { count: 1, timeframeSec: 60 }
  },
  {
    humanId: 'RULE-04',
    internalUuid: 'rule-0466bb33-661d-4773-bb44-990011223344',
    name: 'Endpoint Ransomware Shadow Copy Deletion',
    description: 'Detects vssadmin or wmic utility commands attempting to purge Volume Shadow Copies on endpoints.',
    severity: 'CRITICAL',
    capabilityId: '',
    capabilityName: '',
    scope: ['SRC-05'],
    dslType: 'YARA_L',
    logicCode: `rule ransomware_shadowcopy_delete {
  meta:
    mitre_tactic = "TA0040 Impact"
    mitre_technique = "T1490 Inhibit System Recovery"
  events:
    $p.process.file.name = "vssadmin.exe" or $p.process.file.name = "wmic.exe"
    $p.process.command_line = /delete\\s+shadows/ nocase or $p.process.command_line = /shadowcopy\\s+delete/ nocase
  condition:
    $p
}`,
    lifecycleStatus: 'ACTIVE',
    lastModified: '2026-03-25 11:10:00 UTC',
    affectedDetectionsCount: 4,
    author: 'Elena Vance (Lead Threat Eng)',
    thresholds: { count: 1, timeframeSec: 30 }
  },
  {
    humanId: 'RULE-05',
    internalUuid: 'rule-0555cc44-772e-4664-cc55-001122334455',
    name: 'High Frequency DNS Tunneling Queries',
    description: 'Detects excessive high-entropy TXT/NULL record lookups to anomalous dynamic DNS zones.',
    severity: 'HIGH',
    capabilityId: '',
    capabilityName: '',
    scope: ['SRC-01', 'SRC-04'],
    dslType: 'SIGMA',
    logicCode: `title: High Frequency DNS Tunneling Queries
status: production
logsource:
  category: dns
detection:
  selection:
    query_type: ['TXT', 'NULL']
    query_name_length|gt: 65
  timeframe: 1m
  condition: selection | count() > 50 by source_ip
level: high`,
    lifecycleStatus: 'ACTIVE',
    lastModified: '2026-03-10 13:00:00 UTC',
    affectedDetectionsCount: 18,
    author: 'Marcus Brody (SecOps Eng)',
    thresholds: { count: 50, timeframeSec: 60 }
  },
  {
    humanId: 'RULE-06',
    internalUuid: 'rule-0644dd55-883f-4555-dd66-112233445566',
    name: 'Mass PostgreSQL Data Exfiltration Query',
    description: 'Detects SELECT queries extracting greater than 100,000 sensitive records without an indexed WHERE clause.',
    severity: 'MEDIUM',
    capabilityId: '',
    capabilityName: '',
    scope: [],
    dslType: 'CEL',
    logicCode: `rule "mass_db_dump" {
  events:
    $sql.statement_type == "SELECT" &&
    $sql.rows_returned > 100000 &&
    $sql.target_table in ["users", "credit_cards", "auth_tokens"]
  condition:
    $sql
}`,
    lifecycleStatus: 'TESTING',
    lastModified: '2026-03-28 17:55:00 UTC',
    affectedDetectionsCount: 1,
    author: 'Devon Hayes (Cloud Security)',
    thresholds: { count: 1, timeframeSec: 60 }
  }
];

export const INITIAL_CASES: Case[] = [
  {
    humanId: 'CASE-01',
    internalUuid: 'case-04861cab-8f92-4911-b4fa-6c1e95b058fe',
    title: 'Brute-Force Authentication Attack & Password Spray',
    description: 'Distributed credential stuffing campaign against NGINX auth gateway followed by successful lateral credential assumption.',
    severity: 'HIGH',
    status: 'OPEN',
    sourceId: 'SRC-01',
    sourceName: 'Production NGINX Gateway',
    attackerIp: '203.0.113.42',
    attackerCountry: 'RU (Autonomous System AS14061)',
    attackerHost: 'host-203-0-113-42.tor-exit.net',
    targetAsset: 'auth.proshield.corp (Production Gateway)',
    targetUser: 'admin@proshield.corp',
    firstSeen: '2026-03-30 06:14:22 UTC',
    lastSeen: '2026-03-30 08:31:05 UTC',
    eventCount: 384,
    detectionCount: 18,
    correlationCount: 1,
    mitreTactics: ['TA0006 Credential Access', 'TA0001 Initial Access', 'TA0008 Lateral Movement'],
    assignedAnalyst: {
      name: 'Sarah Chen',
      avatar: 'SC',
      role: 'Senior SOC Analyst'
    },
    isCorrelated: true,
    centralizedAnalysisDone: false,
    notes: [
      {
        id: 'note-1',
        author: 'Sarah Chen',
        timestamp: '2026-03-30 07:15:00 UTC',
        text: 'Initial triage complete. Source IP 203.0.113.42 observed rotating User-Agents with Python-urllib/3.11 fingerprint. Blocking IP at edge firewall.'
      },
      {
        id: 'note-2',
        author: 'Sarah Chen',
        timestamp: '2026-03-30 08:02:00 UTC',
        text: 'Correlation CORR-01 indicates 3 distinct sub-bursts over a 90-minute sliding window.'
      }
    ]
  },
  {
    humanId: 'CASE-02',
    internalUuid: 'case-1122aaff-7711-4091-a110-880099112233',
    title: 'Impossible Travel & IAM PrivEsc Attempt',
    description: 'Single user account authenticated in San Francisco and Frankfurt within 12 minutes, then invoked IAM PutUserPolicy.',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    sourceId: 'SRC-03',
    sourceName: 'Okta Enterprise SSO',
    attackerIp: '198.51.100.89',
    attackerCountry: 'DE (Hetzner Cloud)',
    attackerHost: 'fra-node-89.vpn.services',
    targetAsset: 'iam.aws.proshield.internal',
    targetUser: 'd.morrison@proshield.corp (DevOps Lead)',
    firstSeen: '2026-03-30 05:40:11 UTC',
    lastSeen: '2026-03-30 07:50:20 UTC',
    eventCount: 42,
    detectionCount: 6,
    correlationCount: 1,
    mitreTactics: ['TA0004 Privilege Escalation', 'TA0005 Defense Evasion'],
    assignedAnalyst: {
      name: 'Marcus Brody',
      avatar: 'MB',
      role: 'SecOps Engineer'
    },
    isCorrelated: true,
    centralizedAnalysisDone: true,
    notes: [
      {
        id: 'note-1',
        author: 'Marcus Brody',
        timestamp: '2026-03-30 06:00:00 UTC',
        text: 'User contacted via Slack emergency pager. User confirms they are in California and did not execute the German login.'
      },
      {
        id: 'note-2',
        author: 'Marcus Brody',
        timestamp: '2026-03-30 06:18:00 UTC',
        text: 'Okta sessions terminated. AWS IAM access key rotated.'
      }
    ]
  },
  {
    humanId: 'CASE-03',
    internalUuid: 'case-3344bbcc-9922-4112-b221-991100223344',
    title: 'DNS Tunneling Telemetry Exfiltration',
    description: 'Subdomain generation algorithm detected transmitting encrypted payloads encoded in TXT queries.',
    severity: 'HIGH',
    status: 'ACKNOWLEDGED',
    sourceId: 'SRC-04',
    sourceName: 'AWS CloudTrail Production',
    attackerIp: '185.220.101.5',
    attackerCountry: 'NL (Exit Relay)',
    targetAsset: 'ip-10-0-4-192.ec2.internal (Data Worker)',
    firstSeen: '2026-03-30 03:22:00 UTC',
    lastSeen: '2026-03-30 06:45:00 UTC',
    eventCount: 1290,
    detectionCount: 12,
    correlationCount: 1,
    mitreTactics: ['TA0010 Exfiltration', 'TA0011 Command and Control'],
    assignedAnalyst: {
      name: 'Sarah Chen',
      avatar: 'SC',
      role: 'Senior SOC Analyst'
    },
    isCorrelated: true,
    centralizedAnalysisDone: false,
    notes: []
  },
  {
    humanId: 'CASE-04',
    internalUuid: 'case-5566ccdd-1133-4223-c332-002211334455',
    title: 'Shadow Copy Deletion & Ransomware Activity',
    description: 'Endpoint execution of vssadmin delete shadows on engineering workstation WS-CORP-9142.',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    sourceId: 'SRC-05',
    sourceName: 'Falcon EDR Workstation Fleet',
    attackerIp: '10.14.88.22',
    attackerCountry: 'US (Internal Subnet)',
    targetAsset: 'WS-CORP-9142.corp.proshield.internal',
    targetUser: 't.alvarez@proshield.corp',
    firstSeen: '2026-03-30 08:10:00 UTC',
    lastSeen: '2026-03-30 08:35:14 UTC',
    eventCount: 18,
    detectionCount: 4,
    correlationCount: 1,
    mitreTactics: ['TA0040 Impact', 'TA0002 Execution'],
    assignedAnalyst: {
      name: 'Elena Vance',
      avatar: 'EV',
      role: 'Lead Threat Engineer'
    },
    isCorrelated: true,
    centralizedAnalysisDone: false,
    notes: [
      {
        id: 'note-1',
        author: 'Elena Vance',
        timestamp: '2026-03-30 08:15:00 UTC',
        text: 'Host network isolated immediately via CrowdStrike Falcon containment policy.'
      }
    ]
  },
  {
    humanId: 'CASE-05',
    internalUuid: 'case-7788ddee-3355-4445-e554-224433556677',
    title: 'Mass Data Extraction Query on Customers Table',
    description: 'PostgreSQL read operation fetched 420,000 records outside normal business ETL schedule.',
    severity: 'MEDIUM',
    status: 'OPEN',
    sourceId: 'SRC-04',
    sourceName: 'AWS CloudTrail Production',
    attackerIp: '10.0.12.90',
    attackerCountry: 'US (Private VPC)',
    targetAsset: 'rds-prod-primary.db.internal',
    targetUser: 'svc_analytics_etl',
    firstSeen: '2026-03-30 01:10:00 UTC',
    lastSeen: '2026-03-30 01:45:00 UTC',
    eventCount: 95,
    detectionCount: 2,
    correlationCount: 0,
    mitreTactics: ['TA0009 Collection'],
    isCorrelated: false,
    centralizedAnalysisDone: false,
    notes: []
  },
  {
    humanId: 'CASE-06',
    internalUuid: 'case-9900eeff-5577-4667-f776-446655778899',
    title: 'Suspicious CloudTrail S3 Bucket ACL Enumeration',
    description: 'Rapid ListBuckets and GetBucketAcl reconnaissance API calls from temporary STS credential.',
    severity: 'LOW',
    status: 'OPEN',
    sourceId: 'SRC-04',
    sourceName: 'AWS CloudTrail Production',
    attackerIp: '54.210.88.19',
    attackerCountry: 'US (Amazon EC2)',
    targetAsset: 's3://proshield-customer-vault-prod',
    firstSeen: '2026-03-30 07:05:00 UTC',
    lastSeen: '2026-03-30 07:22:00 UTC',
    eventCount: 160,
    detectionCount: 3,
    correlationCount: 0,
    mitreTactics: ['TA0007 Discovery'],
    isCorrelated: false,
    centralizedAnalysisDone: false,
    notes: []
  },
  {
    humanId: 'CASE-07',
    internalUuid: 'case-aabbccdd-7799-4889-0887-668877990011',
    title: 'SQL Injection Payload on Payment Checkout API',
    description: 'Blind SQL injection test patterns observed in the order_ref parameter of checkout endpoint.',
    severity: 'HIGH',
    status: 'CLOSED',
    sourceId: 'SRC-01',
    sourceName: 'Production NGINX Gateway',
    attackerIp: '94.102.61.8',
    attackerCountry: 'SE (DigitalOcean)',
    targetAsset: 'api.proshield.corp/v1/payments/checkout',
    firstSeen: '2026-03-29 18:00:00 UTC',
    lastSeen: '2026-03-29 19:15:00 UTC',
    eventCount: 88,
    detectionCount: 5,
    correlationCount: 1,
    mitreTactics: ['TA0001 Initial Access'],
    assignedAnalyst: {
      name: 'Sarah Chen',
      avatar: 'SC',
      role: 'Senior SOC Analyst'
    },
    closureReason: 'TRUE_POSITIVE',
    closureNotes: 'WAF signature 942100 blocked all payloads. Application code verified parameterized queries. No backend database compromise.',
    closedAt: '2026-03-29 20:30:00 UTC',
    closedBy: 'Sarah Chen',
    isCorrelated: true,
    centralizedAnalysisDone: true,
    notes: []
  },
  {
    humanId: 'CASE-08',
    internalUuid: 'case-ccddee00-99bb-4001-2998-880099112244',
    title: 'Routine Bastion SSH Key Rotation (Automated)',
    description: 'Scheduled keypair rotation triggered alerting thresholds for bulk auth anomalies.',
    severity: 'INFORMATIONAL',
    status: 'CLOSED',
    sourceId: 'SRC-01',
    sourceName: 'Production NGINX Gateway',
    attackerIp: '10.0.1.5',
    attackerCountry: 'US (Internal Bastion)',
    targetAsset: 'bastion-mgmt-01.corp.proshield.internal',
    firstSeen: '2026-03-29 12:00:00 UTC',
    lastSeen: '2026-03-29 12:05:00 UTC',
    eventCount: 12,
    detectionCount: 1,
    correlationCount: 0,
    mitreTactics: [],
    assignedAnalyst: {
      name: 'Marcus Brody',
      avatar: 'MB',
      role: 'SecOps Engineer'
    },
    closureReason: 'BENIGN_TRUE_POSITIVE',
    closureNotes: 'Verified Ansible automation playbook execution by Infrastructure team. Expected behavior.',
    closedAt: '2026-03-29 12:20:00 UTC',
    closedBy: 'Marcus Brody',
    isCorrelated: false,
    centralizedAnalysisDone: false,
    notes: []
  }
];

export const INITIAL_DETECTIONS: Detection[] = [
  {
    humanId: 'DET-01',
    internalUuid: 'det-01a1b2c3-4d5e-6f7a-8b9c-0d1e2f3a4b5c',
    title: 'Repeated Authentication Failure (Burst 1)',
    ruleId: 'RULE-01',
    ruleName: 'Repeated NGINX Authentication Failure',
    sourceId: 'SRC-01',
    sourceName: 'Production NGINX Gateway',
    severity: 'HIGH',
    timestamp: '2026-03-30 06:14:22 UTC',
    firstSeen: '2026-03-30 06:14:00 UTC',
    lastSeen: '2026-03-30 06:16:22 UTC',
    evidenceSummary: '82 failed HTTP POST requests to /api/v1/auth/login returning 401 within 140s from 203.0.113.42',
    attackerIp: '203.0.113.42',
    targetAsset: 'auth.proshield.corp',
    caseId: 'CASE-01',
    correlationId: 'CORR-01',
    matchedFields: [
      { field: 'client_ip', value: '203.0.113.42' },
      { field: 'http_status', value: '401 Unauthorized' },
      { field: 'uri_path', value: '/api/v1/auth/login' },
      { field: 'request_count', value: '82' }
    ],
    rawPayload: {
      source: 'nginx-access-prod',
      client_ip: '203.0.113.42',
      http_method: 'POST',
      request_uri: '/api/v1/auth/login',
      status: 401,
      user_agent: 'Python-urllib/3.11',
      ssl_protocol: 'TLSv1.3',
      upstream_connect_time: '0.002',
      asn: 14061,
      country_iso: 'RU'
    }
  },
  {
    humanId: 'DET-02',
    internalUuid: 'det-02b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d',
    title: 'Repeated Authentication Failure (Burst 2 - Distributed Agent)',
    ruleId: 'RULE-01',
    ruleName: 'Repeated NGINX Authentication Failure',
    sourceId: 'SRC-01',
    sourceName: 'Production NGINX Gateway',
    severity: 'HIGH',
    timestamp: '2026-03-30 07:02:18 UTC',
    firstSeen: '2026-03-30 07:00:00 UTC',
    lastSeen: '2026-03-30 07:04:18 UTC',
    evidenceSummary: '115 failed login attempts with varied User-Agent headers including curl/7.88.1 and Mozilla/5.0 spoofing.',
    attackerIp: '203.0.113.42',
    targetAsset: 'auth.proshield.corp',
    caseId: 'CASE-01',
    correlationId: 'CORR-01',
    matchedFields: [
      { field: 'client_ip', value: '203.0.113.42' },
      { field: 'http_status', value: '401' },
      { field: 'failure_burst', value: '115 in 4 mins' }
    ],
    rawPayload: {
      source: 'nginx-access-prod',
      client_ip: '203.0.113.42',
      target_endpoint: '/oauth/token',
      http_status: 401,
      burst_size: 115,
      correlation_key: 'src_ip_rate_window'
    }
  },
  {
    humanId: 'DET-03',
    internalUuid: 'det-03c3d4e5-6f7a-8b9c-0d1e-2f3a4b5c6d7e',
    title: 'Targeted Administrative Account Password Spray',
    ruleId: 'RULE-01',
    ruleName: 'Repeated NGINX Authentication Failure',
    sourceId: 'SRC-01',
    sourceName: 'Production NGINX Gateway',
    severity: 'HIGH',
    timestamp: '2026-03-30 08:30:10 UTC',
    firstSeen: '2026-03-30 08:28:00 UTC',
    lastSeen: '2026-03-30 08:31:05 UTC',
    evidenceSummary: '187 sequential password attempts against admin@proshield.corp and root@proshield.corp.',
    attackerIp: '203.0.113.42',
    targetAsset: 'auth.proshield.corp',
    caseId: 'CASE-01',
    correlationId: 'CORR-01',
    matchedFields: [
      { field: 'target_account', value: 'admin@proshield.corp' },
      { field: 'spray_velocity', value: '1.2 attempts/sec' }
    ],
    rawPayload: {
      source: 'nginx-access-prod',
      targeted_users: ['admin@proshield.corp', 'secops@proshield.corp', 'root@proshield.corp'],
      attempts_total: 187
    }
  },
  {
    humanId: 'DET-04',
    internalUuid: 'det-04d4e5f6-7a8b-9c0d-1e2f-3a4b5c6d7e8f',
    title: 'Okta Geographically Incompatible MFA Challenge',
    ruleId: 'RULE-02',
    ruleName: 'Okta Impossible Travel & Session Hijack',
    sourceId: 'SRC-03',
    sourceName: 'Okta Enterprise SSO',
    severity: 'CRITICAL',
    timestamp: '2026-03-30 05:40:11 UTC',
    firstSeen: '2026-03-30 05:40:11 UTC',
    lastSeen: '2026-03-30 05:42:00 UTC',
    evidenceSummary: 'Successful MFA push received from Frankfurt (DE) 12 minutes after San Francisco (US) session active.',
    attackerIp: '198.51.100.89',
    targetAsset: 'Okta IAM SSO',
    caseId: 'CASE-02',
    correlationId: 'CORR-02',
    matchedFields: [
      { field: 'user_id', value: 'd.morrison@proshield.corp' },
      { field: 'origin_1', value: 'San Francisco, CA (US)' },
      { field: 'origin_2', value: 'Frankfurt, HE (DE)' },
      { field: 'delta_minutes', value: '12' }
    ],
    rawPayload: {
      event_type: 'user.authentication.auth_via_mfa',
      user: 'd.morrison@proshield.corp',
      geo: { origin: 'US-CA', new_origin: 'DE-HE', distance_km: 9140 },
      mfa_method: 'OKTA_VERIFY_PUSH'
    }
  },
  {
    humanId: 'DET-05',
    internalUuid: 'det-05e5f6a7-8b9c-0d1e-2f3a-4b5c6d7e8f90',
    title: 'AWS CloudTrail PutUserPolicy Admin Escalation',
    ruleId: 'RULE-03',
    ruleName: 'AWS CloudTrail Unauthorized IAM Role Assumption',
    sourceId: 'SRC-04',
    sourceName: 'AWS CloudTrail Production',
    severity: 'CRITICAL',
    timestamp: '2026-03-30 05:48:22 UTC',
    firstSeen: '2026-03-30 05:48:22 UTC',
    lastSeen: '2026-03-30 05:48:22 UTC',
    evidenceSummary: 'API call iam:PutUserPolicy executed attaching AdministratorAccess inline policy to d.morrison.',
    attackerIp: '198.51.100.89',
    targetAsset: 'arn:aws:iam::112233445566:user/d.morrison',
    caseId: 'CASE-02',
    correlationId: 'CORR-02',
    matchedFields: [
      { field: 'eventName', value: 'PutUserPolicy' },
      { field: 'policyName', value: 'SecOpsEmergencyAdmin' },
      { field: 'principal', value: 'd.morrison' }
    ],
    rawPayload: {
      aws_account_id: '112233445566',
      eventName: 'PutUserPolicy',
      policyDocument: '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
      sourceIPAddress: '198.51.100.89'
    }
  },
  {
    humanId: 'DET-06',
    internalUuid: 'det-06f6a7b8-9c0d-1e2f-3a4b-5c6d7e8f9012',
    title: 'vssadmin Shadow Copy Purge Execution',
    ruleId: 'RULE-04',
    ruleName: 'Endpoint Ransomware Shadow Copy Deletion',
    sourceId: 'SRC-05',
    sourceName: 'Falcon EDR Workstation Fleet',
    severity: 'CRITICAL',
    timestamp: '2026-03-30 08:10:00 UTC',
    firstSeen: '2026-03-30 08:10:00 UTC',
    lastSeen: '2026-03-30 08:10:05 UTC',
    evidenceSummary: 'Process vssadmin.exe executed with args: delete shadows /all /quiet by parent powershell.exe',
    attackerIp: '10.14.88.22',
    targetAsset: 'WS-CORP-9142',
    caseId: 'CASE-04',
    correlationId: 'CORR-04',
    matchedFields: [
      { field: 'process', value: 'vssadmin.exe' },
      { field: 'command_line', value: 'vssadmin.exe delete shadows /all /quiet' },
      { field: 'parent_process', value: 'powershell.exe -enc SQBFAFgA...' }
    ],
    rawPayload: {
      host: 'WS-CORP-9142.corp.proshield.internal',
      user: 't.alvarez',
      process_id: 8192,
      command_line: 'vssadmin.exe delete shadows /all /quiet',
      mitre_technique: 'T1490'
    }
  }
];

export const INITIAL_CORRELATIONS: Correlation[] = [
  {
    humanId: 'CORR-01',
    internalUuid: 'corr-0199aabb-1122-3344-5566-778899aabbcc',
    title: 'Multi-Burst NGINX Credential Spray Cluster',
    pattern: 'Distributed High-Frequency HTTP Auth Rejection Pattern with User-Agent Mutation',
    severity: 'HIGH',
    sourceId: 'SRC-01',
    sourceName: 'Production NGINX Gateway',
    attacker: '203.0.113.42 (Autonomous System AS14061 RU)',
    target: 'auth.proshield.corp / NGINX Gateway',
    timeWindow: '2h 17m (Sliding Window)',
    detectionCount: 3,
    eventCount: 384,
    detectionIds: ['DET-01', 'DET-02', 'DET-03'],
    caseId: 'CASE-01',
    description: 'Autonomous correlation engine identified 3 distinct authentication failure bursts converging on admin-level endpoints with coordinated IP persistence.',
    confidenceScore: 94,
    confidenceBand: null,    centralizedAnalysisRan: false,
    crossSourceRelationships: [
      {
        source: 'SRC-01 (NGINX Access)',
        target: 'Gateway Auth Subsystem',
        relation: 'Inbound HTTP POST 401 Flooding'
      },
      {
        source: '203.0.113.42',
        target: 'admin@proshield.corp',
        relation: 'Targeted Password Guessing Payload'
      }
    ]
  },
  {
    humanId: 'CORR-02',
    internalUuid: 'corr-02aabbcc-2233-4455-6677-8899aabbccdd',
    title: 'Cloud Identity Takeover & Privileged Policy Attachment',
    pattern: 'Impossible Travel Sequence followed by Instant AWS IAM PutUserPolicy Execution',
    severity: 'CRITICAL',
    sourceId: 'SRC-03',
    sourceName: 'Okta Enterprise SSO',
    attacker: '198.51.100.89 (DE VPN)',
    target: 'AWS IAM AdministratorAccess (d.morrison)',
    timeWindow: '18m 11s',
    detectionCount: 2,
    eventCount: 42,
    detectionIds: ['DET-04', 'DET-05'],
    caseId: 'CASE-02',
    description: 'Cross-source correlation linked an anomalous German Okta login with an immediate AWS CloudTrail administrative policy injection within 8 minutes.',
    confidenceScore: 98,
    confidenceBand: null,    centralizedAnalysisRan: true,
    crossSourceRelationships: [
      {
        source: 'SRC-03 (Okta SSO)',
        target: 'SRC-04 (AWS CloudTrail)',
        relation: 'SAML Token Exchange to AWS IAM Session'
      },
      {
        source: '198.51.100.89',
        target: 'arn:aws:iam::*:user/d.morrison',
        relation: 'PutUserPolicy AdministratorAccess Injection'
      }
    ]
  },
  {
    humanId: 'CORR-03',
    internalUuid: 'corr-03bbccdd-3344-5566-7788-99aabbccddee',
    title: 'DNS Tunneling Covert Channel Exfiltration Chain',
    pattern: 'High-Entropy TXT Record Query Burst Matching Subdomain Staging',
    severity: 'HIGH',
    sourceId: 'SRC-04',
    sourceName: 'AWS CloudTrail Production',
    attacker: '185.220.101.5 (Tor Relay)',
    target: 'ip-10-0-4-192.ec2.internal',
    timeWindow: '3h 23m',
    detectionCount: 2,
    eventCount: 1290,
    detectionIds: [],
    caseId: 'CASE-03',
    description: 'Suricata DNS telemetry matched 1200+ oversized TXT queries resolving to dynamic NS servers, indicating base64 encoded exfiltration.',
    confidenceScore: 89,
    confidenceBand: null,    centralizedAnalysisRan: false,
    crossSourceRelationships: [
      {
        source: 'SRC-04 (AWS VPC DNS)',
        target: 'External Dynamic Nameserver',
        relation: 'Covert Channel Data Exfiltration'
      }
    ]
  },
  {
    humanId: 'CORR-04',
    internalUuid: 'corr-04ccddeeff-4455-6677-8899-aabbccddeeff',
    title: 'Pre-Ransomware Inhibited Recovery Chain',
    pattern: 'Shadow Copy Purge + Disable Windows Recovery Console Command Chain',
    severity: 'CRITICAL',
    sourceId: 'SRC-05',
    sourceName: 'Falcon EDR Workstation Fleet',
    attacker: '10.14.88.22 (WS-CORP-9142)',
    target: 'Local Volume Storage & Backup Catalog',
    timeWindow: '2m 14s',
    detectionCount: 1,
    eventCount: 18,
    detectionIds: ['DET-06'],
    caseId: 'CASE-04',
    description: 'Endpoint telemetry correlation confirmed automated script sequence executing vssadmin purge followed by bcdedit recovery disabling.',
    confidenceScore: 99,
    confidenceBand: null,    centralizedAnalysisRan: false,
    crossSourceRelationships: [
      {
        source: 'SRC-05 (Falcon Agent)',
        target: 'Local Windows VSS Subsystem',
        relation: 'Malicious Deletion of System Restore Points'
      }
    ]
  }
];

export const INITIAL_TIMELINE: TimelineEvent[] = [
  {
    id: 'time-01',
    humanId: 'CASE-01',
    timestamp: '2026-03-30 08:35:10 UTC',
    type: 'CASE_ACTION',
    title: 'Edge IP Filter Policy Applied',
    severity: 'HIGH',
    sourceName: 'Production NGINX Gateway',
    shortExplanation: 'Analyst Sarah Chen applied temporary IP drop rule for 203.0.113.42 at edge firewall layer.',
    actor: 'Sarah Chen (SOC Analyst)'
  },
  {
    id: 'time-02',
    humanId: 'CORR-01',
    timestamp: '2026-03-30 08:31:05 UTC',
    type: 'CORRELATION',
    title: 'Correlation CORR-01 Synthesized',
    severity: 'HIGH',
    sourceName: 'ProShield Correlation Engine',
    shortExplanation: 'Correlated 3 authentication failure bursts into multi-stage credential spray attack pattern.',
    caseId: 'CASE-01'
  },
  {
    id: 'time-03',
    humanId: 'DET-03',
    timestamp: '2026-03-30 08:30:10 UTC',
    type: 'DETECTION',
    title: 'Targeted Administrative Account Password Spray Triggered',
    severity: 'HIGH',
    sourceName: 'Production NGINX Gateway',
    shortExplanation: 'Rule RULE-01 matched 187 attempts targeting admin@proshield.corp.',
    caseId: 'CASE-01',
    mitreTechnique: 'T1110.003 Password Spraying'
  },
  {
    id: 'time-04',
    timestamp: '2026-03-30 08:29:44 UTC',
    type: 'EVENT',
    title: 'HTTP 401 Response on /api/v1/auth/login',
    severity: 'LOW',
    sourceName: 'Production NGINX Gateway',
    shortExplanation: 'POST /api/v1/auth/login user=admin status=401 user_agent="Python-urllib/3.11"',
    caseId: 'CASE-01'
  },
  {
    id: 'time-05',
    humanId: 'CASE-04',
    timestamp: '2026-03-30 08:15:00 UTC',
    type: 'ANALYST_NOTE',
    title: 'Host Network Isolated',
    severity: 'CRITICAL',
    sourceName: 'Falcon EDR Workstation Fleet',
    shortExplanation: 'Elena Vance contained endpoint WS-CORP-9142 via Falcon API.',
    actor: 'Elena Vance (Lead Threat Eng)'
  },
  {
    id: 'time-06',
    humanId: 'DET-06',
    timestamp: '2026-03-30 08:10:00 UTC',
    type: 'DETECTION',
    title: 'vssadmin Shadow Copy Purge Execution',
    severity: 'CRITICAL',
    sourceName: 'Falcon EDR Workstation Fleet',
    shortExplanation: 'Rule RULE-04 matched command: vssadmin.exe delete shadows /all /quiet.',
    caseId: 'CASE-04',
    mitreTechnique: 'T1490 Inhibit System Recovery'
  },
  {
    id: 'time-07',
    humanId: 'CASE-02',
    timestamp: '2026-03-30 06:18:00 UTC',
    type: 'CASE_ACTION',
    title: 'Okta Session Revoked & AWS Credential Purged',
    severity: 'CRITICAL',
    sourceName: 'Okta Enterprise SSO',
    shortExplanation: 'Marcus Brody revoked all active Okta sessions for d.morrison.',
    actor: 'Marcus Brody (SecOps Eng)'
  },
  {
    id: 'time-08',
    humanId: 'DET-05',
    timestamp: '2026-03-30 05:48:22 UTC',
    type: 'DETECTION',
    title: 'AWS CloudTrail PutUserPolicy Admin Escalation',
    severity: 'CRITICAL',
    sourceName: 'AWS CloudTrail Production',
    shortExplanation: 'Rule RULE-03 matched inline policy AdministratorAccess attachment.',
    caseId: 'CASE-02',
    mitreTechnique: 'T1098 Account Manipulation'
  },
  {
    id: 'time-09',
    humanId: 'DET-04',
    timestamp: '2026-03-30 05:40:11 UTC',
    type: 'DETECTION',
    title: 'Okta Geographically Incompatible MFA Challenge',
    severity: 'CRITICAL',
    sourceName: 'Okta Enterprise SSO',
    shortExplanation: 'Rule RULE-02 matched Frankfurt login 12m after San Francisco login.',
    caseId: 'CASE-02',
    mitreTechnique: 'T1078 Valid Accounts'
  }
];

export const INITIAL_HEALTH: HealthSubsystem[] = [
  {
    id: 'sub-core',
    name: 'Platform Core & State Coordinator',
    category: 'PROCESSING',
    status: 'HEALTHY',
    latencyMs: 4,
    throughput: '42.8k ops/s',
    uptime: '99.99%',
    lastTested: 'Just now'
  },
  {
    id: 'sub-ingress',
    name: 'Real-time Ingress Pipeline (Vector / HEC)',
    category: 'INGEST',
    status: 'HEALTHY',
    latencyMs: 12,
    throughput: '8,420 events/s',
    uptime: '99.98%',
    lastTested: 'Just now'
  },
  {
    id: 'sub-analyst-api',
    name: 'Analyst GraphQL & REST API Gateway',
    category: 'API',
    status: 'HEALTHY',
    latencyMs: 18,
    throughput: '340 req/s',
    uptime: '100.0%',
    lastTested: 'Just now'
  },
  {
    id: 'sub-db',
    name: 'Telemetry Store & Search Cluster (ClickHouse / Mongo)',
    category: 'STORAGE',
    status: 'HEALTHY',
    latencyMs: 9,
    throughput: '14.2 GB/h',
    uptime: '99.99%',
    lastTested: '1 min ago'
  },
  {
    id: 'sub-sources',
    name: 'Source Connectors & Active Ingestion Feeds',
    category: 'INGEST',
    status: 'WARNING',
    latencyMs: 142,
    throughput: '5 active sources',
    uptime: '99.91%',
    whatIsWrong: 'CrowdStrike Falcon Workstation Fleet (SRC-05) agent queue buffer is at 88% capacity.',
    severityExplanation: 'High burst of process telemetry from engineering fleet caused ingestion lag of 45 seconds.',
    affectedComponents: ['SRC-05 Falcon Workstation Fleet', 'EDR Ingestion Partition #4'],
    remediationAction: 'Increase buffer partition workers or acknowledge downstream batch throttle.',
    lastTested: '45s ago'
  },
  {
    id: 'sub-rules',
    name: 'Rule Engine & Sigma/CEL Evaluation Pipeline',
    category: 'PROCESSING',
    status: 'HEALTHY',
    latencyMs: 7,
    throughput: '6 rules active',
    uptime: '100.0%',
    lastTested: 'Just now'
  },
  {
    id: 'sub-detection',
    name: 'Detection Pipeline & Stream Matcher',
    category: 'PROCESSING',
    status: 'HEALTHY',
    latencyMs: 11,
    throughput: '48 detections/hr',
    uptime: '99.98%',
    lastTested: 'Just now'
  },
  {
    id: 'sub-correlation',
    name: 'Correlation Graph & Sliding Window Synthesizer',
    category: 'ANALYTICS',
    status: 'HEALTHY',
    latencyMs: 24,
    throughput: '4 active clusters',
    uptime: '99.95%',
    lastTested: 'Just now'
  },
  {
    id: 'sub-reporting',
    name: 'Executive Reporting & Centralized Analysis Engine',
    category: 'ANALYTICS',
    status: 'HEALTHY',
    latencyMs: 32,
    throughput: 'Ready on demand',
    uptime: '100.0%',
    lastTested: '2 min ago'
  }
];

export const INITIAL_REPORTS: Report[] = [
  {
    id: 'rep-01',
    humanId: 'REPORT-01',
    title: 'Incident Summary Report: CASE-01 Brute-Force Attack',
    type: 'CASE_SUMMARY',
    caseId: 'CASE-01',
    generatedAt: '2026-03-30 08:36:00 UTC',
    author: 'Sarah Chen',
    summary: 'Comprehensive forensic summary of distributed credential stuffing attack against Production NGINX Gateway.',
    findings: [
      '384 authentication events recorded from IP 203.0.113.42 over a 2-hour sliding timeframe.',
      '3 distinct high-velocity bursts identified with automated user-agent header rotation.',
      'Targeted administrative identities admin@proshield.corp and secops@proshield.corp.',
      'Edge IP block enforced at 08:35 UTC. Zero backend database breach confirmed.'
    ],
    recommendations: [
      'Implement adaptive CAPTCHA challenge upon 3 consecutive authentication failures per IP.',
      'Enforce hardware token FIDO2/WebAuthn for all corporate administrative portals.',
      'Subscribe autonomous IP blocklist to AS14061 reputation feed.'
    ],
    mitreMatrix: ['T1110.003 Password Spraying', 'T1110.004 Credential Stuffing', 'T1595.002 Vulnerability Scanning'],
    isCentralized: false
  },
  {
    id: 'rep-02',
    humanId: 'REPORT-02',
    title: 'Centralized Multi-Source Intelligence Analysis: CASE-02 IAM Takeover',
    type: 'CENTRALIZED_ANALYSIS',
    caseId: 'CASE-02',
    generatedAt: '2026-03-30 07:55:00 UTC',
    author: 'Centralized Correlation Engine (AI + Heuristic)',
    summary: 'Cross-cloud federated correlation between Okta Identity SSO and AWS CloudTrail management logs.',
    findings: [
      'Cross-source pivot linked IP 198.51.100.89 to both Okta MFA bypass and AWS PutUserPolicy execution.',
      'Session token hijacking occurred through cookie theft rather than password compromise.',
      'Full AdministratorAccess policy remained active for 8 minutes before automated containment.',
      'CloudTrail audit verified no S3 data exfiltration or secondary IAM user creations during the compromise window.'
    ],
    recommendations: [
      'Enable Okta FastPass device-bound certificate binding to neutralize session token theft.',
      'Deploy AWS Service Control Policy (SCP) to forbid PutUserPolicy on sensitive break-glass roles.',
      'Audit all engineer workstations for browser cookie infostealer malware signatures.'
    ],
    mitreMatrix: ['T1078.004 Cloud Accounts', 'T1098 Account Manipulation', 'T1539 Steal Web Session Cookie', 'T1556 Modify Authentication Process'],
    isCentralized: true
  }
];

export const INITIAL_NOTIFICATIONS: SocNotification[] = [
  {
    id: 'notif-1',
    title: 'New High Severity Incident Created',
    description: 'CASE-01 Brute-Force Authentication Attack escalated from NGINX Gateway telemetry.',
    timestamp: '14 min ago',
    read: false,
    severity: 'HIGH',
    linkPage: 'case-detail',
    targetId: 'CASE-01'
  },
  {
    id: 'notif-2',
    title: 'Critical Impossible Travel Correlated',
    description: 'CORR-02 linked Okta login from Frankfurt with AWS IAM AdministratorAccess attempt.',
    timestamp: '42 min ago',
    read: false,
    severity: 'CRITICAL',
    linkPage: 'case-detail',
    targetId: 'CASE-02'
  },
  {
    id: 'notif-3',
    title: 'Source Ingestion Buffer Alert',
    description: 'SRC-05 Falcon Workstation Fleet buffer reached 88% capacity limit.',
    timestamp: '1 hour ago',
    read: true,
    severity: 'MEDIUM',
    linkPage: 'health',
    targetId: 'sub-sources'
  }
];
