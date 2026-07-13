export interface UserRow {
  ID: string
  Username: string
  Email: string
  Role: string
  APIKey: string
  CreatedAt: string
  UpdatedAt: string
}

export interface TargetRow {
  ID: string
  URL: string
  Domain: string
  Name: string
  Tags: string
  CreatedBy: string
  CreatedAt: string
}

export interface ScanRow {
  ID: string
  TargetID: string
  Status: string
  Modules: string
  Threads: number
  Timeout: number
  Proxy: string
  StartedAt: string
  FinishedAt: string
  DurationMs: number
  Error: string
  TriggeredBy: string
  ScheduleID: string
  CreatedAt: string
}

export interface FindingRow {
  ID: string
  ScanID: string
  TargetID: string
  ModuleID: string
  Title: string
  Severity: string
  Confidence: string
  CWEID: NullString | null
  OWASPCategory: NullString | null
  CVSS: NullFloat64 | null
  URL: NullString | null
  Parameter: NullString | null
  Payload: NullString | null
  Evidence: NullString | null
  Description: NullString | null
  Remediation: NullString | null
  Request: NullString | null
  Response: NullString | null
  Extra: NullString | null
  IsFalsePositive: boolean
  CreatedAt: string
}

export interface SeverityStat {
  severity: string
  count: number
}

export interface ModuleStat {
  module_id: string
  count: number
}

export interface NullString {
  String: string
  Valid: boolean
}

export interface NullFloat64 {
  Float64: number
  Valid: boolean
}

export interface NotificationRow {
  ID: string
  UserID: string
  ScanID: string
  Type: string
  Title: string
  Message: NullString | null
  Read: boolean
  Channel: string
  CreatedAt: string
}

export interface ScheduleRow {
  ID: string
  TargetID: string
  Name: string
  CronExpr: string
  Modules: string
  Enabled: boolean
  NotifyOn: string
  WebhookURL: string
  CreatedBy: string
  LastRunAt: string
  NextRunAt: string
  CreatedAt: string
}

export interface ModuleInfo {
  id: string
  name: string
  description: string
  severity: string
}

export interface ScanStats {
  total_scans: number
  total_findings: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
}

export interface ScanProgress {
  scan_id: string
  status: string
  current: number
  total: number
  module: string
  message: string
}

export interface OrganizationRow {
  ID: string
  Name: string
  Domain: string
  CreatedBy: string
  CreatedAt: string
  MemberCount: number
}

export interface OrgMemberRow {
  ID: string
  OrgID: string
  UserID: string
  Username: string
  Role: string
  JoinedAt: string
}

export interface AuditEntry {
  ID: string
  UserID: string
  Username: string
  OrgID: string
  Action: string
  Resource: string
  Details: string
  CreatedAt: string
}

export interface JiraConfig {
  url: string
  username: string
  api_token: string
  project: string
  issue_type: string
}

export interface GitHubConfig {
  token: string
  owner: string
  repo: string
}

export interface SlackConfig {
  webhook_url: string
}

export interface IntegrationConfigs {
  jira: JiraConfig | null
  github: GitHubConfig | null
  slack: SlackConfig | null
}

export interface WorkflowTrigger {
  type: string
  conditions: Record<string, string>
}

export interface WorkflowAction {
  type: string
  config: Record<string, string>
}

export interface Workflow {
  id: string
  name: string
  enabled: boolean
  trigger: WorkflowTrigger
  actions: WorkflowAction[]
  created_at: string
}
