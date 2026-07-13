import { EventsOn, EventsOff } from '../wailsjs/runtime/runtime'
import type {
  TargetRow,
  ScanRow,
  FindingRow,
  SeverityStat,
  ModuleStat,
  NotificationRow,
  ScheduleRow,
  ModuleInfo,
  ScanStats,
  ScanProgress,
  UserRow,
  OrganizationRow,
  OrgMemberRow,
  AuditEntry,
  Workflow,
} from './types'

interface App {
  RunScanAsync(targetURL: string, modules: string[]): Promise<string>
  RunScan(targetURL: string, modules: string[]): Promise<string>
  CancelScan(): Promise<void>
  GetActiveScan(): Promise<string>
  GetTargets(): Promise<TargetRow[]>
  CreateTarget(url: string): Promise<string>
  DeleteTarget(id: string): Promise<void>
  GetScans(): Promise<ScanRow[]>
  GetScan(scanID: string): Promise<ScanRow>
  GetScanFindings(scanID: string): Promise<FindingRow[]>
  GetAllFindings(limit: number, offset: number): Promise<FindingRow[]>
  GetSeverityStats(): Promise<SeverityStat[]>
  GetModuleStats(): Promise<ModuleStat[]>
  GetNotifications(): Promise<NotificationRow[]>
  MarkNotificationRead(id: string): Promise<void>
  DeleteNotification(id: string): Promise<void>
  DeleteScan(id: string): Promise<void>
  ListModules(): Promise<ModuleInfo[]>
  GetStats(): Promise<ScanStats>
  GenerateReport(scanID: string, format: string): Promise<string>
  CreateSchedule(input: {
    target_id: string
    name: string
    cron_expr: string
    modules: string
    notify_on: string
    webhook_url: string
  }): Promise<string>
  GetSchedules(): Promise<ScheduleRow[]>
  DeleteSchedule(id: string): Promise<void>
  GetReportDir(): Promise<string>
  OpenDirectory(path: string): Promise<void>

  GetConfig(): Promise<Record<string, unknown>>
  SaveConfig(cfg: Record<string, unknown>): Promise<void>

  Login(username: string, password: string): Promise<{ success: boolean; user_id: string; username: string; role: string; error: string }>
  RegisterUser(username: string, email: string, password: string, role: string): Promise<string>
  ListUsers(): Promise<UserRow[]>
  DeleteUser(id: string): Promise<void>
  ChangePassword(userID: string, oldPassword: string, newPassword: string): Promise<void>

  ExportAll(format: string): Promise<string>
  ImportData(path: string): Promise<number>
  DownloadReport(scanID: string, format: string): Promise<string>

  GetFinding(id: string): Promise<FindingRow>
  UpdateFinding(id: string, isFalsePositive: boolean, severity: string, notes: string): Promise<void>

  CreateOrg(name: string, domain: string): Promise<string>
  ListOrgs(): Promise<OrganizationRow[]>
  DeleteOrg(id: string): Promise<void>
  ListOrgMembers(orgID: string): Promise<OrgMemberRow[]>
  InviteUser(orgID: string, username: string, role: string): Promise<void>
  RemoveUser(orgID: string, userID: string): Promise<void>
  GetAuditLog(orgID: string): Promise<AuditEntry[]>

  CreateJiraIssue(scanID: string, findingID: string): Promise<string>
  CreateGitHubIssue(scanID: string, findingID: string): Promise<string>
  ConfigureIntegration(integType: string, config: string): Promise<void>
  GetIntegrationConfig(integType: string): Promise<string>

  CreateWorkflow(name: string, triggerType: string, conditions: string, actions: string): Promise<string>
  ListWorkflows(): Promise<Workflow[]>
  DeleteWorkflow(id: string): Promise<void>
  ToggleWorkflow(id: string, enabled: boolean): Promise<void>
  TestWorkflow(id: string): Promise<string>

  GetPluginDir(): Promise<string>
  ListPlugins(): Promise<string>
  GetEvasionConfig(): Promise<string>
  SaveEvasionConfig(config: string): Promise<void>
  ConfigureSIEM(config: string): Promise<void>
  GetSIEMConfig(): Promise<string>
  SendToSIEM(scanID: string): Promise<void>
  CreateBountyReport(findingID: string, platform: string): Promise<string>
  SetLanguage(lang: string): Promise<void>
  GetLanguage(): Promise<string>
  GetTranslation(key: string): Promise<string>
}

declare global {
  interface Window {
    go: {
      main: {
        App: App
      }
    }
  }
}

export function bridge(): App {
  return window.go.main.App
}

export function onScanEvent(event: string, callback: (data: ScanProgress) => void) {
  EventsOn(event, callback)
}

export function offScanEvent(event: string) {
  EventsOff(event)
}
