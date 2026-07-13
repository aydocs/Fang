export namespace db {
	
	export class FindingRow {
	    ID: string;
	    ScanID: string;
	    TargetID: string;
	    ModuleID: string;
	    Title: string;
	    Severity: string;
	    Confidence: string;
	    CWEID: sql.NullString;
	    OWASPCategory: sql.NullString;
	    CVSS: sql.NullFloat64;
	    URL: sql.NullString;
	    Parameter: sql.NullString;
	    Payload: sql.NullString;
	    Evidence: sql.NullString;
	    Description: sql.NullString;
	    Remediation: sql.NullString;
	    Request: sql.NullString;
	    Response: sql.NullString;
	    Extra: sql.NullString;
	    IsFalsePositive: boolean;
	    // Go type: time
	    CreatedAt: any;
	
	    static createFrom(source: any = {}) {
	        return new FindingRow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.ScanID = source["ScanID"];
	        this.TargetID = source["TargetID"];
	        this.ModuleID = source["ModuleID"];
	        this.Title = source["Title"];
	        this.Severity = source["Severity"];
	        this.Confidence = source["Confidence"];
	        this.CWEID = this.convertValues(source["CWEID"], sql.NullString);
	        this.OWASPCategory = this.convertValues(source["OWASPCategory"], sql.NullString);
	        this.CVSS = this.convertValues(source["CVSS"], sql.NullFloat64);
	        this.URL = this.convertValues(source["URL"], sql.NullString);
	        this.Parameter = this.convertValues(source["Parameter"], sql.NullString);
	        this.Payload = this.convertValues(source["Payload"], sql.NullString);
	        this.Evidence = this.convertValues(source["Evidence"], sql.NullString);
	        this.Description = this.convertValues(source["Description"], sql.NullString);
	        this.Remediation = this.convertValues(source["Remediation"], sql.NullString);
	        this.Request = this.convertValues(source["Request"], sql.NullString);
	        this.Response = this.convertValues(source["Response"], sql.NullString);
	        this.Extra = this.convertValues(source["Extra"], sql.NullString);
	        this.IsFalsePositive = source["IsFalsePositive"];
	        this.CreatedAt = this.convertValues(source["CreatedAt"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ModuleStat {
	    module_id: string;
	    count: number;
	
	    static createFrom(source: any = {}) {
	        return new ModuleStat(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.module_id = source["module_id"];
	        this.count = source["count"];
	    }
	}
	export class NotificationRow {
	    ID: string;
	    UserID: sql.NullString;
	    ScanID: sql.NullString;
	    Type: string;
	    Title: string;
	    Message: sql.NullString;
	    Read: boolean;
	    Channel: sql.NullString;
	    // Go type: time
	    CreatedAt: any;
	
	    static createFrom(source: any = {}) {
	        return new NotificationRow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.UserID = this.convertValues(source["UserID"], sql.NullString);
	        this.ScanID = this.convertValues(source["ScanID"], sql.NullString);
	        this.Type = source["Type"];
	        this.Title = source["Title"];
	        this.Message = this.convertValues(source["Message"], sql.NullString);
	        this.Read = source["Read"];
	        this.Channel = this.convertValues(source["Channel"], sql.NullString);
	        this.CreatedAt = this.convertValues(source["CreatedAt"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ScanRow {
	    ID: string;
	    TargetID: string;
	    Status: string;
	    Modules: sql.NullString;
	    Threads: number;
	    Timeout: number;
	    Proxy: sql.NullString;
	    StartedAt: sql.NullTime;
	    FinishedAt: sql.NullTime;
	    DurationMs: sql.NullInt64;
	    Error: sql.NullString;
	    TriggeredBy: sql.NullString;
	    ScheduleID: sql.NullString;
	    // Go type: time
	    CreatedAt: any;
	
	    static createFrom(source: any = {}) {
	        return new ScanRow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.TargetID = source["TargetID"];
	        this.Status = source["Status"];
	        this.Modules = this.convertValues(source["Modules"], sql.NullString);
	        this.Threads = source["Threads"];
	        this.Timeout = source["Timeout"];
	        this.Proxy = this.convertValues(source["Proxy"], sql.NullString);
	        this.StartedAt = this.convertValues(source["StartedAt"], sql.NullTime);
	        this.FinishedAt = this.convertValues(source["FinishedAt"], sql.NullTime);
	        this.DurationMs = this.convertValues(source["DurationMs"], sql.NullInt64);
	        this.Error = this.convertValues(source["Error"], sql.NullString);
	        this.TriggeredBy = this.convertValues(source["TriggeredBy"], sql.NullString);
	        this.ScheduleID = this.convertValues(source["ScheduleID"], sql.NullString);
	        this.CreatedAt = this.convertValues(source["CreatedAt"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class ScheduleRow {
	    ID: string;
	    TargetID: string;
	    Name: string;
	    CronExpr: string;
	    Modules: string;
	    Enabled: boolean;
	    NotifyOn: string;
	    WebhookURL: string;
	    CreatedBy: string;
	    // Go type: time
	    LastRunAt: any;
	    // Go type: time
	    NextRunAt: any;
	    // Go type: time
	    CreatedAt: any;
	
	    static createFrom(source: any = {}) {
	        return new ScheduleRow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.TargetID = source["TargetID"];
	        this.Name = source["Name"];
	        this.CronExpr = source["CronExpr"];
	        this.Modules = source["Modules"];
	        this.Enabled = source["Enabled"];
	        this.NotifyOn = source["NotifyOn"];
	        this.WebhookURL = source["WebhookURL"];
	        this.CreatedBy = source["CreatedBy"];
	        this.LastRunAt = this.convertValues(source["LastRunAt"], null);
	        this.NextRunAt = this.convertValues(source["NextRunAt"], null);
	        this.CreatedAt = this.convertValues(source["CreatedAt"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class SeverityStat {
	    severity: string;
	    count: number;
	
	    static createFrom(source: any = {}) {
	        return new SeverityStat(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.count = source["count"];
	    }
	}
	export class TargetRow {
	    ID: string;
	    URL: string;
	    Domain: string;
	    Name: string;
	    Tags: string;
	    CreatedBy: string;
	    // Go type: time
	    CreatedAt: any;
	
	    static createFrom(source: any = {}) {
	        return new TargetRow(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ID = source["ID"];
	        this.URL = source["URL"];
	        this.Domain = source["Domain"];
	        this.Name = source["Name"];
	        this.Tags = source["Tags"];
	        this.CreatedBy = source["CreatedBy"];
	        this.CreatedAt = this.convertValues(source["CreatedAt"], null);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace main {
	
	export class ModuleInfo {
	    id: string;
	    name: string;
	    description: string;
	    severity: string;
	
	    static createFrom(source: any = {}) {
	        return new ModuleInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.description = source["description"];
	        this.severity = source["severity"];
	    }
	}
	export class ScanStats {
	    total_scans: number;
	    total_findings: number;
	    critical_count: number;
	    high_count: number;
	    medium_count: number;
	    low_count: number;
	
	    static createFrom(source: any = {}) {
	        return new ScanStats(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.total_scans = source["total_scans"];
	        this.total_findings = source["total_findings"];
	        this.critical_count = source["critical_count"];
	        this.high_count = source["high_count"];
	        this.medium_count = source["medium_count"];
	        this.low_count = source["low_count"];
	    }
	}
	export class ScheduleInput {
	    target_id: string;
	    name: string;
	    cron_expr: string;
	    modules: string;
	    notify_on: string;
	    webhook_url: string;
	
	    static createFrom(source: any = {}) {
	        return new ScheduleInput(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.target_id = source["target_id"];
	        this.name = source["name"];
	        this.cron_expr = source["cron_expr"];
	        this.modules = source["modules"];
	        this.notify_on = source["notify_on"];
	        this.webhook_url = source["webhook_url"];
	    }
	}

}

export namespace sql {
	
	export class NullFloat64 {
	    Float64: number;
	    Valid: boolean;
	
	    static createFrom(source: any = {}) {
	        return new NullFloat64(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Float64 = source["Float64"];
	        this.Valid = source["Valid"];
	    }
	}
	export class NullInt64 {
	    Int64: number;
	    Valid: boolean;
	
	    static createFrom(source: any = {}) {
	        return new NullInt64(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Int64 = source["Int64"];
	        this.Valid = source["Valid"];
	    }
	}
	export class NullString {
	    String: string;
	    Valid: boolean;
	
	    static createFrom(source: any = {}) {
	        return new NullString(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.String = source["String"];
	        this.Valid = source["Valid"];
	    }
	}
	export class NullTime {
	    // Go type: time
	    Time: any;
	    Valid: boolean;
	
	    static createFrom(source: any = {}) {
	        return new NullTime(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Time = this.convertValues(source["Time"], null);
	        this.Valid = source["Valid"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

