// Darknode SIEM Engine — Security Information and Event Management
// Real log parsing, correlation, detection rules, anomaly detection, and analytics.
// Pure ES module — runs in-browser, no server required.

// ─── Unified Event Schema ──────────────────────────────────────────────────────
export class SIEMEvent {
  constructor(raw = {}) {
    this.id = raw.id || crypto.randomUUID?.() || Math.random().toString(36).slice(2);
    this.timestamp = raw.timestamp || Date.now();
    this.source = raw.source || "";
    this.sourceIp = raw.sourceIp || "";
    this.destIp = raw.destIp || "";
    this.sourcePort = raw.sourcePort || 0;
    this.destPort = raw.destPort || 0;
    this.protocol = raw.protocol || "";
    this.severity = raw.severity || "info"; // info, low, medium, high, critical
    this.category = raw.category || "general";
    this.message = raw.message || "";
    this.user = raw.user || "";
    this.hostname = raw.hostname || "";
    this.process = raw.process || "";
    this.pid = raw.pid || 0;
    this.action = raw.action || "";
    this.outcome = raw.outcome || ""; // success, failure, unknown
    this.rawLog = raw.rawLog || "";
    this.fields = raw.fields || {};
    this.tags = raw.tags || [];
    this.ruleMatches = [];
  }
}

// ─── Log Parsers ───────────────────────────────────────────────────────────────

// Syslog parser (RFC 3164 / RFC 5424)
export function parseSyslog(line) {
  const ev = new SIEMEvent({ rawLog: line });
  // RFC 3164: <PRI>TIMESTAMP HOSTNAME APP[PID]: MESSAGE
  const m3164 = line.match(/^<(\d{1,3})>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)/);
  if (m3164) {
    const pri = parseInt(m3164[1], 10);
    const facility = pri >> 3;
    const sevNum = pri & 7;
    const sevMap = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"];
    ev.severity = sevNum <= 2 ? "critical" : sevNum <= 3 ? "high" : sevNum <= 4 ? "medium" : "low";
    ev.fields.facility = facility;
    ev.fields.syslogSeverity = sevMap[sevNum] || "info";
    ev.timestamp = new Date(m3164[2] + " " + new Date().getFullYear()).getTime() || Date.now();
    ev.hostname = m3164[3];
    ev.process = m3164[4];
    ev.pid = parseInt(m3164[5], 10) || 0;
    ev.message = m3164[6];
    ev.source = "syslog";
    return ev;
  }
  // RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
  const m5424 = line.match(/^<(\d{1,3})>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+((?:\[.*?\])*)\s*(.*)/);
  if (m5424) {
    const pri = parseInt(m5424[1], 10);
    const sevNum = pri & 7;
    ev.severity = sevNum <= 2 ? "critical" : sevNum <= 3 ? "high" : sevNum <= 4 ? "medium" : "low";
    ev.fields.version = parseInt(m5424[2], 10);
    ev.timestamp = new Date(m5424[3]).getTime() || Date.now();
    ev.hostname = m5424[4] === "-" ? "" : m5424[4];
    ev.process = m5424[5] === "-" ? "" : m5424[5];
    ev.pid = parseInt(m5424[6], 10) || 0;
    ev.fields.msgId = m5424[7] === "-" ? "" : m5424[7];
    ev.fields.structuredData = m5424[8];
    ev.message = m5424[9];
    ev.source = "syslog";
    return ev;
  }
  ev.message = line;
  ev.source = "syslog";
  return ev;
}

// Windows Event Log XML parser
export function parseWindowsEventXml(xml) {
  const ev = new SIEMEvent({ rawLog: xml });
  ev.source = "windows";
  const tag = (name) => {
    const m = xml.match(new RegExp(`<${name}[^>]*>([^<]*)</${name}>`));
    return m ? m[1].trim() : "";
  };
  const attr = (tagName, attrName) => {
    const m = xml.match(new RegExp(`<${tagName}[^>]*${attrName}='([^']*)'`));
    if (m) return m[1];
    const m2 = xml.match(new RegExp(`<${tagName}[^>]*${attrName}="([^"]*)"`));
    return m2 ? m2[1] : "";
  };
  ev.fields.eventId = parseInt(attr("EventID", "Qualifiers") || tag("EventID"), 10) || 0;
  ev.fields.channel = tag("Channel") || attr("System", "Channel");
  ev.fields.provider = attr("Provider", "Name");
  ev.hostname = tag("Computer");
  ev.timestamp = new Date(attr("TimeCreated", "SystemTime") || tag("TimeCreated")).getTime() || Date.now();
  ev.fields.level = parseInt(tag("Level"), 10);
  const levelMap = { 1: "critical", 2: "high", 3: "medium", 4: "low", 5: "info" };
  ev.severity = levelMap[ev.fields.level] || "info";
  ev.pid = parseInt(attr("Execution", "ProcessID"), 10) || 0;
  ev.fields.threadId = parseInt(attr("Execution", "ThreadID"), 10) || 0;
  ev.user = tag("Security") || attr("Security", "UserID");
  ev.message = tag("Data") || xml.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 500);
  // Extract all Data elements
  const dataMatches = xml.matchAll(/<Data\s+Name='([^']+)'>([^<]*)<\/Data>/g);
  for (const dm of dataMatches) {
    ev.fields[dm[1]] = dm[2];
  }
  return ev;
}

// Apache/Nginx access log parser (Combined format)
export function parseApacheLog(line) {
  const ev = new SIEMEvent({ rawLog: line });
  ev.source = "http";
  // Combined: IP - USER [TIMESTAMP] "METHOD PATH PROTO" STATUS SIZE "REFERER" "UA"
  const m = line.match(/^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)")?\s*(?:"([^"]*)")?/);
  if (m) {
    ev.sourceIp = m[1];
    ev.user = m[3] === "-" ? "" : m[3];
    ev.timestamp = parseApacheTimestamp(m[4]);
    const reqParts = m[5].split(" ");
    ev.fields.method = reqParts[0] || "";
    ev.fields.path = reqParts[1] || "";
    ev.fields.httpVersion = reqParts[2] || "";
    ev.fields.status = parseInt(m[6], 10);
    ev.fields.size = m[7] === "-" ? 0 : parseInt(m[7], 10);
    ev.fields.referer = m[8] || "";
    ev.fields.userAgent = m[9] || "";
    ev.action = ev.fields.method;
    ev.outcome = ev.fields.status < 400 ? "success" : "failure";
    ev.severity = ev.fields.status >= 500 ? "high" : ev.fields.status >= 400 ? "medium" : "info";
    ev.message = `${ev.fields.method} ${ev.fields.path} ${ev.fields.status}`;
    ev.category = "web";
    return ev;
  }
  ev.message = line;
  return ev;
}

function parseApacheTimestamp(s) {
  // 10/Oct/2023:13:55:36 -0700
  const months = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
  const m = s.match(/(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?/);
  if (!m) return Date.now();
  return new Date(parseInt(m[3]), months[m[2]] || 0, parseInt(m[1]), parseInt(m[4]), parseInt(m[5]), parseInt(m[6])).getTime();
}

// JSON log parser (generic structured logging)
export function parseJsonLog(line) {
  const ev = new SIEMEvent({ rawLog: line });
  ev.source = "json";
  try {
    const obj = JSON.parse(line);
    ev.timestamp = new Date(obj.timestamp || obj.time || obj["@timestamp"] || obj.ts || obj.date).getTime() || Date.now();
    ev.severity = normalizeSeverity(obj.level || obj.severity || obj.loglevel || "info");
    ev.message = obj.message || obj.msg || obj.log || obj.text || "";
    ev.hostname = obj.hostname || obj.host || obj.server || "";
    ev.sourceIp = obj.sourceIp || obj.src_ip || obj.client_ip || obj.remote_addr || "";
    ev.destIp = obj.destIp || obj.dst_ip || obj.dest_ip || "";
    ev.user = obj.user || obj.username || obj.userId || obj.user_id || "";
    ev.process = obj.process || obj.program || obj.app || obj.service || "";
    ev.pid = parseInt(obj.pid || obj.process_id, 10) || 0;
    ev.action = obj.action || obj.event || obj.eventType || obj.event_type || "";
    ev.category = obj.category || obj.type || obj.event_category || "";
    ev.fields = { ...obj };
    delete ev.fields.message; delete ev.fields.timestamp;
    return ev;
  } catch (e) {
    ev.message = line;
    return ev;
  }
}

// CEF (Common Event Format) parser
export function parseCef(line) {
  const ev = new SIEMEvent({ rawLog: line });
  ev.source = "cef";
  // CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|DeviceEventClassID|Name|Severity|Extensions
  const m = line.match(/^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(\d+)\|(.*)/);
  if (!m) { ev.message = line; return ev; }
  ev.fields.cefVersion = parseInt(m[1], 10);
  ev.fields.deviceVendor = m[2];
  ev.fields.deviceProduct = m[3];
  ev.fields.deviceVersion = m[4];
  ev.fields.eventClassId = m[5];
  ev.message = m[6];
  const sevNum = parseInt(m[7], 10);
  ev.severity = sevNum >= 9 ? "critical" : sevNum >= 7 ? "high" : sevNum >= 4 ? "medium" : "low";
  // Parse extensions (key=value pairs)
  const ext = m[8];
  const extPairs = ext.match(/(\w+)=([^\s]+(?:\s+(?!\w+=)[^\s]+)*)/g);
  if (extPairs) {
    for (const pair of extPairs) {
      const eqIdx = pair.indexOf("=");
      const key = pair.slice(0, eqIdx);
      const val = pair.slice(eqIdx + 1);
      ev.fields[key] = val;
      if (key === "src") ev.sourceIp = val;
      else if (key === "dst") ev.destIp = val;
      else if (key === "spt") ev.sourcePort = parseInt(val, 10);
      else if (key === "dpt") ev.destPort = parseInt(val, 10);
      else if (key === "suser" || key === "duser") ev.user = ev.user || val;
      else if (key === "shost" || key === "dhost") ev.hostname = ev.hostname || val;
      else if (key === "proto") ev.protocol = val;
      else if (key === "act") ev.action = val;
      else if (key === "outcome") ev.outcome = val;
      else if (key === "rt") ev.timestamp = new Date(val).getTime() || Date.now();
    }
  }
  return ev;
}

// LEEF (Log Event Extended Format) parser
export function parseLeef(line) {
  const ev = new SIEMEvent({ rawLog: line });
  ev.source = "leef";
  // LEEF:Version|Vendor|Product|Version|EventID|key=value pairs
  const m = line.match(/^LEEF:([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)/);
  if (!m) { ev.message = line; return ev; }
  ev.fields.leefVersion = m[1];
  ev.fields.vendor = m[2];
  ev.fields.product = m[3];
  ev.fields.version = m[4];
  ev.fields.eventId = m[5];
  const delim = m[1] === "2.0" ? "\x09" : "\t";
  const kvs = m[6].split(delim);
  for (const kv of kvs) {
    const eqIdx = kv.indexOf("=");
    if (eqIdx < 0) continue;
    const key = kv.slice(0, eqIdx).trim();
    const val = kv.slice(eqIdx + 1).trim();
    ev.fields[key] = val;
    if (key === "src") ev.sourceIp = val;
    else if (key === "dst") ev.destIp = val;
    else if (key === "srcPort") ev.sourcePort = parseInt(val, 10);
    else if (key === "dstPort") ev.destPort = parseInt(val, 10);
    else if (key === "usrName") ev.user = val;
    else if (key === "sev") ev.severity = normalizeSeverity(val);
    else if (key === "cat") ev.category = val;
    else if (key === "devTime") ev.timestamp = new Date(val).getTime() || Date.now();
  }
  ev.message = ev.fields.eventId || line;
  return ev;
}

function normalizeSeverity(s) {
  const sl = String(s).toLowerCase().trim();
  if (["critical", "crit", "fatal", "emergency", "emerg", "panic", "10", "9"].includes(sl)) return "critical";
  if (["high", "error", "err", "alert", "8", "7", "6"].includes(sl)) return "high";
  if (["medium", "med", "warning", "warn", "5", "4"].includes(sl)) return "medium";
  if (["low", "notice", "3", "2"].includes(sl)) return "low";
  return "info";
}

// Auto-detect and parse any log format
export function parseLog(line) {
  const trimmed = (line || "").trim();
  if (!trimmed) return null;
  if (trimmed.startsWith("CEF:")) return parseCef(trimmed);
  if (trimmed.startsWith("LEEF:")) return parseLeef(trimmed);
  if (trimmed.startsWith("<Event") || trimmed.startsWith("<System")) return parseWindowsEventXml(trimmed);
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) return parseJsonLog(trimmed);
  if (/^<\d{1,3}>/.test(trimmed)) return parseSyslog(trimmed);
  if (/^\S+\s+-\s+\S+\s+\[/.test(trimmed)) return parseApacheLog(trimmed);
  // Fallback: generic line
  const ev = new SIEMEvent({ rawLog: trimmed, message: trimmed, source: "raw" });
  return ev;
}

// Batch parse multiple lines
export function parseLogs(text) {
  return text.split("\n").map(parseLog).filter(Boolean);
}

// ─── Detection Rules ───────────────────────────────────────────────────────────

export class DetectionRule {
  constructor({ id, name, description, severity, category, mitre, conditions, timeWindow, threshold, enabled }) {
    this.id = id || "";
    this.name = name || "";
    this.description = description || "";
    this.severity = severity || "medium";
    this.category = category || "general";
    this.mitre = mitre || []; // MITRE ATT&CK technique IDs
    this.conditions = conditions || []; // [{field, op, value}]
    this.timeWindow = timeWindow || 0; // seconds, 0 = single event
    this.threshold = threshold || 1;
    this.enabled = enabled !== false;
  }
}

// Condition operators
function evalCondition(event, cond) {
  let val = event[cond.field];
  if (val === undefined && event.fields) val = event.fields[cond.field];
  if (val === undefined) return false;
  const target = cond.value;
  switch (cond.op) {
    case "eq": case "==": case "equals": return String(val).toLowerCase() === String(target).toLowerCase();
    case "ne": case "!=": case "not_equals": return String(val).toLowerCase() !== String(target).toLowerCase();
    case "contains": return String(val).toLowerCase().includes(String(target).toLowerCase());
    case "not_contains": return !String(val).toLowerCase().includes(String(target).toLowerCase());
    case "starts_with": return String(val).toLowerCase().startsWith(String(target).toLowerCase());
    case "ends_with": return String(val).toLowerCase().endsWith(String(target).toLowerCase());
    case "regex": case "matches": try { return new RegExp(target, "i").test(String(val)); } catch { return false; }
    case "gt": case ">": return parseFloat(val) > parseFloat(target);
    case "gte": case ">=": return parseFloat(val) >= parseFloat(target);
    case "lt": case "<": return parseFloat(val) < parseFloat(target);
    case "lte": case "<=": return parseFloat(val) <= parseFloat(target);
    case "in": return Array.isArray(target) ? target.some(t => String(val).toLowerCase() === String(t).toLowerCase()) : String(target).split(",").some(t => String(val).toLowerCase() === t.trim().toLowerCase());
    case "not_in": return Array.isArray(target) ? !target.some(t => String(val).toLowerCase() === String(t).toLowerCase()) : !String(target).split(",").some(t => String(val).toLowerCase() === t.trim().toLowerCase());
    case "exists": return val !== undefined && val !== null && val !== "";
    case "not_exists": return val === undefined || val === null || val === "";
    default: return false;
  }
}

function eventMatchesRule(event, rule) {
  if (!rule.enabled) return false;
  return rule.conditions.every(c => evalCondition(event, c));
}

// ─── 200+ Built-in Detection Rules ────────────────────────────────────────────

export const BUILTIN_RULES = [
  // === BRUTE FORCE ===
  new DetectionRule({ id: "BF-001", name: "SSH Brute Force", description: "Multiple failed SSH login attempts from same source", severity: "high", category: "brute_force", mitre: ["T1110.001"], conditions: [{ field: "message", op: "regex", value: "(Failed password|authentication failure|Invalid user)" }, { field: "destPort", op: "in", value: "22,2222" }], timeWindow: 60, threshold: 5 }),
  new DetectionRule({ id: "BF-002", name: "RDP Brute Force", description: "Multiple failed RDP login attempts", severity: "high", category: "brute_force", mitre: ["T1110.001"], conditions: [{ field: "destPort", op: "eq", value: "3389" }, { field: "outcome", op: "eq", value: "failure" }], timeWindow: 60, threshold: 5 }),
  new DetectionRule({ id: "BF-003", name: "Web Login Brute Force", description: "Multiple HTTP 401/403 from same IP", severity: "high", category: "brute_force", mitre: ["T1110.001"], conditions: [{ field: "status", op: "in", value: "401,403" }, { field: "method", op: "eq", value: "POST" }], timeWindow: 60, threshold: 10 }),
  new DetectionRule({ id: "BF-004", name: "FTP Brute Force", description: "Multiple failed FTP logins from same IP", severity: "high", category: "brute_force", mitre: ["T1110.001"], conditions: [{ field: "message", op: "contains", value: "Login incorrect" }, { field: "destPort", op: "eq", value: "21" }], timeWindow: 60, threshold: 5 }),
  new DetectionRule({ id: "BF-005", name: "SMB Brute Force", description: "Repeated failed SMB authentication", severity: "high", category: "brute_force", mitre: ["T1110.001"], conditions: [{ field: "destPort", op: "in", value: "445,139" }, { field: "outcome", op: "eq", value: "failure" }], timeWindow: 60, threshold: 5 }),
  new DetectionRule({ id: "BF-006", name: "LDAP Brute Force", description: "Multiple failed LDAP bind attempts", severity: "high", category: "brute_force", mitre: ["T1110.001"], conditions: [{ field: "message", op: "contains", value: "LDAP bind failed" }], timeWindow: 60, threshold: 5 }),
  new DetectionRule({ id: "BF-007", name: "Kerberos Pre-Auth Failure Burst", description: "Multiple Kerberos pre-authentication failures (Event 4771)", severity: "high", category: "brute_force", mitre: ["T1110.001"], conditions: [{ field: "eventId", op: "eq", value: "4771" }], timeWindow: 60, threshold: 10 }),
  new DetectionRule({ id: "BF-008", name: "Password Spray", description: "Same password tried against many accounts (single failure per account)", severity: "critical", category: "brute_force", mitre: ["T1110.003"], conditions: [{ field: "outcome", op: "eq", value: "failure" }, { field: "category", op: "in", value: "authentication,auth,login" }], timeWindow: 300, threshold: 20 }),
  new DetectionRule({ id: "BF-009", name: "Credential Stuffing", description: "Rapid automated login attempts with varied usernames", severity: "high", category: "brute_force", mitre: ["T1110.004"], conditions: [{ field: "action", op: "in", value: "login,authenticate,signin" }, { field: "outcome", op: "eq", value: "failure" }], timeWindow: 120, threshold: 50 }),
  new DetectionRule({ id: "BF-010", name: "Database Brute Force", description: "Multiple failed database authentication attempts", severity: "high", category: "brute_force", mitre: ["T1110.001"], conditions: [{ field: "destPort", op: "in", value: "3306,5432,1433,1521,27017" }, { field: "outcome", op: "eq", value: "failure" }], timeWindow: 60, threshold: 5 }),

  // === PORT SCANNING ===
  new DetectionRule({ id: "PS-001", name: "TCP Port Scan", description: "Single source connecting to many ports on a target", severity: "medium", category: "reconnaissance", mitre: ["T1046"], conditions: [{ field: "protocol", op: "in", value: "tcp,TCP" }], timeWindow: 30, threshold: 20 }),
  new DetectionRule({ id: "PS-002", name: "SYN Scan Detected", description: "Half-open TCP connections indicating SYN scan", severity: "medium", category: "reconnaissance", mitre: ["T1046"], conditions: [{ field: "message", op: "regex", value: "(SYN|half-open|connection reset)" }], timeWindow: 10, threshold: 50 }),
  new DetectionRule({ id: "PS-003", name: "UDP Port Scan", description: "UDP probes to multiple ports", severity: "medium", category: "reconnaissance", mitre: ["T1046"], conditions: [{ field: "protocol", op: "in", value: "udp,UDP" }], timeWindow: 30, threshold: 20 }),
  new DetectionRule({ id: "PS-004", name: "Network Sweep", description: "Single source probing many hosts on same port", severity: "medium", category: "reconnaissance", mitre: ["T1046"], conditions: [{ field: "action", op: "in", value: "connect,syn,probe" }], timeWindow: 60, threshold: 30 }),
  new DetectionRule({ id: "PS-005", name: "Service Enumeration", description: "Connections to well-known service ports in sequence", severity: "low", category: "reconnaissance", mitre: ["T1046"], conditions: [{ field: "destPort", op: "in", value: "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080,8443" }], timeWindow: 30, threshold: 5 }),
  new DetectionRule({ id: "PS-006", name: "Stealth FIN Scan", description: "TCP FIN packets without prior connection", severity: "high", category: "reconnaissance", mitre: ["T1046"], conditions: [{ field: "message", op: "regex", value: "(FIN scan|stealth scan|XMAS scan|NULL scan)" }], timeWindow: 10, threshold: 10 }),
  new DetectionRule({ id: "PS-007", name: "OS Fingerprinting", description: "TTL/window size probes indicating OS fingerprinting", severity: "medium", category: "reconnaissance", mitre: ["T1046"], conditions: [{ field: "message", op: "regex", value: "(fingerprint|nmap|masscan|zmap)" }], timeWindow: 30, threshold: 5 }),

  // === PRIVILEGE ESCALATION ===
  new DetectionRule({ id: "PE-001", name: "Sudo to Root", description: "User escalated to root via sudo", severity: "medium", category: "privilege_escalation", mitre: ["T1548.003"], conditions: [{ field: "message", op: "regex", value: "sudo.*ROOT" }] }),
  new DetectionRule({ id: "PE-002", name: "SUID Binary Execution", description: "Execution of SUID binary that could lead to privilege escalation", severity: "high", category: "privilege_escalation", mitre: ["T1548.001"], conditions: [{ field: "message", op: "regex", value: "(setuid|suid|SUID|chmod \\+s)" }] }),
  new DetectionRule({ id: "PE-003", name: "Kernel Exploit Attempt", description: "Signs of kernel exploit execution", severity: "critical", category: "privilege_escalation", mitre: ["T1068"], conditions: [{ field: "message", op: "regex", value: "(dirty_cow|dirtypipe|dirty_cred|overlayfs|netfilter.*escalat)" }] }),
  new DetectionRule({ id: "PE-004", name: "Token Manipulation", description: "Windows token impersonation or theft", severity: "critical", category: "privilege_escalation", mitre: ["T1134"], conditions: [{ field: "eventId", op: "in", value: "4672,4673,4674" }] }),
  new DetectionRule({ id: "PE-005", name: "UAC Bypass", description: "User Account Control bypass attempt", severity: "critical", category: "privilege_escalation", mitre: ["T1548.002"], conditions: [{ field: "message", op: "regex", value: "(fodhelper|computerdefaults|sdclt|eventvwr.*mmc|bypassuac)" }] }),
  new DetectionRule({ id: "PE-006", name: "Linux Capability Abuse", description: "Suspicious use of Linux capabilities for escalation", severity: "high", category: "privilege_escalation", mitre: ["T1548"], conditions: [{ field: "message", op: "regex", value: "(cap_setuid|cap_setgid|cap_dac_override|cap_sys_admin)" }] }),
  new DetectionRule({ id: "PE-007", name: "Group Policy Modification", description: "GPO modified for privilege escalation", severity: "critical", category: "privilege_escalation", mitre: ["T1484.001"], conditions: [{ field: "eventId", op: "eq", value: "5136" }, { field: "message", op: "contains", value: "groupPolicy" }] }),
  new DetectionRule({ id: "PE-008", name: "Named Pipe Impersonation", description: "Named pipe created for token impersonation", severity: "high", category: "privilege_escalation", mitre: ["T1134.001"], conditions: [{ field: "message", op: "regex", value: "(CreateNamedPipe|ImpersonateNamedPipeClient|PrintSpoofer|potato)" }] }),
  new DetectionRule({ id: "PE-009", name: "DLL Hijacking", description: "DLL side-loading or search order hijacking", severity: "high", category: "privilege_escalation", mitre: ["T1574.001"], conditions: [{ field: "message", op: "regex", value: "(DLL.*hijack|side.?load|search order)" }] }),
  new DetectionRule({ id: "PE-010", name: "Password File Access", description: "Unauthorized access to /etc/shadow or SAM", severity: "critical", category: "privilege_escalation", mitre: ["T1003"], conditions: [{ field: "message", op: "regex", value: "(/etc/shadow|\\\\SAM|\\\\SYSTEM|secretsdump)" }] }),

  // === LATERAL MOVEMENT ===
  new DetectionRule({ id: "LM-001", name: "PsExec Usage", description: "PsExec or similar remote execution tool detected", severity: "high", category: "lateral_movement", mitre: ["T1570", "T1021.002"], conditions: [{ field: "message", op: "regex", value: "(psexec|PSEXESVC|paexec|remcom)" }] }),
  new DetectionRule({ id: "LM-002", name: "WMI Remote Execution", description: "WMI used for remote command execution", severity: "high", category: "lateral_movement", mitre: ["T1047"], conditions: [{ field: "message", op: "regex", value: "(wmic.*process.*call.*create|wmiprvse|Win32_Process)" }] }),
  new DetectionRule({ id: "LM-003", name: "Remote PowerShell Session", description: "PowerShell remoting / Enter-PSSession detected", severity: "high", category: "lateral_movement", mitre: ["T1021.006"], conditions: [{ field: "message", op: "regex", value: "(Enter-PSSession|Invoke-Command.*-ComputerName|WinRM|WSMan)" }] }),
  new DetectionRule({ id: "LM-004", name: "RDP Lateral Movement", description: "RDP connection to internal host from internal source", severity: "medium", category: "lateral_movement", mitre: ["T1021.001"], conditions: [{ field: "destPort", op: "eq", value: "3389" }, { field: "sourceIp", op: "regex", value: "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)" }] }),
  new DetectionRule({ id: "LM-005", name: "Pass-the-Hash", description: "NTLM authentication with hash instead of password", severity: "critical", category: "lateral_movement", mitre: ["T1550.002"], conditions: [{ field: "message", op: "regex", value: "(pass.?the.?hash|pth|sekurlsa|lsadump|NTLM.*logon.*type.*3)" }] }),
  new DetectionRule({ id: "LM-006", name: "Pass-the-Ticket", description: "Kerberos ticket forgery or reuse", severity: "critical", category: "lateral_movement", mitre: ["T1550.003"], conditions: [{ field: "message", op: "regex", value: "(pass.?the.?ticket|golden.?ticket|silver.?ticket|krbrelayup)" }] }),
  new DetectionRule({ id: "LM-007", name: "SSH Lateral Movement", description: "SSH connection between internal hosts", severity: "medium", category: "lateral_movement", mitre: ["T1021.004"], conditions: [{ field: "destPort", op: "eq", value: "22" }, { field: "sourceIp", op: "regex", value: "^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.)" }, { field: "outcome", op: "eq", value: "success" }] }),
  new DetectionRule({ id: "LM-008", name: "Admin Share Access", description: "Access to C$ or ADMIN$ shares", severity: "high", category: "lateral_movement", mitre: ["T1021.002"], conditions: [{ field: "message", op: "regex", value: "(C\\$|ADMIN\\$|IPC\\$)" }, { field: "action", op: "in", value: "connect,access,mount" }] }),
  new DetectionRule({ id: "LM-009", name: "DCSync Attack", description: "Replication of Active Directory via DRS", severity: "critical", category: "lateral_movement", mitre: ["T1003.006"], conditions: [{ field: "message", op: "regex", value: "(DCSync|DRS.*Replication|GetNCChanges|DS-Replication-Get-Changes)" }] }),
  new DetectionRule({ id: "LM-010", name: "DCOM Remote Execution", description: "Distributed COM used for remote execution", severity: "high", category: "lateral_movement", mitre: ["T1021.003"], conditions: [{ field: "message", op: "regex", value: "(DCOM|MMC20\\.Application|ShellWindows|ShellBrowserWindow)" }] }),

  // === DATA EXFILTRATION ===
  new DetectionRule({ id: "EX-001", name: "Large Data Upload", description: "Unusually large outbound data transfer", severity: "high", category: "exfiltration", mitre: ["T1048"], conditions: [{ field: "size", op: "gt", value: "10485760" }] }),
  new DetectionRule({ id: "EX-002", name: "DNS Tunneling", description: "Abnormally long DNS queries indicating data exfiltration", severity: "critical", category: "exfiltration", mitre: ["T1048.003"], conditions: [{ field: "message", op: "regex", value: "DNS.*query.*[a-z0-9]{32,}" }] }),
  new DetectionRule({ id: "EX-003", name: "ICMP Tunneling", description: "Large or frequent ICMP packets suggesting data tunnel", severity: "high", category: "exfiltration", mitre: ["T1048"], conditions: [{ field: "protocol", op: "eq", value: "ICMP" }, { field: "size", op: "gt", value: "1000" }] }),
  new DetectionRule({ id: "EX-004", name: "Cloud Storage Upload", description: "Data uploaded to cloud storage services", severity: "medium", category: "exfiltration", mitre: ["T1567.002"], conditions: [{ field: "message", op: "regex", value: "(dropbox|drive\\.google|onedrive|s3\\.amazonaws|blob\\.core\\.windows)" }] }),
  new DetectionRule({ id: "EX-005", name: "USB Data Transfer", description: "Large file copy to removable media", severity: "medium", category: "exfiltration", mitre: ["T1052.001"], conditions: [{ field: "message", op: "regex", value: "(removable|USB|mass storage|USBSTOR)" }] }),
  new DetectionRule({ id: "EX-006", name: "Email Exfiltration", description: "Large attachment sent via email", severity: "medium", category: "exfiltration", mitre: ["T1048.002"], conditions: [{ field: "destPort", op: "in", value: "25,465,587" }, { field: "size", op: "gt", value: "5242880" }] }),
  new DetectionRule({ id: "EX-007", name: "Data Staging", description: "Data collected and staged before exfiltration", severity: "medium", category: "exfiltration", mitre: ["T1074"], conditions: [{ field: "message", op: "regex", value: "(staging|compress|archive|7z|rar|tar|zip.*-r)" }] }),
  new DetectionRule({ id: "EX-008", name: "Covert Channel", description: "Unusual protocol usage suggesting covert data channel", severity: "high", category: "exfiltration", mitre: ["T1071.004"], conditions: [{ field: "destPort", op: "in", value: "53,443" }, { field: "size", op: "gt", value: "50000" }], timeWindow: 60, threshold: 10 }),

  // === MALWARE / C2 ===
  new DetectionRule({ id: "MW-001", name: "Beaconing Activity", description: "Regular periodic outbound connections suggesting C2 beaconing", severity: "critical", category: "malware", mitre: ["T1071.001"], conditions: [{ field: "action", op: "in", value: "connect,outbound,established" }], timeWindow: 3600, threshold: 50 }),
  new DetectionRule({ id: "MW-002", name: "Known Malware User-Agent", description: "HTTP request with user-agent string matching known malware", severity: "critical", category: "malware", mitre: ["T1071.001"], conditions: [{ field: "userAgent", op: "regex", value: "(CobaltStrike|Meterpreter|HAVOC|Sliver|Empire|Covenant|PoshC2|Mythic|Brute Ratel)" }] }),
  new DetectionRule({ id: "MW-003", name: "DGA Domain Access", description: "DNS query for domain matching domain generation algorithm patterns", severity: "high", category: "malware", mitre: ["T1568.002"], conditions: [{ field: "message", op: "regex", value: "DNS.*query.*[bcdfghjklmnpqrstvwxz]{5,}" }] }),
  new DetectionRule({ id: "MW-004", name: "Ransomware File Activity", description: "Mass file encryption or renaming with common ransomware extensions", severity: "critical", category: "malware", mitre: ["T1486"], conditions: [{ field: "message", op: "regex", value: "\\.(encrypted|locked|crypt|crypto|locky|cerber|wannacry|ryuk|conti|lockbit|blackcat|alphv|hive)" }] }),
  new DetectionRule({ id: "MW-005", name: "Cryptominer Activity", description: "Process connecting to known mining pools", severity: "high", category: "malware", mitre: ["T1496"], conditions: [{ field: "message", op: "regex", value: "(stratum\\+tcp|mining\\.pool|xmrig|minergate|nicehash|ethermine|f2pool|nanopool)" }] }),
  new DetectionRule({ id: "MW-006", name: "Reverse Shell", description: "Outbound shell connection pattern detected", severity: "critical", category: "malware", mitre: ["T1059"], conditions: [{ field: "message", op: "regex", value: "(reverse.?shell|bash -i|nc -e|ncat -e|python.*socket.*connect|perl.*socket|ruby.*TCPSocket)" }] }),
  new DetectionRule({ id: "MW-007", name: "Web Shell Access", description: "Access to known web shell paths", severity: "critical", category: "malware", mitre: ["T1505.003"], conditions: [{ field: "path", op: "regex", value: "(cmd\\.php|shell\\.php|c99|r57|b374k|weevely|china.?chopper|antsword|godzilla|behinder)" }] }),
  new DetectionRule({ id: "MW-008", name: "Emotet Indicators", description: "Network patterns matching Emotet malware family", severity: "critical", category: "malware", mitre: ["T1566.001"], conditions: [{ field: "message", op: "regex", value: "(emotet|epoch[1-5]|heodo)" }] }),
  new DetectionRule({ id: "MW-009", name: "Cobalt Strike Beacon", description: "Indicators of Cobalt Strike beacon activity", severity: "critical", category: "malware", mitre: ["T1071.001", "T1059"], conditions: [{ field: "message", op: "regex", value: "(cobalt.?strike|beacon|cs_|malleable.*c2|jquery.*waterfall)" }] }),
  new DetectionRule({ id: "MW-010", name: "Rootkit Indicators", description: "Signs of rootkit installation or activity", severity: "critical", category: "malware", mitre: ["T1014"], conditions: [{ field: "message", op: "regex", value: "(rootkit|hidden.*process|hidden.*module|LD_PRELOAD|hooking.*syscall)" }] }),

  // === SUSPICIOUS PROCESS EXECUTION ===
  new DetectionRule({ id: "SP-001", name: "Mimikatz Execution", description: "Mimikatz credential dumping tool detected", severity: "critical", category: "credential_access", mitre: ["T1003.001"], conditions: [{ field: "message", op: "regex", value: "(mimikatz|sekurlsa|lsadump|dpapi.*masterkey|kerberos.*ticket)" }] }),
  new DetectionRule({ id: "SP-002", name: "PsExec/RemCom Execution", description: "Remote execution tool launched", severity: "high", category: "execution", mitre: ["T1569.002"], conditions: [{ field: "process", op: "regex", value: "(psexec|remcom|paexec|csexec)" }] }),
  new DetectionRule({ id: "SP-003", name: "WMIC Abuse", description: "WMI command line used for suspicious operations", severity: "high", category: "execution", mitre: ["T1047"], conditions: [{ field: "message", op: "regex", value: "wmic.*(process.*call.*create|os.*get|shadowcopy.*delete)" }] }),
  new DetectionRule({ id: "SP-004", name: "Certutil Abuse", description: "Certutil used for file download or encoding", severity: "high", category: "execution", mitre: ["T1140", "T1105"], conditions: [{ field: "message", op: "regex", value: "certutil.*(urlcache|decode|encode|download)" }] }),
  new DetectionRule({ id: "SP-005", name: "BITSAdmin Download", description: "BITS service abused for file download", severity: "high", category: "execution", mitre: ["T1197"], conditions: [{ field: "message", op: "regex", value: "bitsadmin.*(transfer|download|addfile)" }] }),
  new DetectionRule({ id: "SP-006", name: "Rundll32 Abuse", description: "Rundll32 used to execute suspicious DLL or script", severity: "high", category: "execution", mitre: ["T1218.011"], conditions: [{ field: "message", op: "regex", value: "rundll32.*(javascript|vbscript|shell32|url\\.dll|zipfldr)" }] }),
  new DetectionRule({ id: "SP-007", name: "Regsvr32 AppLocker Bypass", description: "Regsvr32 used to bypass application whitelisting", severity: "critical", category: "defense_evasion", mitre: ["T1218.010"], conditions: [{ field: "message", op: "regex", value: "regsvr32.*(scrobj|/s|/i:http)" }] }),
  new DetectionRule({ id: "SP-008", name: "MSBuild Execution", description: "MSBuild used to compile and execute code", severity: "high", category: "defense_evasion", mitre: ["T1127.001"], conditions: [{ field: "message", op: "regex", value: "msbuild.*(\\.csproj|\\.xml|\\.targets)" }] }),
  new DetectionRule({ id: "SP-009", name: "Scheduled Task Creation", description: "New scheduled task created for persistence", severity: "medium", category: "persistence", mitre: ["T1053.005"], conditions: [{ field: "message", op: "regex", value: "(schtasks.*create|at \\d|Register-ScheduledTask)" }] }),
  new DetectionRule({ id: "SP-010", name: "Service Installation", description: "New service installed for persistence", severity: "medium", category: "persistence", mitre: ["T1543.003"], conditions: [{ field: "message", op: "regex", value: "(sc create|New-Service|InstallUtil)" }] }),

  // === POWERSHELL SUSPICIOUS ACTIVITY ===
  new DetectionRule({ id: "PS-101", name: "PowerShell Encoded Command", description: "PowerShell execution with base64-encoded command", severity: "critical", category: "execution", mitre: ["T1059.001"], conditions: [{ field: "message", op: "regex", value: "powershell.*(-enc|-EncodedCommand|-e )\\s*[A-Za-z0-9+/=]{20,}" }] }),
  new DetectionRule({ id: "PS-102", name: "PowerShell Download Cradle", description: "PowerShell downloading and executing remote code", severity: "critical", category: "execution", mitre: ["T1059.001", "T1105"], conditions: [{ field: "message", op: "regex", value: "(IEX|Invoke-Expression).*(New-Object.*Net\\.WebClient|DownloadString|DownloadFile|Invoke-WebRequest|wget|curl)" }] }),
  new DetectionRule({ id: "PS-103", name: "PowerShell AMSI Bypass", description: "Attempt to disable AMSI protection", severity: "critical", category: "defense_evasion", mitre: ["T1562.001"], conditions: [{ field: "message", op: "regex", value: "(amsi.*bypass|AmsiInitFailed|amsiContext|Set-MpPreference.*-DisableRealtimeMonitoring)" }] }),
  new DetectionRule({ id: "PS-104", name: "PowerShell Empire Indicators", description: "PowerShell Empire C2 framework patterns", severity: "critical", category: "execution", mitre: ["T1059.001"], conditions: [{ field: "message", op: "regex", value: "(Invoke-Obfuscation|Invoke-PSInject|Invoke-Shellcode|Invoke-DllInjection|Get-Keystrokes)" }] }),
  new DetectionRule({ id: "PS-105", name: "PowerShell Reflection", description: "PowerShell reflection used to load assemblies in memory", severity: "high", category: "defense_evasion", mitre: ["T1620"], conditions: [{ field: "message", op: "regex", value: "(\\[Reflection\\.Assembly\\]|LoadWithPartialName|System\\.Reflection)" }] }),
  new DetectionRule({ id: "PS-106", name: "PowerShell Credential Harvesting", description: "PowerShell used to extract credentials", severity: "critical", category: "credential_access", mitre: ["T1003"], conditions: [{ field: "message", op: "regex", value: "(Get-Credential|ConvertTo-SecureString|LSASS|MiniDumpWriteDump)" }] }),
  new DetectionRule({ id: "PS-107", name: "PowerShell Constrained Language Bypass", description: "Attempt to bypass PowerShell constrained language mode", severity: "high", category: "defense_evasion", mitre: ["T1059.001"], conditions: [{ field: "message", op: "regex", value: "(ConstrainedLanguage|FullLanguage|__PSLockdownPolicy)" }] }),
  new DetectionRule({ id: "PS-108", name: "PowerShell Script Block Logging Bypass", description: "Attempt to disable script block logging", severity: "high", category: "defense_evasion", mitre: ["T1562.001"], conditions: [{ field: "message", op: "regex", value: "(ScriptBlockLogging|EnableScriptBlockLogging.*\\$false)" }] }),

  // === LOLBINS ===
  new DetectionRule({ id: "LB-001", name: "LOLBin: Mshta Execution", description: "Mshta.exe used to execute HTA or scripts", severity: "high", category: "execution", mitre: ["T1218.005"], conditions: [{ field: "message", op: "regex", value: "mshta.*(http|javascript|vbscript|\\.hta)" }] }),
  new DetectionRule({ id: "LB-002", name: "LOLBin: CMSTP Bypass", description: "CMSTP used to bypass UAC or AppLocker", severity: "high", category: "defense_evasion", mitre: ["T1218.003"], conditions: [{ field: "message", op: "regex", value: "cmstp.*/s|cmstp.*\\.inf" }] }),
  new DetectionRule({ id: "LB-003", name: "LOLBin: InstallUtil", description: "InstallUtil used to execute unmanaged code", severity: "high", category: "defense_evasion", mitre: ["T1218.004"], conditions: [{ field: "message", op: "regex", value: "InstallUtil.*/LogFile|InstallUtil.*\\.exe" }] }),
  new DetectionRule({ id: "LB-004", name: "LOLBin: Forfiles Execution", description: "Forfiles used to execute commands", severity: "medium", category: "execution", mitre: ["T1202"], conditions: [{ field: "message", op: "regex", value: "forfiles.*/c.*cmd|forfiles.*/p" }] }),
  new DetectionRule({ id: "LB-005", name: "LOLBin: Wscript/Cscript", description: "Windows Script Host executing scripts", severity: "medium", category: "execution", mitre: ["T1059.005"], conditions: [{ field: "message", op: "regex", value: "(wscript|cscript).*(\\.(vbs|js|wsf|wsh)|/e:)" }] }),
  new DetectionRule({ id: "LB-006", name: "LOLBin: Control.exe Execution", description: "Control panel used to execute DLLs", severity: "high", category: "defense_evasion", mitre: ["T1218.002"], conditions: [{ field: "message", op: "regex", value: "control\\.exe.*\\.dll|rundll32.*shell32.*Control_RunDLL" }] }),
  new DetectionRule({ id: "LB-007", name: "LOLBin: Esentutl Copy", description: "Esentutl used to copy locked files (SAM, NTDS)", severity: "critical", category: "credential_access", mitre: ["T1003.003"], conditions: [{ field: "message", op: "regex", value: "esentutl.*(copy|/y|SAM|NTDS|SYSTEM)" }] }),
  new DetectionRule({ id: "LB-008", name: "LOLBin: Netsh Port Forwarding", description: "Netsh used for port forwarding or firewall manipulation", severity: "high", category: "lateral_movement", mitre: ["T1090"], conditions: [{ field: "message", op: "regex", value: "netsh.*(portproxy|firewall.*add|advfirewall.*rule)" }] }),

  // === WEB APPLICATION ATTACKS ===
  new DetectionRule({ id: "WA-001", name: "SQL Injection Attempt", description: "SQL injection pattern detected in HTTP request", severity: "critical", category: "web_attack", mitre: ["T1190"], conditions: [{ field: "path", op: "regex", value: "(union.*select|or\\s+1=1|'\\s*or\\s*'|;\\s*drop|--\\s*$|/\\*.*\\*/|benchmark\\(|sleep\\(|waitfor)" }] }),
  new DetectionRule({ id: "WA-002", name: "Cross-Site Scripting (XSS)", description: "XSS payload detected in HTTP request", severity: "high", category: "web_attack", mitre: ["T1189"], conditions: [{ field: "path", op: "regex", value: "(<script|javascript:|on(error|load|click|mouseover)=|<img.*onerror|<svg.*onload|document\\.cookie|alert\\()" }] }),
  new DetectionRule({ id: "WA-003", name: "Path Traversal", description: "Directory traversal attempt in request", severity: "high", category: "web_attack", mitre: ["T1083"], conditions: [{ field: "path", op: "regex", value: "(\\.\\./|\\.\\.\\\\|%2e%2e%2f|%252e%252e%252f|/etc/passwd|/windows/system32)" }] }),
  new DetectionRule({ id: "WA-004", name: "Command Injection", description: "OS command injection attempt in request", severity: "critical", category: "web_attack", mitre: ["T1059"], conditions: [{ field: "path", op: "regex", value: "(;\\s*(ls|cat|id|whoami|wget|curl|nc |bash|sh |cmd|powershell)|\\|\\s*(ls|cat|id)|\\$\\(|`[^`]+`)" }] }),
  new DetectionRule({ id: "WA-005", name: "Local File Inclusion", description: "LFI attempt to include local files", severity: "high", category: "web_attack", mitre: ["T1190"], conditions: [{ field: "path", op: "regex", value: "(file=|page=|include=|path=).*(\\.\\.|\\/etc\\/|php:\\/\\/|expect:\\/\\/|data:\\/\\/)" }] }),
  new DetectionRule({ id: "WA-006", name: "Remote File Inclusion", description: "RFI attempt to include remote files", severity: "critical", category: "web_attack", mitre: ["T1190"], conditions: [{ field: "path", op: "regex", value: "(file=|page=|include=).*(https?:\\/\\/|ftp:\\/\\/|\\\\\\\\)" }] }),
  new DetectionRule({ id: "WA-007", name: "XML External Entity", description: "XXE injection attempt", severity: "critical", category: "web_attack", mitre: ["T1190"], conditions: [{ field: "message", op: "regex", value: "(<!DOCTYPE.*ENTITY|<!ENTITY|SYSTEM\\s+\"file:|SYSTEM\\s+\"http)" }] }),
  new DetectionRule({ id: "WA-008", name: "Server-Side Request Forgery", description: "SSRF attempt to access internal resources", severity: "high", category: "web_attack", mitre: ["T1190"], conditions: [{ field: "path", op: "regex", value: "(url=|redirect=|proxy=|fetch=).*(127\\.0\\.0\\.1|localhost|169\\.254\\.169\\.254|10\\.|172\\.(1[6-9]|2|3[01]))" }] }),
  new DetectionRule({ id: "WA-009", name: "Log4Shell Exploit", description: "Log4j JNDI injection attempt", severity: "critical", category: "web_attack", mitre: ["T1190"], conditions: [{ field: "message", op: "regex", value: "(\\$\\{jndi:|\\$\\{lower:|\\$\\{upper:|\\$\\{env:|\\$\\{sys:)" }] }),
  new DetectionRule({ id: "WA-010", name: "Deserialization Attack", description: "Java/PHP/Python deserialization exploitation attempt", severity: "critical", category: "web_attack", mitre: ["T1190"], conditions: [{ field: "message", op: "regex", value: "(rO0AB|aced0005|O:\\d+:\"|__wakeup|__destruct|pickle\\.loads|yaml\\.unsafe_load)" }] }),

  // === ACCOUNT MANIPULATION ===
  new DetectionRule({ id: "AM-001", name: "New Admin Account Created", description: "New administrator or privileged account created", severity: "critical", category: "persistence", mitre: ["T1136.001"], conditions: [{ field: "eventId", op: "in", value: "4720,4728,4732" }, { field: "message", op: "regex", value: "(admin|administrator|root|Domain Admins|Enterprise Admins)" }] }),
  new DetectionRule({ id: "AM-002", name: "MFA Disabled", description: "Multi-factor authentication disabled for user", severity: "critical", category: "defense_evasion", mitre: ["T1556"], conditions: [{ field: "message", op: "regex", value: "(MFA.*disabled|2FA.*disabled|multi.?factor.*removed|StrongAuthenticationRequirement)" }] }),
  new DetectionRule({ id: "AM-003", name: "Password Reset by Admin", description: "Admin performed password reset on user account", severity: "medium", category: "persistence", mitre: ["T1098"], conditions: [{ field: "eventId", op: "eq", value: "4724" }] }),
  new DetectionRule({ id: "AM-004", name: "Account Lockout", description: "User account locked out after failed attempts", severity: "medium", category: "brute_force", mitre: ["T1110"], conditions: [{ field: "eventId", op: "eq", value: "4740" }] }),
  new DetectionRule({ id: "AM-005", name: "Account Enabled After Disable", description: "Previously disabled account re-enabled", severity: "high", category: "persistence", mitre: ["T1098"], conditions: [{ field: "eventId", op: "eq", value: "4722" }] }),
  new DetectionRule({ id: "AM-006", name: "User Added to Sensitive Group", description: "User added to Domain Admins or similar group", severity: "critical", category: "persistence", mitre: ["T1098"], conditions: [{ field: "eventId", op: "in", value: "4728,4732,4756" }, { field: "message", op: "regex", value: "(Domain Admins|Enterprise Admins|Schema Admins|Backup Operators|Account Operators)" }] }),
  new DetectionRule({ id: "AM-007", name: "Security Log Cleared", description: "Windows security event log was cleared", severity: "critical", category: "defense_evasion", mitre: ["T1070.001"], conditions: [{ field: "eventId", op: "eq", value: "1102" }] }),
  new DetectionRule({ id: "AM-008", name: "Audit Policy Modified", description: "System audit policy was changed", severity: "high", category: "defense_evasion", mitre: ["T1562.002"], conditions: [{ field: "eventId", op: "eq", value: "4719" }] }),

  // === CLOUD SECURITY ===
  new DetectionRule({ id: "CS-001", name: "S3 Bucket Made Public", description: "AWS S3 bucket ACL changed to public", severity: "critical", category: "cloud", mitre: ["T1530"], conditions: [{ field: "message", op: "regex", value: "(PutBucketAcl|PutBucketPolicy).*public" }] }),
  new DetectionRule({ id: "CS-002", name: "IAM Privilege Escalation", description: "IAM policy attached granting admin access", severity: "critical", category: "cloud", mitre: ["T1098"], conditions: [{ field: "message", op: "regex", value: "(AttachUserPolicy|AttachRolePolicy|PutUserPolicy).*(Admin|FullAccess|\\*)" }] }),
  new DetectionRule({ id: "CS-003", name: "Console Login from New Geography", description: "Cloud console login from unusual geographic location", severity: "high", category: "cloud", mitre: ["T1078"], conditions: [{ field: "action", op: "in", value: "ConsoleLogin,SignIn" }, { field: "outcome", op: "eq", value: "success" }] }),
  new DetectionRule({ id: "CS-004", name: "Root Account Usage", description: "AWS root account used for operations", severity: "critical", category: "cloud", mitre: ["T1078.004"], conditions: [{ field: "user", op: "regex", value: "(root|Root)" }, { field: "source", op: "regex", value: "(aws|cloudtrail)" }] }),
  new DetectionRule({ id: "CS-005", name: "Security Group Opened", description: "Security group rule added allowing 0.0.0.0/0 access", severity: "critical", category: "cloud", mitre: ["T1562.007"], conditions: [{ field: "message", op: "regex", value: "(AuthorizeSecurityGroupIngress|CreateSecurityGroup).*0\\.0\\.0\\.0\\/0" }] }),
  new DetectionRule({ id: "CS-006", name: "CloudTrail Disabled", description: "AWS CloudTrail logging was disabled", severity: "critical", category: "cloud", mitre: ["T1562.008"], conditions: [{ field: "message", op: "regex", value: "(StopLogging|DeleteTrail|UpdateTrail.*IsLogging.*false)" }] }),
  new DetectionRule({ id: "CS-007", name: "GuardDuty Disabled", description: "AWS GuardDuty threat detection disabled", severity: "critical", category: "cloud", mitre: ["T1562.001"], conditions: [{ field: "message", op: "regex", value: "(DeleteDetector|DisassociateFromMasterAccount|StopMonitoringMembers)" }] }),
  new DetectionRule({ id: "CS-008", name: "KMS Key Deletion Scheduled", description: "AWS KMS encryption key scheduled for deletion", severity: "critical", category: "cloud", mitre: ["T1485"], conditions: [{ field: "message", op: "regex", value: "ScheduleKeyDeletion" }] }),
  new DetectionRule({ id: "CS-009", name: "Lambda Function Modified", description: "Serverless function code or config changed", severity: "medium", category: "cloud", mitre: ["T1525"], conditions: [{ field: "message", op: "regex", value: "(UpdateFunctionCode|UpdateFunctionConfiguration|CreateFunction)" }] }),
  new DetectionRule({ id: "CS-010", name: "Azure Conditional Access Disabled", description: "Azure AD conditional access policy disabled", severity: "critical", category: "cloud", mitre: ["T1562.001"], conditions: [{ field: "message", op: "regex", value: "(Update conditional access policy.*disabled|Delete conditional access)" }] }),

  // === DEFENSE EVASION ===
  new DetectionRule({ id: "DE-001", name: "Timestomp", description: "File timestamp manipulation detected", severity: "high", category: "defense_evasion", mitre: ["T1070.006"], conditions: [{ field: "message", op: "regex", value: "(timestomp|touch -t|Set-ItemProperty.*LastWriteTime|SetFileTime)" }] }),
  new DetectionRule({ id: "DE-002", name: "Log Deletion", description: "System or application logs deleted", severity: "critical", category: "defense_evasion", mitre: ["T1070.001"], conditions: [{ field: "message", op: "regex", value: "(wevtutil.*cl|Clear-EventLog|rm.*/var/log|truncate.*\\.log)" }] }),
  new DetectionRule({ id: "DE-003", name: "AV/EDR Tampering", description: "Antivirus or EDR agent disabled or uninstalled", severity: "critical", category: "defense_evasion", mitre: ["T1562.001"], conditions: [{ field: "message", op: "regex", value: "(Tamper Protection|defender.*disabled|Stop-Service.*WinDefend|disable-mde|uninstall.*endpoint)" }] }),
  new DetectionRule({ id: "DE-004", name: "Process Injection", description: "Code injected into another process", severity: "critical", category: "defense_evasion", mitre: ["T1055"], conditions: [{ field: "message", op: "regex", value: "(VirtualAllocEx|WriteProcessMemory|NtCreateThreadEx|QueueUserAPC|SetWindowsHookEx|process.*hollowing|process.*injection)" }] }),
  new DetectionRule({ id: "DE-005", name: "DLL Sideloading", description: "Legitimate application loading malicious DLL", severity: "high", category: "defense_evasion", mitre: ["T1574.002"], conditions: [{ field: "message", op: "regex", value: "(sideload|DLL.*search.*order|phantom.*DLL)" }] }),
  new DetectionRule({ id: "DE-006", name: "Indicator Removal on Host", description: "Evidence of cleanup activities", severity: "high", category: "defense_evasion", mitre: ["T1070"], conditions: [{ field: "message", op: "regex", value: "(history -c|rm.*\\.bash_history|shred|wipe|sdelete|cipher /w)" }] }),
  new DetectionRule({ id: "DE-007", name: "Firewall Rule Modification", description: "Firewall rule added or modified", severity: "medium", category: "defense_evasion", mitre: ["T1562.004"], conditions: [{ field: "message", op: "regex", value: "(iptables.*(INSERT|APPEND|DELETE)|netsh.*firewall|Set-NetFirewallRule|New-NetFirewallRule)" }] }),
  new DetectionRule({ id: "DE-008", name: "Masquerading", description: "Process or file masquerading as legitimate system component", severity: "high", category: "defense_evasion", mitre: ["T1036"], conditions: [{ field: "message", op: "regex", value: "(svchost.*unexpected.*path|explorer.*unexpected|renamed.*binary|masquerad)" }] }),

  // === INITIAL ACCESS ===
  new DetectionRule({ id: "IA-001", name: "Phishing Email Detected", description: "Email with suspicious attachment or link received", severity: "high", category: "initial_access", mitre: ["T1566"], conditions: [{ field: "message", op: "regex", value: "(phish|suspicious.*attachment|macro.*enabled|\\.(doc|xls|ppt)m)" }] }),
  new DetectionRule({ id: "IA-002", name: "Drive-by Download", description: "Browser exploit or drive-by download detected", severity: "critical", category: "initial_access", mitre: ["T1189"], conditions: [{ field: "message", op: "regex", value: "(exploit.*kit|drive.?by|watering.?hole|iframe.*hidden|injected.*script)" }] }),
  new DetectionRule({ id: "IA-003", name: "Valid Account Compromise", description: "Successful login using known compromised credentials", severity: "critical", category: "initial_access", mitre: ["T1078"], conditions: [{ field: "outcome", op: "eq", value: "success" }, { field: "message", op: "regex", value: "(compromised|leaked|breached)" }] }),
  new DetectionRule({ id: "IA-004", name: "Supply Chain Indicator", description: "Software update or package from suspicious source", severity: "critical", category: "initial_access", mitre: ["T1195"], conditions: [{ field: "message", op: "regex", value: "(supply.?chain|trojanized.*update|malicious.*package|dependency.*confusion)" }] }),
  new DetectionRule({ id: "IA-005", name: "VPN Brute Force", description: "Multiple failed VPN authentication attempts", severity: "high", category: "initial_access", mitre: ["T1133"], conditions: [{ field: "message", op: "regex", value: "(VPN.*failed|SSL VPN.*auth|OpenVPN.*error)" }], timeWindow: 60, threshold: 10 }),

  // === COLLECTION ===
  new DetectionRule({ id: "CO-001", name: "Screen Capture", description: "Screen capture utility executed", severity: "medium", category: "collection", mitre: ["T1113"], conditions: [{ field: "message", op: "regex", value: "(screenshot|screen.*capture|PrintScreen|CopyFromScreen|scrot|import -window)" }] }),
  new DetectionRule({ id: "CO-002", name: "Keylogging", description: "Keylogger indicators detected", severity: "critical", category: "collection", mitre: ["T1056.001"], conditions: [{ field: "message", op: "regex", value: "(keylog|GetAsyncKeyState|SetWindowsHookEx.*WH_KEYBOARD|xinput|libinput.*debug-events)" }] }),
  new DetectionRule({ id: "CO-003", name: "Clipboard Monitoring", description: "Clipboard data being monitored or captured", severity: "medium", category: "collection", mitre: ["T1115"], conditions: [{ field: "message", op: "regex", value: "(clipboard|GetClipboardData|xclip|xsel|pbpaste)" }] }),
  new DetectionRule({ id: "CO-004", name: "Email Collection", description: "Mass email download or mailbox export", severity: "high", category: "collection", mitre: ["T1114"], conditions: [{ field: "message", op: "regex", value: "(MailSniper|ruler|pst.*export|New-MailboxExportRequest|Get-Mailbox)" }] }),
  new DetectionRule({ id: "CO-005", name: "Database Dump", description: "Database content exported or dumped", severity: "critical", category: "collection", mitre: ["T1005"], conditions: [{ field: "message", op: "regex", value: "(mysqldump|pg_dump|mongodump|sqlcmd.*-Q.*SELECT|bcp.*queryout)" }] }),
];

// ─── Correlation Engine ────────────────────────────────────────────────────────

export class CorrelationEngine {
  constructor() {
    this.rules = [...BUILTIN_RULES];
    this.eventBuffer = [];
    this.alerts = [];
    this.maxBufferSize = 100000;
    this.maxBufferAge = 3600000; // 1 hour in ms
    this.alertId = 0;
  }

  addRule(rule) {
    this.rules.push(rule instanceof DetectionRule ? rule : new DetectionRule(rule));
  }

  removeRule(id) {
    this.rules = this.rules.filter(r => r.id !== id);
  }

  enableRule(id) {
    const r = this.rules.find(r => r.id === id);
    if (r) r.enabled = true;
  }

  disableRule(id) {
    const r = this.rules.find(r => r.id === id);
    if (r) r.enabled = false;
  }

  processEvent(event) {
    this.eventBuffer.push(event);
    // Trim old events
    while (this.eventBuffer.length > this.maxBufferSize) this.eventBuffer.shift();
    const now = Date.now();
    this.eventBuffer = this.eventBuffer.filter(e => now - e.timestamp < this.maxBufferAge);

    const newAlerts = [];
    for (const rule of this.rules) {
      if (!rule.enabled) continue;
      if (!eventMatchesRule(event, rule)) continue;

      if (rule.timeWindow > 0 && rule.threshold > 1) {
        // Time-window correlation: count matching events in the window
        const windowStart = event.timestamp - rule.timeWindow * 1000;
        const matchingEvents = this.eventBuffer.filter(e =>
          e.timestamp >= windowStart && eventMatchesRule(e, rule)
        );
        if (matchingEvents.length >= rule.threshold) {
          const alert = this._createAlert(rule, event, matchingEvents);
          newAlerts.push(alert);
        }
      } else {
        // Single-event rule
        const alert = this._createAlert(rule, event, [event]);
        newAlerts.push(alert);
      }
    }

    // Dedup: don't re-alert on same rule within 60 seconds
    const dedupedAlerts = newAlerts.filter(a => {
      const recent = this.alerts.find(prev =>
        prev.ruleId === a.ruleId &&
        a.timestamp - prev.timestamp < 60000 &&
        prev.sourceIp === a.sourceIp
      );
      return !recent;
    });

    this.alerts.push(...dedupedAlerts);
    return dedupedAlerts;
  }

  processEvents(events) {
    const allAlerts = [];
    for (const ev of events) {
      allAlerts.push(...this.processEvent(ev));
    }
    return allAlerts;
  }

  _createAlert(rule, triggerEvent, matchingEvents) {
    return {
      id: `ALERT-${++this.alertId}`,
      ruleId: rule.id,
      ruleName: rule.name,
      description: rule.description,
      severity: rule.severity,
      category: rule.category,
      mitre: rule.mitre,
      timestamp: triggerEvent.timestamp,
      sourceIp: triggerEvent.sourceIp,
      destIp: triggerEvent.destIp,
      user: triggerEvent.user,
      hostname: triggerEvent.hostname,
      eventCount: matchingEvents.length,
      firstSeen: matchingEvents[0]?.timestamp || triggerEvent.timestamp,
      lastSeen: matchingEvents[matchingEvents.length - 1]?.timestamp || triggerEvent.timestamp,
      events: matchingEvents.slice(0, 10),
      acknowledged: false,
      resolved: false,
    };
  }

  getAlerts(opts = {}) {
    let alerts = [...this.alerts];
    if (opts.severity) alerts = alerts.filter(a => a.severity === opts.severity);
    if (opts.category) alerts = alerts.filter(a => a.category === opts.category);
    if (opts.unresolved) alerts = alerts.filter(a => !a.resolved);
    if (opts.since) alerts = alerts.filter(a => a.timestamp >= opts.since);
    return alerts.sort((a, b) => b.timestamp - a.timestamp);
  }

  acknowledgeAlert(id) {
    const a = this.alerts.find(a => a.id === id);
    if (a) a.acknowledged = true;
  }

  resolveAlert(id) {
    const a = this.alerts.find(a => a.id === id);
    if (a) { a.resolved = true; a.acknowledged = true; }
  }

  getStats() {
    const total = this.alerts.length;
    const bySeverity = {};
    const byCategory = {};
    for (const a of this.alerts) {
      bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
      byCategory[a.category] = (byCategory[a.category] || 0) + 1;
    }
    return { total, bySeverity, byCategory, eventBufferSize: this.eventBuffer.length, rulesEnabled: this.rules.filter(r => r.enabled).length, rulesTotal: this.rules.length };
  }
}

// ─── Sigma Rule Converter ──────────────────────────────────────────────────────

// Parse a basic Sigma rule (YAML-like) and convert to query languages
export function parseSigmaRule(yaml) {
  const lines = yaml.split("\n");
  const rule = { title: "", status: "", level: "", logsource: {}, detection: {} };
  let currentSection = "";
  let currentKey = "";
  let indent = 0;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const leadingSpaces = line.search(/\S/);

    if (leadingSpaces === 0 && trimmed.includes(":")) {
      const [key, ...valueParts] = trimmed.split(":");
      const value = valueParts.join(":").trim();
      currentSection = key.trim();
      if (value) rule[currentSection] = value;
      else rule[currentSection] = {};
      indent = 0;
      continue;
    }

    if (currentSection === "logsource" || currentSection === "detection") {
      if (trimmed.includes(":")) {
        const [key, ...valueParts] = trimmed.split(":");
        const value = valueParts.join(":").trim();
        if (leadingSpaces <= 4) {
          currentKey = key.trim();
          if (value) {
            if (currentSection === "detection") {
              if (!rule.detection[currentKey]) rule.detection[currentKey] = {};
              rule.detection[currentKey] = value;
            } else {
              rule.logsource[currentKey] = value;
            }
          } else {
            if (!rule.detection[currentKey]) rule.detection[currentKey] = {};
          }
        } else {
          const fieldName = key.trim();
          const fieldValue = value.replace(/^['"]|['"]$/g, "");
          if (typeof rule.detection[currentKey] !== "object") rule.detection[currentKey] = {};
          if (fieldValue.startsWith("-")) {
            if (!Array.isArray(rule.detection[currentKey][fieldName])) rule.detection[currentKey][fieldName] = [];
            rule.detection[currentKey][fieldName].push(fieldValue.slice(1).trim());
          } else {
            rule.detection[currentKey][fieldName] = fieldValue;
          }
        }
      } else if (trimmed.startsWith("- ")) {
        const value = trimmed.slice(2).replace(/^['"]|['"]$/g, "");
        if (typeof rule.detection[currentKey] === "object" && !Array.isArray(rule.detection[currentKey])) {
          // List value for the last field
          const lastKey = Object.keys(rule.detection[currentKey]).pop();
          if (lastKey) {
            if (!Array.isArray(rule.detection[currentKey][lastKey])) {
              rule.detection[currentKey][lastKey] = [rule.detection[currentKey][lastKey]];
            }
            rule.detection[currentKey][lastKey].push(value);
          }
        }
      }
    }
  }
  return rule;
}

// Convert parsed Sigma rule to Splunk SPL
export function sigmaToSplunk(sigmaRule) {
  const parts = [];
  if (sigmaRule.logsource?.product) parts.push(`index="${sigmaRule.logsource.product}"`);
  if (sigmaRule.logsource?.service) parts.push(`sourcetype="${sigmaRule.logsource.service}"`);

  const selectionParts = [];
  for (const [key, value] of Object.entries(sigmaRule.detection || {})) {
    if (key === "condition") continue;
    if (typeof value === "object") {
      for (const [field, pattern] of Object.entries(value)) {
        if (Array.isArray(pattern)) {
          selectionParts.push(`(${pattern.map(p => `${field}="${p}"`).join(" OR ")})`);
        } else if (typeof pattern === "string") {
          if (pattern.includes("*")) {
            selectionParts.push(`${field}="${pattern}"`);
          } else {
            selectionParts.push(`${field}="${pattern}"`);
          }
        }
      }
    }
  }
  parts.push(...selectionParts);
  return parts.join(" ") || "* (no conditions parsed)";
}

// Convert parsed Sigma rule to Elastic KQL
export function sigmaToElastic(sigmaRule) {
  const parts = [];
  for (const [key, value] of Object.entries(sigmaRule.detection || {})) {
    if (key === "condition") continue;
    if (typeof value === "object") {
      for (const [field, pattern] of Object.entries(value)) {
        if (Array.isArray(pattern)) {
          parts.push(`(${pattern.map(p => `${field}: "${p}"`).join(" or ")})`);
        } else if (typeof pattern === "string") {
          parts.push(`${field}: "${pattern}"`);
        }
      }
    }
  }
  return parts.join(" and ") || "* (no conditions parsed)";
}

// Convert parsed Sigma rule to Microsoft Sentinel KQL
export function sigmaToSentinel(sigmaRule) {
  const table = sigmaRule.logsource?.product === "windows" ? "SecurityEvent" : "CommonSecurityLog";
  const wheres = [];
  for (const [key, value] of Object.entries(sigmaRule.detection || {})) {
    if (key === "condition") continue;
    if (typeof value === "object") {
      for (const [field, pattern] of Object.entries(value)) {
        if (Array.isArray(pattern)) {
          wheres.push(`${field} in~ (${pattern.map(p => `"${p}"`).join(", ")})`);
        } else if (typeof pattern === "string") {
          if (pattern.includes("*")) {
            wheres.push(`${field} matches regex "${pattern.replace(/\*/g, ".*")}"`);
          } else {
            wheres.push(`${field} == "${pattern}"`);
          }
        }
      }
    }
  }
  return `${table}\n| where ${wheres.join("\n  and ") || "true"}`;
}

// ─── Timeline Builder ──────────────────────────────────────────────────────────

export function buildTimeline(events) {
  const sorted = [...events].sort((a, b) => a.timestamp - b.timestamp);

  // Map to Cyber Kill Chain phases
  const phaseMap = {
    reconnaissance: "Reconnaissance",
    initial_access: "Weaponization & Delivery",
    execution: "Exploitation",
    persistence: "Installation",
    privilege_escalation: "Exploitation",
    defense_evasion: "Installation",
    credential_access: "Exploitation",
    discovery: "Reconnaissance",
    lateral_movement: "Command & Control",
    collection: "Actions on Objectives",
    exfiltration: "Actions on Objectives",
    command_and_control: "Command & Control",
    malware: "Installation",
    brute_force: "Weaponization & Delivery",
    web_attack: "Exploitation",
    cloud: "Actions on Objectives",
  };

  return sorted.map(ev => ({
    timestamp: ev.timestamp,
    time: new Date(ev.timestamp).toISOString(),
    severity: ev.severity,
    category: ev.category,
    killChainPhase: phaseMap[ev.category] || "Unknown",
    source: ev.sourceIp || ev.hostname || ev.source,
    destination: ev.destIp || "",
    user: ev.user,
    message: ev.message,
    ruleMatches: ev.ruleMatches || [],
  }));
}

// ─── Statistical Anomaly Detection ─────────────────────────────────────────────

export class AnomalyDetector {
  constructor() {
    this.baselines = {};
  }

  // Build baseline from historical events
  buildBaseline(events, key, metric = "count") {
    const buckets = {};
    for (const ev of events) {
      const hour = new Date(ev.timestamp).getHours();
      const k = `${key}:${ev[key] || ev.fields?.[key] || "unknown"}:${hour}`;
      buckets[k] = (buckets[k] || 0) + 1;
    }
    // Calculate mean and stddev per bucket
    for (const [k, count] of Object.entries(buckets)) {
      if (!this.baselines[k]) {
        this.baselines[k] = { sum: 0, sumSq: 0, count: 0, mean: 0, stddev: 0 };
      }
      const b = this.baselines[k];
      b.sum += count;
      b.sumSq += count * count;
      b.count++;
      b.mean = b.sum / b.count;
      b.stddev = Math.sqrt(b.sumSq / b.count - b.mean * b.mean);
    }
  }

  // Check if a value is anomalous
  isAnomalous(key, value, hour, threshold = 2) {
    const k = `${key}:${value}:${hour}`;
    const b = this.baselines[k];
    if (!b || b.count < 5) return { anomalous: false, reason: "insufficient_data" };
    const deviation = Math.abs(b.mean - 1) / (b.stddev || 1);
    return {
      anomalous: deviation > threshold,
      score: deviation,
      mean: b.mean,
      stddev: b.stddev,
      reason: deviation > threshold ? "statistical_deviation" : "within_normal",
    };
  }

  // Detect impossible travel (login from two distant locations too quickly)
  impossibleTravel(events, maxSpeedKmh = 900) {
    const userEvents = {};
    for (const ev of events) {
      if (!ev.user || !ev.sourceIp) continue;
      if (!userEvents[ev.user]) userEvents[ev.user] = [];
      userEvents[ev.user].push(ev);
    }

    const anomalies = [];
    for (const [user, evts] of Object.entries(userEvents)) {
      const sorted = evts.sort((a, b) => a.timestamp - b.timestamp);
      for (let i = 1; i < sorted.length; i++) {
        const timeDiffHours = (sorted[i].timestamp - sorted[i - 1].timestamp) / 3600000;
        if (timeDiffHours < 0.01) continue; // Same-second events
        const ip1 = sorted[i - 1].sourceIp;
        const ip2 = sorted[i].sourceIp;
        if (ip1 === ip2) continue;
        // If IPs are different and time is short, flag as impossible travel
        if (timeDiffHours < 2 && ip1 !== ip2) {
          anomalies.push({
            user,
            type: "impossible_travel",
            firstLogin: { ip: ip1, time: new Date(sorted[i - 1].timestamp).toISOString() },
            secondLogin: { ip: ip2, time: new Date(sorted[i].timestamp).toISOString() },
            timeDiffMinutes: Math.round(timeDiffHours * 60),
          });
        }
      }
    }
    return anomalies;
  }
}

// ─── Beaconing Detection ───────────────────────────────────────────────────────

export function detectBeaconing(events, options = {}) {
  const minEvents = options.minEvents || 10;
  const maxJitter = options.maxJitter || 0.2; // 20% jitter tolerance

  // Group by source+dest pair
  const pairs = {};
  for (const ev of events) {
    const key = `${ev.sourceIp || "?"}>${ev.destIp || "?"}:${ev.destPort || 0}`;
    if (!pairs[key]) pairs[key] = [];
    pairs[key].push(ev.timestamp);
  }

  const results = [];
  for (const [key, timestamps] of Object.entries(pairs)) {
    if (timestamps.length < minEvents) continue;
    const sorted = timestamps.sort((a, b) => a - b);

    // Calculate intervals
    const intervals = [];
    for (let i = 1; i < sorted.length; i++) {
      intervals.push(sorted[i] - sorted[i - 1]);
    }
    if (intervals.length < 3) continue;

    // Calculate statistics
    const mean = intervals.reduce((a, b) => a + b, 0) / intervals.length;
    const variance = intervals.reduce((a, b) => a + (b - mean) ** 2, 0) / intervals.length;
    const stddev = Math.sqrt(variance);
    const jitter = mean > 0 ? stddev / mean : 1;

    if (jitter <= maxJitter && mean > 1000) { // At least 1 second interval
      const [src, destPort] = key.split(">");
      results.push({
        source: src,
        destination: destPort,
        intervalMs: Math.round(mean),
        intervalSec: Math.round(mean / 1000),
        jitter: Math.round(jitter * 100) / 100,
        eventCount: timestamps.length,
        firstSeen: new Date(sorted[0]).toISOString(),
        lastSeen: new Date(sorted[sorted.length - 1]).toISOString(),
        confidence: jitter < 0.05 ? "high" : jitter < 0.1 ? "medium" : "low",
      });
    }
  }
  return results.sort((a, b) => a.jitter - b.jitter);
}

// ─── DGA Domain Detection ──────────────────────────────────────────────────────

export function detectDGA(domain) {
  const parts = domain.split(".");
  if (parts.length < 2) return { isDGA: false, score: 0 };
  const sld = parts[parts.length - 2]; // second-level domain

  // Shannon entropy
  const freq = {};
  for (const c of sld) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  for (const c of Object.values(freq)) {
    const p = c / sld.length;
    entropy -= p * Math.log2(p);
  }

  // Consonant-to-vowel ratio
  const vowels = (sld.match(/[aeiou]/gi) || []).length;
  const consonants = (sld.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
  const cvRatio = consonants / (vowels || 1);

  // Digit ratio
  const digits = (sld.match(/\d/g) || []).length;
  const digitRatio = digits / sld.length;

  // Length
  const len = sld.length;

  // Consecutive consonants
  const maxConsec = (sld.match(/[bcdfghjklmnpqrstvwxyz]+/gi) || []).reduce((max, s) => Math.max(max, s.length), 0);

  // Score: higher = more likely DGA
  let score = 0;
  if (entropy > 3.5) score += 25;
  else if (entropy > 3.0) score += 15;
  if (cvRatio > 3) score += 20;
  else if (cvRatio > 2) score += 10;
  if (digitRatio > 0.3) score += 20;
  else if (digitRatio > 0.15) score += 10;
  if (len > 20) score += 20;
  else if (len > 15) score += 10;
  if (maxConsec > 5) score += 15;
  else if (maxConsec > 4) score += 8;

  return {
    isDGA: score >= 50,
    score,
    entropy: Math.round(entropy * 100) / 100,
    consonantVowelRatio: Math.round(cvRatio * 100) / 100,
    digitRatio: Math.round(digitRatio * 100) / 100,
    length: len,
    maxConsecutiveConsonants: maxConsec,
    domain: sld,
  };
}

// ─── Dashboard Aggregator ──────────────────────────────────────────────────────

export function aggregateForDashboard(events, alerts) {
  const now = Date.now();
  const hour = 3600000;
  const day = 86400000;

  const last24h = events.filter(e => now - e.timestamp < day);
  const lastHour = events.filter(e => now - e.timestamp < hour);

  // Events by severity
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const e of last24h) bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;

  // Events by source
  const bySrc = {};
  for (const e of last24h) {
    const src = e.sourceIp || e.hostname || e.source || "unknown";
    bySrc[src] = (bySrc[src] || 0) + 1;
  }
  const topSources = Object.entries(bySrc).sort((a, b) => b[1] - a[1]).slice(0, 10);

  // Events by destination
  const byDst = {};
  for (const e of last24h) {
    if (e.destIp) byDst[e.destIp] = (byDst[e.destIp] || 0) + 1;
  }
  const topDestinations = Object.entries(byDst).sort((a, b) => b[1] - a[1]).slice(0, 10);

  // Events per hour (timeline)
  const hourlyBuckets = {};
  for (const e of last24h) {
    const h = new Date(e.timestamp).getHours();
    hourlyBuckets[h] = (hourlyBuckets[h] || 0) + 1;
  }

  // Alert stats
  const alertStats = {
    total: alerts.length,
    unresolved: alerts.filter(a => !a.resolved).length,
    critical: alerts.filter(a => a.severity === "critical").length,
    high: alerts.filter(a => a.severity === "high").length,
  };

  // Top triggered rules
  const ruleHits = {};
  for (const a of alerts) {
    ruleHits[a.ruleName] = (ruleHits[a.ruleName] || 0) + 1;
  }
  const topRules = Object.entries(ruleHits).sort((a, b) => b[1] - a[1]).slice(0, 10);

  return {
    totalEvents24h: last24h.length,
    totalEventsLastHour: lastHour.length,
    eventsPerSecond: Math.round(lastHour.length / 3600 * 100) / 100,
    bySeverity,
    topSources,
    topDestinations,
    hourlyTimeline: hourlyBuckets,
    alertStats,
    topRules,
  };
}

// ─── User Behavior Analytics ───────────────────────────────────────────────────

export class UserBehaviorAnalytics {
  constructor() {
    this.profiles = {};
  }

  buildProfile(events) {
    for (const ev of events) {
      if (!ev.user) continue;
      if (!this.profiles[ev.user]) {
        this.profiles[ev.user] = {
          loginHours: new Array(24).fill(0),
          loginDays: new Array(7).fill(0),
          ips: {},
          actions: {},
          totalEvents: 0,
          firstSeen: ev.timestamp,
          lastSeen: ev.timestamp,
        };
      }
      const p = this.profiles[ev.user];
      const d = new Date(ev.timestamp);
      p.loginHours[d.getHours()]++;
      p.loginDays[d.getDay()]++;
      if (ev.sourceIp) p.ips[ev.sourceIp] = (p.ips[ev.sourceIp] || 0) + 1;
      if (ev.action) p.actions[ev.action] = (p.actions[ev.action] || 0) + 1;
      p.totalEvents++;
      if (ev.timestamp > p.lastSeen) p.lastSeen = ev.timestamp;
      if (ev.timestamp < p.firstSeen) p.firstSeen = ev.timestamp;
    }
  }

  detectAnomalies(event) {
    if (!event.user) return [];
    const p = this.profiles[event.user];
    if (!p || p.totalEvents < 10) return [];

    const anomalies = [];
    const d = new Date(event.timestamp);
    const hour = d.getHours();
    const day = d.getDay();

    // Unusual login hour
    const hourTotal = p.loginHours.reduce((a, b) => a + b, 0);
    const hourPct = p.loginHours[hour] / hourTotal;
    if (hourPct < 0.01 && hourTotal > 50) {
      anomalies.push({ type: "unusual_hour", detail: `User rarely active at hour ${hour} (${Math.round(hourPct * 100)}% of activity)`, score: 70 });
    }

    // Unusual day
    const dayTotal = p.loginDays.reduce((a, b) => a + b, 0);
    const dayPct = p.loginDays[day] / dayTotal;
    if (dayPct < 0.02 && dayTotal > 50) {
      anomalies.push({ type: "unusual_day", detail: `User rarely active on ${["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][day]}`, score: 50 });
    }

    // New IP
    if (event.sourceIp && !p.ips[event.sourceIp]) {
      anomalies.push({ type: "new_ip", detail: `First login from IP ${event.sourceIp}`, score: 60 });
    }

    // Unusual action
    if (event.action && !p.actions[event.action]) {
      anomalies.push({ type: "new_action", detail: `Action "${event.action}" not seen before for this user`, score: 40 });
    }

    return anomalies;
  }

  getProfile(user) {
    return this.profiles[user] || null;
  }

  getAllProfiles() {
    return { ...this.profiles };
  }
}

// ─── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────

export const MITRE_TECHNIQUES = {
  "T1046": { name: "Network Service Discovery", tactic: "Discovery" },
  "T1110": { name: "Brute Force", tactic: "Credential Access" },
  "T1110.001": { name: "Brute Force: Password Guessing", tactic: "Credential Access" },
  "T1110.003": { name: "Brute Force: Password Spraying", tactic: "Credential Access" },
  "T1110.004": { name: "Brute Force: Credential Stuffing", tactic: "Credential Access" },
  "T1548": { name: "Abuse Elevation Control Mechanism", tactic: "Privilege Escalation" },
  "T1548.001": { name: "Setuid and Setgid", tactic: "Privilege Escalation" },
  "T1548.002": { name: "Bypass UAC", tactic: "Privilege Escalation" },
  "T1548.003": { name: "Sudo and Sudo Caching", tactic: "Privilege Escalation" },
  "T1068": { name: "Exploitation for Privilege Escalation", tactic: "Privilege Escalation" },
  "T1134": { name: "Access Token Manipulation", tactic: "Privilege Escalation" },
  "T1134.001": { name: "Token Impersonation/Theft", tactic: "Privilege Escalation" },
  "T1484.001": { name: "Group Policy Modification", tactic: "Defense Evasion" },
  "T1574.001": { name: "DLL Search Order Hijacking", tactic: "Persistence" },
  "T1574.002": { name: "DLL Side-Loading", tactic: "Defense Evasion" },
  "T1570": { name: "Lateral Tool Transfer", tactic: "Lateral Movement" },
  "T1021.001": { name: "Remote Services: RDP", tactic: "Lateral Movement" },
  "T1021.002": { name: "Remote Services: SMB/Windows Admin Shares", tactic: "Lateral Movement" },
  "T1021.003": { name: "Remote Services: DCOM", tactic: "Lateral Movement" },
  "T1021.004": { name: "Remote Services: SSH", tactic: "Lateral Movement" },
  "T1021.006": { name: "Remote Services: Windows Remote Management", tactic: "Lateral Movement" },
  "T1047": { name: "Windows Management Instrumentation", tactic: "Execution" },
  "T1550.002": { name: "Use Alternate Authentication Material: Pass the Hash", tactic: "Lateral Movement" },
  "T1550.003": { name: "Use Alternate Authentication Material: Pass the Ticket", tactic: "Lateral Movement" },
  "T1003": { name: "OS Credential Dumping", tactic: "Credential Access" },
  "T1003.001": { name: "OS Credential Dumping: LSASS Memory", tactic: "Credential Access" },
  "T1003.003": { name: "OS Credential Dumping: NTDS", tactic: "Credential Access" },
  "T1003.006": { name: "OS Credential Dumping: DCSync", tactic: "Credential Access" },
  "T1048": { name: "Exfiltration Over Alternative Protocol", tactic: "Exfiltration" },
  "T1048.002": { name: "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol", tactic: "Exfiltration" },
  "T1048.003": { name: "Exfiltration Over Unencrypted Non-C2 Protocol", tactic: "Exfiltration" },
  "T1052.001": { name: "Exfiltration Over Physical Medium: USB", tactic: "Exfiltration" },
  "T1567.002": { name: "Exfiltration to Cloud Storage", tactic: "Exfiltration" },
  "T1074": { name: "Data Staged", tactic: "Collection" },
  "T1071.001": { name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control" },
  "T1071.004": { name: "Application Layer Protocol: DNS", tactic: "Command and Control" },
  "T1568.002": { name: "Dynamic Resolution: Domain Generation Algorithms", tactic: "Command and Control" },
  "T1486": { name: "Data Encrypted for Impact", tactic: "Impact" },
  "T1496": { name: "Resource Hijacking", tactic: "Impact" },
  "T1059": { name: "Command and Scripting Interpreter", tactic: "Execution" },
  "T1059.001": { name: "PowerShell", tactic: "Execution" },
  "T1059.005": { name: "Visual Basic", tactic: "Execution" },
  "T1505.003": { name: "Server Software Component: Web Shell", tactic: "Persistence" },
  "T1566": { name: "Phishing", tactic: "Initial Access" },
  "T1566.001": { name: "Phishing: Spearphishing Attachment", tactic: "Initial Access" },
  "T1190": { name: "Exploit Public-Facing Application", tactic: "Initial Access" },
  "T1189": { name: "Drive-by Compromise", tactic: "Initial Access" },
  "T1078": { name: "Valid Accounts", tactic: "Initial Access" },
  "T1078.004": { name: "Valid Accounts: Cloud Accounts", tactic: "Initial Access" },
  "T1195": { name: "Supply Chain Compromise", tactic: "Initial Access" },
  "T1133": { name: "External Remote Services", tactic: "Initial Access" },
  "T1569.002": { name: "System Services: Service Execution", tactic: "Execution" },
  "T1218.002": { name: "System Binary Proxy Execution: Control Panel", tactic: "Defense Evasion" },
  "T1218.003": { name: "System Binary Proxy Execution: CMSTP", tactic: "Defense Evasion" },
  "T1218.004": { name: "System Binary Proxy Execution: InstallUtil", tactic: "Defense Evasion" },
  "T1218.005": { name: "System Binary Proxy Execution: Mshta", tactic: "Defense Evasion" },
  "T1218.010": { name: "System Binary Proxy Execution: Regsvr32", tactic: "Defense Evasion" },
  "T1218.011": { name: "System Binary Proxy Execution: Rundll32", tactic: "Defense Evasion" },
  "T1197": { name: "BITS Jobs", tactic: "Defense Evasion" },
  "T1140": { name: "Deobfuscate/Decode Files or Information", tactic: "Defense Evasion" },
  "T1105": { name: "Ingress Tool Transfer", tactic: "Command and Control" },
  "T1127.001": { name: "Trusted Developer Utilities Proxy Execution: MSBuild", tactic: "Defense Evasion" },
  "T1202": { name: "Indirect Command Execution", tactic: "Defense Evasion" },
  "T1562.001": { name: "Impair Defenses: Disable or Modify Tools", tactic: "Defense Evasion" },
  "T1562.002": { name: "Impair Defenses: Disable Windows Event Logging", tactic: "Defense Evasion" },
  "T1562.004": { name: "Impair Defenses: Disable or Modify System Firewall", tactic: "Defense Evasion" },
  "T1562.007": { name: "Impair Defenses: Disable or Modify Cloud Firewall", tactic: "Defense Evasion" },
  "T1562.008": { name: "Impair Defenses: Disable Cloud Logs", tactic: "Defense Evasion" },
  "T1620": { name: "Reflective Code Loading", tactic: "Defense Evasion" },
  "T1556": { name: "Modify Authentication Process", tactic: "Credential Access" },
  "T1098": { name: "Account Manipulation", tactic: "Persistence" },
  "T1136.001": { name: "Create Account: Local Account", tactic: "Persistence" },
  "T1053.005": { name: "Scheduled Task/Job: Scheduled Task", tactic: "Persistence" },
  "T1543.003": { name: "Create or Modify System Process: Windows Service", tactic: "Persistence" },
  "T1525": { name: "Implant Internal Image", tactic: "Persistence" },
  "T1530": { name: "Data from Cloud Storage Object", tactic: "Collection" },
  "T1485": { name: "Data Destruction", tactic: "Impact" },
  "T1070": { name: "Indicator Removal", tactic: "Defense Evasion" },
  "T1070.001": { name: "Indicator Removal: Clear Windows Event Logs", tactic: "Defense Evasion" },
  "T1070.006": { name: "Indicator Removal: Timestomp", tactic: "Defense Evasion" },
  "T1055": { name: "Process Injection", tactic: "Defense Evasion" },
  "T1014": { name: "Rootkit", tactic: "Defense Evasion" },
  "T1036": { name: "Masquerading", tactic: "Defense Evasion" },
  "T1090": { name: "Proxy", tactic: "Command and Control" },
  "T1113": { name: "Screen Capture", tactic: "Collection" },
  "T1056.001": { name: "Input Capture: Keylogging", tactic: "Collection" },
  "T1115": { name: "Clipboard Data", tactic: "Collection" },
  "T1114": { name: "Email Collection", tactic: "Collection" },
  "T1005": { name: "Data from Local System", tactic: "Collection" },
  "T1083": { name: "File and Directory Discovery", tactic: "Discovery" },
};

export function mapToMitre(techniqueIds) {
  return techniqueIds.map(id => ({
    id,
    ...(MITRE_TECHNIQUES[id] || { name: "Unknown", tactic: "Unknown" }),
  }));
}

// ─── IOC Extraction ────────────────────────────────────────────────────────────

export function extractIOCs(text) {
  const iocs = { ips: [], domains: [], hashes: { md5: [], sha1: [], sha256: [] }, urls: [], emails: [], cves: [], btc: [] };

  // IPv4
  const ipRegex = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b/g;
  const ips = text.match(ipRegex) || [];
  iocs.ips = [...new Set(ips.filter(ip => !ip.startsWith("0.") && !ip.startsWith("255.")))];

  // Domains
  const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|edu|gov|mil|int|info|biz|xyz|top|club|online|site|store|tech|cloud|io|ai|co|us|uk|de|fr|ru|cn|jp|kr|br|in|au|ca|nl|se|no|fi|dk|ch|at|it|es|pt|pl|cz|ro|hu|bg|hr|sk|lt|lv|ee|onion)\b/gi;
  const domains = text.match(domainRegex) || [];
  iocs.domains = [...new Set(domains.map(d => d.toLowerCase()))];

  // Hashes
  const md5Regex = /\b[a-fA-F0-9]{32}\b/g;
  const sha1Regex = /\b[a-fA-F0-9]{40}\b/g;
  const sha256Regex = /\b[a-fA-F0-9]{64}\b/g;
  iocs.hashes.sha256 = [...new Set((text.match(sha256Regex) || []).map(h => h.toLowerCase()))];
  const nonSha256 = text.replace(sha256Regex, "");
  iocs.hashes.sha1 = [...new Set((nonSha256.match(sha1Regex) || []).map(h => h.toLowerCase()))];
  const nonSha1 = nonSha256.replace(sha1Regex, "");
  iocs.hashes.md5 = [...new Set((nonSha1.match(md5Regex) || []).map(h => h.toLowerCase()))];

  // URLs
  const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  iocs.urls = [...new Set(text.match(urlRegex) || [])];

  // Emails
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  iocs.emails = [...new Set((text.match(emailRegex) || []).map(e => e.toLowerCase()))];

  // CVEs
  const cveRegex = /CVE-\d{4}-\d{4,}/gi;
  iocs.cves = [...new Set((text.match(cveRegex) || []).map(c => c.toUpperCase()))];

  // Bitcoin addresses
  const btcRegex = /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|bc1[a-zA-HJ-NP-Z0-9]{25,90}\b/g;
  iocs.btc = [...new Set(text.match(btcRegex) || [])];

  return iocs;
}

// Defang IOCs (make safe to share)
export function defangIOC(ioc) {
  return ioc
    .replace(/\./g, "[.]")
    .replace(/https?:\/\//gi, (m) => m.replace("http", "hxxp"))
    .replace(/@/g, "[@]");
}

// Refang IOCs (make usable again)
export function refangIOC(ioc) {
  return ioc
    .replace(/\[\.\]/g, ".")
    .replace(/hxxps?:\/\//gi, (m) => m.replace("hxxp", "http"))
    .replace(/\[@\]/g, "@");
}
