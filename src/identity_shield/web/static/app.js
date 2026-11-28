/* Identity Shield Control Plane — Frontend Application */

const STATE = {
  view: "overview",
  app: null,
  analytics: null,
  selectedRuleset: "baseline-v1",
  selectedRunId: "",
  attacksData: null,
  attackCloud: "all",
  showAddAttack: false,
  variantsData: null,
  varFilterTech: "",
  varFilterSet: "",
  rulesData: null,
  rulesTab: "rules",
  showAddRule: false,
  ruleFilterCloud: "all",
  ruleFilterSet: "",
  ruleFilterLevel: "",
  auditRuleset: "baseline-v1",
  auditData: null,
  dynamicRulesData: null,
  dynamicAlertsData: null,
  showAddDynRule: false,
  proxyData: null,
  proxyProfiles: null,
  proxyTab: "traffic",
  proxySearch: "",
  proxyKind: "",
  proxyCloud: "all",
  proxyAlertsOnly: false,
  proxySimScenario: "mixed",
  proxyEventSource: null,
  logsData: null,
  logsTab: "events",
  logsRunId: "",
  logsCloud: "all",
  logsSearch: "",
  logsAlertsOnly: false,
  probeData: null,
  probeTab: "buckets",
  doctorData: null,
  templatesData: null,
  templateTab: "single-account",
  connCloud: "aws",
  connMode: "profile",
  gcpConnMode: "gcloud_adc",
  azureConnMode: "az_cli",
  mcCensusData: null,
  activeJobId: null,
  jobLines: [],
  jobStatus: "idle",
  closedLoopMode: "both",
  closedLoopCloud: "all",
  closedLoopPreview: null,
  closedLoopReport: null,
  toolsStatus: null,
  cliHistory: [],
  cliOutputs: [],
};

const VIEW_TITLES = {
  overview: "Overview",
  connections: "Connections",
  lab: "Lab Resources",
  attacks: "Attacks",
  variants: "Variants",
  campaigns: "Campaigns",
  proxy: "Live Security Proxy",
  rules: "Rules & Thresholds",
  logs: "Logs",
  cli: "CLI Console",
};

const AWS_REGIONS = [
  { value: "eu-west-1", hint: "Ireland" },
  { value: "us-east-1", hint: "N. Virginia" },
  { value: "us-east-2", hint: "Ohio" },
  { value: "us-west-2", hint: "Oregon" },
  { value: "eu-central-1", hint: "Frankfurt" },
  { value: "eu-west-2", hint: "London" },
  { value: "ap-south-1", hint: "Mumbai" },
  { value: "ap-southeast-1", hint: "Singapore" },
  { value: "ap-northeast-1", hint: "Tokyo" },
  { value: "ca-central-1", hint: "Canada" },
];

const GCP_REGIONS = [
  { value: "us-central1", hint: "Iowa" },
  { value: "us-east1", hint: "South Carolina" },
  { value: "europe-west1", hint: "Belgium" },
  { value: "europe-west2", hint: "London" },
  { value: "asia-south1", hint: "Mumbai" },
  { value: "asia-southeast1", hint: "Singapore" },
];

const AZURE_LOCATIONS = [
  { value: "eastus", hint: "East US" },
  { value: "westus2", hint: "West US 2" },
  { value: "westeurope", hint: "West Europe" },
  { value: "uksouth", hint: "UK South" },
  { value: "centralindia", hint: "Central India" },
  { value: "southeastasia", hint: "Southeast Asia" },
];

const SERVICE_OPERATIONS = {
  ec2: [
    { value: "describe_vpcs", hint: "DescribeVpcs" },
    { value: "describe_instances", hint: "DescribeInstances" },
    { value: "describe_security_groups", hint: "DescribeSecurityGroups" },
    { value: "describe_subnets", hint: "DescribeSubnets" },
    { value: "describe_regions", hint: "DescribeRegions" },
  ],
  s3: [
    { value: "list_buckets", hint: "ListBuckets" },
    { value: "head_bucket", hint: "HeadBucket" },
    { value: "list_objects_v2", hint: "ListBucket" },
    { value: "get_object", hint: "GetObject" },
  ],
  iam: [
    { value: "list_users", hint: "ListUsers" },
    { value: "list_roles", hint: "ListRoles" },
    { value: "list_policies", hint: "ListPolicies" },
    { value: "list_access_keys", hint: "ListAccessKeys" },
    { value: "get_account_authorization_details", hint: "GetAccountAuthorizationDetails" },
  ],
  sts: [
    { value: "get_caller_identity", hint: "GetCallerIdentity" },
    { value: "get_access_key_info", hint: "GetAccessKeyInfo" },
  ],
  secretsmanager: [
    { value: "list_secrets", hint: "ListSecrets" },
  ],
  kms: [
    { value: "list_keys", hint: "ListKeys" },
    { value: "list_aliases", hint: "ListAliases" },
  ],
  lambda: [
    { value: "list_functions", hint: "ListFunctions" },
  ],
  rds: [
    { value: "describe_db_instances", hint: "DescribeDBInstances" },
  ],
  cloudtrail: [
    { value: "describe_trails", hint: "DescribeTrails" },
  ],
  ssm: [
    { value: "describe_instance_information", hint: "DescribeInstanceInformation" },
  ],
};

const ATTACK_PRESETS = {
  vpc_enum: {
    technique_id: "T1538",
    name: "VPC & Network Discovery",
    tactic: "discovery",
    service: "ec2",
    operation: "describe_vpcs",
    event_names: "DescribeVpcs",
    kwargs: "{}",
    requires_data_events: false,
  },
  s3_probe: {
    technique_id: "T1530.custom",
    name: "Target Bucket Existence Check",
    tactic: "collection",
    service: "s3",
    operation: "head_bucket",
    event_names: "HeadBucket",
    kwargs: '{"Bucket": "{bucket}"}',
    requires_data_events: false,
  },
  secrets_enum: {
    technique_id: "T1555.custom",
    name: "Secrets Manager Enumeration",
    tactic: "credential-access",
    service: "secretsmanager",
    operation: "list_secrets",
    event_names: "ListSecrets",
    kwargs: "{}",
    requires_data_events: false,
  },
  iam_policies: {
    technique_id: "T1087.custom",
    name: "IAM Policy Enumeration",
    tactic: "discovery",
    service: "iam",
    operation: "list_policies",
    event_names: "ListPolicies",
    kwargs: "{}",
    requires_data_events: false,
  },
  lambda_list: {
    technique_id: "T1526.custom",
    name: "Lambda Function Discovery",
    tactic: "discovery",
    service: "lambda",
    operation: "list_functions",
    event_names: "ListFunctions",
    kwargs: "{}",
    requires_data_events: false,
  },
};

const SIGMA_TEMPLATES = {
  vpc: {
    filename: "custom-vpc-enum.yml",
    yaml: `title: Custom AWS VPC Enumeration
id: custom-vpc-001
status: test
description: Detects EC2 DescribeVpcs discovery calls
tags:
  - attack.discovery
  - attack.t1538
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: ec2.amazonaws.com
    eventName: DescribeVpcs
  condition: selection
level: medium`,
  },
  secrets: {
    filename: "custom-secrets-enum.yml",
    yaml: `title: Custom Secrets Manager Enumeration
id: custom-secrets-001
status: test
description: Detects Secrets Manager ListSecrets API calls
tags:
  - attack.credential_access
  - attack.t1555
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: secretsmanager.amazonaws.com
    eventName: ListSecrets
  condition: selection
level: high`,
  },
  s3_probe: {
    filename: "custom-s3-probe.yml",
    yaml: `title: Custom S3 Bucket Probe
id: custom-s3-001
status: test
description: Detects HeadBucket or ListBucket enumeration
tags:
  - attack.collection
  - attack.t1530
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: s3.amazonaws.com
    eventName:
      - HeadBucket
      - ListBucket
  condition: selection
level: medium`,
  },
  blank: {
    filename: "custom-rule.yml",
    yaml: `title: Custom Detection Rule
id: custom-001
status: test
tags:
  - attack.discovery
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: sts.amazonaws.com
    eventName: GetCallerIdentity
  condition: selection
level: low`,
  },
};

const COMBO_OPTIONS = {};

function esc(val) {
  if (val === null || val === undefined) return "";
  return String(val)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function pct(val) {
  if (val === null || val === undefined || Number.isNaN(Number(val))) return "n/a";
  return `${(Number(val) * 100).toFixed(1)}%`;
}

function toCamelEvent(snakeOp) {
  return String(snakeOp || "")
    .split("_")
    .filter(Boolean)
    .map((p) => (p === "vpcs" ? "Vpcs" : p === "db" ? "DB" : p.charAt(0).toUpperCase() + p.slice(1)))
    .join("");
}

function getApiToken() {
  const saved = sessionStorage.getItem("is_api_token") || "";
  if (saved) return saved;
  const meta = document.querySelector('meta[name="is-token"]');
  return meta ? (meta.getAttribute("content") || "").trim() : "";
}

function setApiToken(tok) {
  if (tok) sessionStorage.setItem("is_api_token", tok);
  else sessionStorage.removeItem("is_api_token");
}

function withTokenQuery(url) {
  const tok = getApiToken();
  if (!tok) return url;
  const sep = url.includes("?") ? "&" : "?";
  return `${url}${sep}token=${encodeURIComponent(tok)}`;
}

async function api(url, opts = {}) {
  const tok = getApiToken();
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (tok) headers["X-Identity-Shield-Token"] = tok;
  const res = await fetch(url, { headers, ...opts });
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }
  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function toast(msg, kind = "ok") {
  const stack = document.getElementById("toast-stack");
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  stack.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

function openDrawer(eyebrow, title, htmlBody) {
  document.getElementById("drawer-eyebrow").textContent = eyebrow;
  document.getElementById("drawer-title").textContent = title;
  document.getElementById("drawer-body").innerHTML = htmlBody;
  document.getElementById("drawer-backdrop").classList.remove("hidden");
  document.getElementById("detail-drawer").classList.remove("hidden");
}

function closeDrawer() {
  document.getElementById("drawer-backdrop").classList.add("hidden");
  document.getElementById("detail-drawer").classList.add("hidden");
}

/* ------------------------------------------------------------------ */
/* Reusable Editable ComboBox (Input + Clickable Dropdown Button)     */
/* ------------------------------------------------------------------ */

function comboHtml(id, value, options, { mono = false, placeholder = "", type = "text" } = {}) {
  const normalized = (options || []).map((opt) =>
    typeof opt === "string" ? { value: opt, hint: "" } : opt
  );
  COMBO_OPTIONS[id] = normalized;
  return `
    <div class="combo" data-combo="${esc(id)}">
      <input
        id="${esc(id)}"
        type="${esc(type)}"
        class="${mono ? "mono" : ""}"
        value="${esc(value ?? "")}"
        placeholder="${esc(placeholder)}"
        autocomplete="off"
      />
      <button type="button" class="combo-btn" data-combo-toggle="${esc(id)}" title="Choose option" aria-label="Show options">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><polyline points="6 9 12 15 18 9"/></svg>
      </button>
      <div class="combo-menu hidden" id="combo-menu-${esc(id)}"></div>
    </div>
  `;
}

function setComboOptions(id, options) {
  COMBO_OPTIONS[id] = (options || []).map((opt) =>
    typeof opt === "string" ? { value: opt, hint: "" } : opt
  );
}

function renderComboMenu(id) {
  const menu = document.getElementById(`combo-menu-${id}`);
  if (!menu) return;
  const opts = COMBO_OPTIONS[id] || [];
  if (!opts.length) {
    menu.innerHTML = `<div class="small-text" style="padding:8px 10px">Type a custom value</div>`;
    return;
  }
  menu.innerHTML = opts
    .map(
      (opt) => `
      <button type="button" class="combo-opt" data-combo-pick="${esc(id)}" data-val="${esc(opt.value)}">
        <span class="combo-opt-val">${esc(opt.label || opt.value)}</span>
        ${opt.hint ? `<span class="combo-opt-hint">${esc(opt.hint)}</span>` : ""}
      </button>
    `
    )
    .join("");
  menu.querySelectorAll("[data-combo-pick]").forEach((btn) => {
    btn.onclick = (e) => {
      e.stopPropagation();
      const input = document.getElementById(id);
      if (input) {
        input.value = btn.dataset.val;
        input.dispatchEvent(new Event("input", { bubbles: true }));
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
      menu.classList.add("hidden");
    };
  });
}

function closeAllCombos(exceptId = null) {
  document.querySelectorAll(".combo-menu").forEach((m) => {
    if (!exceptId || m.id !== `combo-menu-${exceptId}`) {
      m.classList.add("hidden");
    }
  });
}

function bindCombos(root) {
  root.querySelectorAll("[data-combo-toggle]").forEach((btn) => {
    btn.onclick = (e) => {
      e.stopPropagation();
      const id = btn.dataset.comboToggle;
      const menu = document.getElementById(`combo-menu-${id}`);
      if (!menu) return;
      const willOpen = menu.classList.contains("hidden");
      closeAllCombos();
      if (willOpen) {
        renderComboMenu(id);
        menu.classList.remove("hidden");
      }
    };
  });
}

/* ------------------------------------------------------------------ */
/* Global State & Navigation                                          */
/* ------------------------------------------------------------------ */

async function refreshGlobalState() {
  STATE.app = await api("/api/state");
  updateHeaderAndSidebar();
}

function updateHeaderAndSidebar() {
  const s = STATE.app;
  if (!s) return;

  const db = s.db || {};
  const dbName = db.path ? db.path.split(/[\\/]/).pop() : "identity_shield.db";
  document.getElementById("sidebar-db-counts").textContent =
    `${dbName} · ${db.runs || 0}r · ${db.events || 0}e${db.proxy_events ? ` · ${db.proxy_events}p` : ""}`;
  const dot = document.getElementById("sidebar-db-dot");
  dot.className = db.exists ? (db.events > 0 || db.proxy_events > 0 ? "dot" : "dot warn") : "dot err";

  const conns = s.connections || {};
  const connAws = conns.aws || s.connection || {};
  const chipAws = document.getElementById("pill-aws");
  if (chipAws) {
    if (connAws.connected) {
      const reg = (connAws.descriptor || {}).region || "";
      chipAws.className = "status-chip ok";
      chipAws.innerHTML = `<span class="dot"></span><span>AWS: ${esc(connAws.account_id)} (${esc(reg)})</span>`;
    } else {
      chipAws.className = "status-chip warn";
      chipAws.innerHTML = `<span class="dot warn"></span><span>AWS: Offline</span>`;
    }
  }

  const connGcp = conns.gcp || {};
  const chipGcp = document.getElementById("pill-gcp");
  if (chipGcp) {
    if (connGcp.connected) {
      const id = connGcp.identity || {};
      const label = id.organization_id ? `org:${id.organization_id}` : (id.project_id || id.principal || "Connected");
      chipGcp.className = "status-chip ok";
      chipGcp.innerHTML = `<span class="dot"></span><span>GCP: ${esc(label)}</span>`;
    } else {
      chipGcp.className = "status-chip warn";
      chipGcp.innerHTML = `<span class="dot warn"></span><span>GCP: Offline</span>`;
    }
  }

  const connAz = conns.azure || {};
  const chipAz = document.getElementById("pill-azure");
  if (chipAz) {
    if (connAz.connected) {
      const id = connAz.identity || {};
      const label = (id.scope === "organization" && id.management_group_id)
        ? `org:${id.management_group_id}`
        : (id.subscription_id ? `sub:${String(id.subscription_id).slice(0, 8)}` : (id.tenant_id || "Connected"));
      chipAz.className = "status-chip ok";
      chipAz.innerHTML = `<span class="dot"></span><span>Azure: ${esc(label)}</span>`;
    } else {
      chipAz.className = "status-chip warn";
      chipAz.innerHTML = `<span class="dot warn"></span><span>Azure: Offline</span>`;
    }
  }

  const pStat = s.proxy_status || {};
  const chipProxy = document.getElementById("pill-proxy");
  if (chipProxy) {
    if (pStat.running) {
      const mode = (pStat.config || {}).mode || "observe";
      chipProxy.className = "status-chip ok";
      chipProxy.innerHTML = `<span class="dot"></span><span>Proxy: ${esc(pStat.host)}:${esc(pStat.port)} (${esc(mode)})</span>`;
    } else {
      const cnt = (pStat.stats || {}).total_events || 0;
      chipProxy.className = "status-chip";
      chipProxy.innerHTML = `<span class="dot muted"></span><span>Proxy: Stopped${cnt ? ` · ${cnt} reqs` : ""}</span>`;
    }
  }
}

function closeProxyStream() {
  if (STATE.proxyEventSource) {
    STATE.proxyEventSource.close();
    STATE.proxyEventSource = null;
  }
}

async function navigate(view) {
  if (STATE.view === "proxy" && view !== "proxy") closeProxyStream();
  STATE.view = view;
  document.getElementById("topbar-title").textContent = VIEW_TITLES[view] || view;
  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.classList.toggle("active", btn.dataset.view === view);
  });
  await renderCurrentView();
}

async function renderCurrentView() {
  const root = document.getElementById("main-content");
  root.innerHTML = `<div class="muted-text">Loading...</div>`;
  try {
    if (!STATE.app) await refreshGlobalState();
    if (STATE.view !== "proxy") closeProxyStream();
    switch (STATE.view) {
      case "overview":
        await renderOverview(root);
        break;
      case "connections":
        await renderConnections(root);
        break;
      case "lab":
        await renderLab(root);
        break;
      case "attacks":
        await renderAttacks(root);
        break;
      case "variants":
        await renderVariants(root);
        break;
      case "campaigns":
        await renderCampaigns(root);
        break;
      case "proxy":
        await renderProxy(root);
        break;
      case "rules":
        await renderRules(root);
        break;
      case "logs":
        await renderLogs(root);
        break;
      case "cli":
        renderCli(root);
        break;
    }
    bindCombos(root);
    bindNavigationClicks(root);
  } catch (err) {
    if (err.status === 401) {
      root.innerHTML = `
        <div class="empty-box" style="max-width:440px;margin:40px auto">
          <h3 style="margin:0 0 8px">Access Token Required</h3>
          <p class="small-text" style="margin:0 0 14px">Enter the token printed by the Identity Shield server.</p>
          <div class="row-flex" style="justify-content:center">
            <input type="password" id="unlock-token" class="mono" placeholder="Paste access token..." style="max-width:260px" />
            <button type="button" class="btn btn-primary" id="btn-unlock">Unlock</button>
          </div>
        </div>
      `;
      document.getElementById("btn-unlock").onclick = async () => {
        const tok = document.getElementById("unlock-token").value.trim();
        try {
          await api("/api/auth/verify", { method: "POST", body: JSON.stringify({ token: tok }) });
          setApiToken(tok);
          await refreshGlobalState();
          await renderCurrentView();
        } catch (e) {
          toast(e.message, "err");
        }
      };
      return;
    }
    root.innerHTML = `<div class="notice err">${esc(err.message)}</div>`;
  }
}

/* ------------------------------------------------------------------ */
/* 1. Overview                                                        */
/* ------------------------------------------------------------------ */

async function renderOverview(root) {
  const qs = new URLSearchParams({ ruleset: STATE.selectedRuleset });
  if (STATE.selectedRunId) qs.set("run_id", STATE.selectedRunId);
  STATE.analytics = await api(`/api/analytics?${qs.toString()}`);

  const a = STATE.analytics;
  const db = STATE.app.db || {};
  const conn = STATE.app.connection || {};
  const res = STATE.app.resources || {};
  const summary = a.summary || {};
  const overall = summary.overall || {};
  const prov = summary.provenance || {};
  const gates = a.gates || {};

  const stepBar = `
    <div class="step-bar">
      <div class="step-item" data-goto="connections">
        <div><span class="step-num">1</span><span class="step-label">AWS Account</span></div>
        <span class="badge ${conn.connected ? "ok" : "warn"}">${conn.connected ? "Connected" : "Offline"}</span>
      </div>
      <div class="step-item" data-goto="lab">
        <div><span class="step-num">2</span><span class="step-label">Lab Targets</span></div>
        <span class="step-meta mono">${esc(res.data_bucket || "Default")}</span>
      </div>
      <div class="step-item" data-goto="attacks">
        <div><span class="step-num">3</span><span class="step-label">Variants</span></div>
        <span class="step-meta mono">${db.variants || 0}</span>
      </div>
      <div class="step-item" data-goto="campaigns">
        <div><span class="step-num">4</span><span class="step-label">Campaigns</span></div>
        <span class="step-meta mono">${db.runs || 0} runs</span>
      </div>
    </div>
  `;

  if (!db.runs) {
    root.innerHTML = `
      ${stepBar}
      <div class="empty-box">
        <h2 style="margin:0 0 8px;font-size:17px">Ready to Test</h2>
        <p class="muted-text" style="max-width:480px;margin:0 auto 18px">
          Run an offline sample test to verify detection rules, or connect an AWS account to test live resources.
        </p>
        <div class="row-flex" style="justify-content:center">
          <button class="btn btn-primary" id="btn-quick-rehearsal">Run Sample Test (T1530)</button>
          <button class="btn btn-secondary" data-goto="connections">Connect AWS</button>
        </div>
      </div>
    `;
    document.getElementById("btn-quick-rehearsal").onclick = async () => {
      const job = await api("/api/campaigns/run", {
        method: "POST",
        body: JSON.stringify({ synthetic: true, techniques: ["T1530"], sets: ["baseline", "ofat", "pairwise"] }),
      });
      toast("Started sample test");
      await navigate("campaigns");
      attachJobStream(job.job_id);
    };
    return;
  }

  const runOptions = [`<option value="">All runs (${(db.run_list || []).length})</option>`]
    .concat(
      (db.run_list || []).map(
        (r) => `<option value="${esc(r.run_id)}" ${STATE.selectedRunId === r.run_id ? "selected" : ""}>${esc(r.run_id)} (${r.synthetic ? "synthetic" : "live"})</option>`
      )
    )
    .join("");

  const rsOptions = (a.available_rulesets || [])
    .map((rs) => `<option value="${esc(rs)}" ${a.ruleset === rs ? "selected" : ""}>${esc(rs)}</option>`)
    .join("");

  const minGate = (gates.detection_rate || {}).threshold || 0.8;
  const techRows = Object.entries(summary.techniques || {})
    .map(([tid, row]) => {
      const det = row.detection_rate;
      const badge = det === null ? `<span class="badge">n/a</span>` : det >= minGate ? `<span class="badge ok">PASS</span>` : `<span class="badge err">FAIL</span>`;
      return `
        <tr class="clickable" data-inspect-tech="${esc(tid)}">
          <td class="mono"><strong>${esc(tid)}</strong></td>
          <td class="mono">${row.valid}</td>
          <td class="mono">${row.detected}</td>
          <td style="min-width:110px">
            <div class="small-text mono">${pct(det)}</div>
            <div class="bar-track"><div class="bar-fill" style="width:${(det || 0) * 100}%"></div></div>
          </td>
          <td>${badge}</td>
        </tr>
      `;
    })
    .join("");

  const factorRows = [];
  for (const [factor, levels] of Object.entries(summary.factor_levels || {})) {
    for (const [lvl, entry] of Object.entries(levels)) {
      factorRows.push(`
        <tr>
          <td class="mono">${esc(factor)}</td>
          <td class="mono">${esc(lvl)}</td>
          <td class="mono">${entry.detected}/${entry.n}</td>
          <td class="mono">${pct(entry.evasion_rate)}</td>
        </tr>
      `);
    }
  }

  const gateCard = (g, label, fmt) => {
    const badge = g.passed === null ? `<span class="badge">n/a</span>` : g.passed ? `<span class="badge ok">PASS</span>` : `<span class="badge err">FAIL</span>`;
    return `
      <div class="kpi">
        <div class="space-between"><span class="kpi-label">${label}</span>${badge}</div>
        <div class="kpi-value mono">${g.actual === null ? "n/a" : fmt(g.actual)}</div>
        <div class="kpi-foot mono">Target: ${fmt(g.threshold)}</div>
      </div>
    `;
  };

  const scopeBadge = prov.synthetic_trials && !prov.live_trials
    ? `<span class="badge warn">Synthetic (${prov.synthetic_trials} trials)</span>`
    : prov.synthetic_trials
      ? `<span class="badge warn">Mixed (${prov.live_trials} live / ${prov.synthetic_trials} synthetic)</span>`
      : `<span class="badge ok">Live AWS (${prov.live_trials} trials)</span>`;

  root.innerHTML = `
    <div class="card" style="margin-bottom:16px">
      <div class="space-between">
        <div class="row-flex">
          <div class="field" style="width:180px">
            <label>Ruleset</label>
            <select id="analytics-ruleset">${rsOptions}</select>
          </div>
          <div class="field" style="width:240px">
            <label>Run Filter</label>
            <select id="analytics-run">${runOptions}</select>
          </div>
          <div style="padding-top:18px">${scopeBadge}</div>
        </div>
        <button class="btn btn-secondary btn-sm" id="btn-export-analytics">Export JSON</button>
      </div>
    </div>

    <div class="grid grid-4" style="margin-bottom:16px">
      ${gateCard(gates.detection_rate, "Detection Rate", pct)}
      ${gateCard(gates.false_alarm_rate, "False Alarms", pct)}
      ${gateCard(gates.ingest_latency_ms, "Ingest p95", (v) => `${Math.round(v)} ms`)}
      <div class="kpi">
        <div class="kpi-label">Valid Trials</div>
        <div class="kpi-value mono">${overall.valid ?? 0}</div>
        <div class="kpi-foot mono">Invalid: ${overall.invalid_or_unverified ?? 0}</div>
      </div>
    </div>

    <div class="grid grid-2">
      <div class="card">
        <div class="card-header"><h3 class="card-title">Results by Technique</h3></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Technique</th><th>Valid</th><th>Detected</th><th>Rate</th><th>Gate</th></tr></thead>
            <tbody>${techRows || `<tr><td colspan="5" class="muted-text">No data</td></tr>`}</tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><h3 class="card-title">Evasion by Factor</h3></div>
        <div class="table-wrap" style="max-height:340px;overflow:auto">
          <table>
            <thead><tr><th>Factor</th><th>Level</th><th>Detected</th><th>Evasion</th></tr></thead>
            <tbody>${factorRows.join("") || `<tr><td colspan="4" class="muted-text">No factor data</td></tr>`}</tbody>
          </table>
        </div>
      </div>
    </div>

    ${a.paired && a.paired.pairs ? `
      <div class="card section-gap">
        <div class="card-header">
          <h3 class="card-title">Rule Comparison (baseline-v1 vs ${esc(a.compare_target || "improved-v1")})</h3>
          <span class="badge info">p = ${Number(a.paired.mcnemar.p_value).toExponential(2)}</span>
        </div>
        <div class="grid grid-4">
          <div class="kpi"><div class="kpi-label">Paired Trials</div><div class="kpi-value mono">${a.paired.pairs}</div></div>
          <div class="kpi"><div class="kpi-label">Baseline</div><div class="kpi-value mono">${pct(a.paired.baseline_detection_rate)}</div></div>
          <div class="kpi"><div class="kpi-label">Improved</div><div class="kpi-value mono">${pct(a.paired.improved_detection_rate)}</div></div>
          <div class="kpi"><div class="kpi-label">Delta</div><div class="kpi-value mono">${a.paired.delta >= 0 ? "+" : ""}${(a.paired.delta * 100).toFixed(1)}%</div></div>
        </div>
      </div>
    ` : ""}
  `;

  document.getElementById("analytics-ruleset").onchange = (e) => {
    STATE.selectedRuleset = e.target.value;
    renderOverview(root);
  };
  document.getElementById("analytics-run").onchange = (e) => {
    STATE.selectedRunId = e.target.value;
    renderOverview(root);
  };
  document.getElementById("btn-export-analytics").onclick = () => {
    const blob = new Blob([JSON.stringify(STATE.analytics, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `identity-shield-${STATE.selectedRuleset}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };
  root.querySelectorAll("[data-inspect-tech]").forEach((tr) => {
    tr.onclick = () => {
      const tid = tr.dataset.inspectTech;
      const row = (summary.techniques || {})[tid];
      if (row) openDrawer("TECHNIQUE METRICS", tid, `<pre class="terminal">${esc(JSON.stringify(row, null, 2))}</pre>`);
    };
  });
}

/* ------------------------------------------------------------------ */
/* 2. Connections                                                     */
/* ------------------------------------------------------------------ */

async function renderConnections(root) {
  if (!STATE.templatesData) STATE.templatesData = (await api("/api/connect/templates")).templates;
  const conns = STATE.app.connections || {};
  const connAws = conns.aws || STATE.app.connection || {};
  const connGcp = conns.gcp || {};
  const connAz = conns.azure || {};
  const descAws = connAws.descriptor || {};
  const descGcp = connGcp.descriptor || {};
  const descAz = connAz.descriptor || {};
  const cloudProfiles = STATE.app.cloud_profiles || {};
  const db = STATE.app.db || {};
  const stor = STATE.app.storage || {};
  const sizeKb = ((db.size_bytes || 0) / 1024).toFixed(1);
  const profiles = Array.from(new Set([...(cloudProfiles.aws || STATE.app.profiles || []), "default", "lab", "dev", "prod"]));
  const gcpProjects = Array.from(
    new Set([...(cloudProfiles.gcp || []).map((c) => c.project).filter(Boolean), ...(descGcp.project_id ? [descGcp.project_id] : [])])
  ).map((p) => ({ value: p, hint: "gcloud" }));
  const gcpConfigs = (cloudProfiles.gcp || []).map((c) => ({ value: c.name, hint: c.project || c.account || "gcloud" }));
  const azSubs = (cloudProfiles.azure || []).map((s) => ({ value: s.id, label: s.name || s.id, hint: s.tenant_id ? s.tenant_id.slice(0, 8) : "az" }));
  const rolePresets = descAws.role_arn
    ? [descAws.role_arn, "arn:aws:iam::123456789012:role/IdentityShieldExecutionRole"]
    : ["arn:aws:iam::123456789012:role/IdentityShieldExecutionRole"];

  const tpl = STATE.templatesData[STATE.templateTab] || { files: {} };
  const fileHtml = Object.entries(tpl.files || {})
    .map(
      ([fname, content]) => `
      <div style="margin-bottom:12px">
        <div class="space-between" style="margin-bottom:6px">
          <span class="mono"><strong>${esc(fname)}</strong></span>
          <button type="button" class="btn btn-secondary btn-sm" data-copy="${esc(content)}">Copy</button>
        </div>
        <pre class="terminal" style="max-height:200px">${esc(content)}</pre>
      </div>
    `
    )
    .join("");

  const activeCloud = STATE.connCloud || "aws";
  let leftCard = "";
  let rightCard = "";

  if (activeCloud === "aws") {
    leftCard = `
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Connect AWS</h3>
          <span class="badge ${connAws.connected ? "ok" : "warn"}">${connAws.connected ? "Connected" : "Disconnected"}</span>
        </div>
        <div class="form-grid">
          <div class="field">
            <label>Authentication Method</label>
            <select id="conn-mode">
              <option value="profile" ${STATE.connMode === "profile" ? "selected" : ""}>Local AWS CLI / SSO Profile</option>
              <option value="assume_role" ${STATE.connMode === "assume_role" ? "selected" : ""}>Client IAM Role / Org Cross-Account (STS AssumeRole)</option>
              <option value="env_default" ${STATE.connMode === "env_default" ? "selected" : ""}>Ambient Env / OIDC Web Identity / Host Role</option>
              <option value="in_memory" ${STATE.connMode === "in_memory" ? "selected" : ""}>Temporary Keys (Session RAM Only)</option>
            </select>
          </div>
          <div class="grid grid-2">
            <div class="field">
              <label>AWS Region</label>
              ${comboHtml("conn-region", descAws.region || "eu-west-1", AWS_REGIONS, { mono: true })}
            </div>
            <div class="field">
              <label>Scope</label>
              <select id="conn-scope">
                <option value="single_account" ${descAws.scope === "single_account" ? "selected" : ""}>Single Account</option>
                <option value="organization" ${descAws.scope === "organization" ? "selected" : ""}>AWS Organization</option>
              </select>
            </div>
          </div>
          ${STATE.connMode === "profile"
      ? `<div class="field"><label>AWS Profile</label>${comboHtml("conn-profile", descAws.profile_name || "default", profiles, { mono: true, placeholder: "default" })}</div>`
      : STATE.connMode === "assume_role"
        ? `
          <div class="field"><label>Target Role ARN</label>${comboHtml("conn-role-arn", descAws.role_arn || "", rolePresets, { mono: true, placeholder: "arn:aws:iam::ACCOUNT:role/RoleName" })}</div>
          <div class="grid grid-2">
            <div class="field"><label>Base Profile</label>${comboHtml("conn-profile", descAws.profile_name || "default", profiles, { mono: true })}</div>
            <div class="field"><label>External ID</label>${comboHtml("conn-external-id", descAws.external_id || "", ["identity-shield-ext"], { mono: true, placeholder: "Optional" })}</div>
          </div>`
        : STATE.connMode === "env_default"
          ? `<div class="notice info">Uses active process environment credentials (AWS_ACCESS_KEY_ID, AWS_WEB_IDENTITY_TOKEN_FILE, or host IAM role).</div>`
          : `
            <div class="notice warn">Keys stay in backend memory for this session only and are never saved to disk.</div>
            <div class="field"><label>Access Key ID</label><input class="mono" type="password" id="conn-ak" /></div>
            <div class="field"><label>Secret Access Key</label><input class="mono" type="password" id="conn-sk" /></div>
            <div class="field"><label>Session Token (Optional)</label><input class="mono" type="password" id="conn-st" /></div>`
    }
          <div class="row-flex" style="margin-top:4px">
            <button type="button" class="btn btn-primary" id="btn-test-connect">Connect &amp; Verify AWS</button>
            ${connAws.connected ? `<button type="button" class="btn btn-secondary" id="btn-disconnect">Disconnect</button>` : ""}
          </div>
        </div>
      </div>`;
    rightCard = `
      <div class="card">
        <div class="card-header"><h3 class="card-title">AWS Session Identity</h3></div>
        ${connAws.connected
      ? `
          <div class="table-wrap" style="margin-bottom:14px">
            <table><tbody>
              <tr><th>Account ID</th><td class="mono">${esc(connAws.account_id)}</td></tr>
              <tr><th>Caller ARN</th><td class="mono">${esc(connAws.caller_arn)}</td></tr>
              <tr><th>Org Status</th><td>${esc((connAws.classification || {}).organization_status || "unknown")}</td></tr>
              <tr><th>Effective Scope</th><td>${esc((connAws.classification || {}).effective_scope)}</td></tr>
            </tbody></table>
          </div>
          <div class="row-flex">
            <button type="button" class="btn btn-secondary" data-goto="logs">Pull CloudTrail SIEM Logs →</button>
            <button type="button" class="btn btn-secondary" data-goto="lab">Lab Resources →</button>
          </div>`
      : `<div class="muted-text" style="padding:18px 0">AWS is not connected. Select an authentication method and click Connect &amp; Verify AWS.</div>`
    }
      </div>`;
  } else if (activeCloud === "gcp") {
    const gid = connGcp.identity || {};
    leftCard = `
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Connect Google Cloud (GCP)</h3>
          <span class="badge ${connGcp.connected ? "ok" : "warn"}">${connGcp.connected ? "Connected" : "Disconnected"}</span>
        </div>
        <div class="form-grid">
          <div class="field">
            <label>Authentication Method</label>
            <select id="gcp-conn-mode">
              <option value="gcloud_adc" ${STATE.gcpConnMode === "gcloud_adc" ? "selected" : ""}>Local gcloud CLI / Application Default Credentials (ADC)</option>
              <option value="impersonate_sa" ${STATE.gcpConnMode === "impersonate_sa" ? "selected" : ""}>Service Account Impersonation (IAM Credentials API)</option>
              <option value="service_account_json" ${STATE.gcpConnMode === "service_account_json" ? "selected" : ""}>Service Account Key JSON (Session RAM Only)</option>
              <option value="workload_identity" ${STATE.gcpConnMode === "workload_identity" ? "selected" : ""}>Workload Identity Federation (External OIDC -> STS)</option>
              <option value="in_memory_token" ${STATE.gcpConnMode === "in_memory_token" ? "selected" : ""}>OAuth 2.0 Bearer Access Token (Session RAM Only)</option>
            </select>
          </div>
          <div class="grid grid-2">
            <div class="field">
              <label>Scope</label>
              <select id="gcp-scope">
                <option value="single_project" ${descGcp.scope === "single_project" ? "selected" : ""}>Single Project / User</option>
                <option value="organization" ${descGcp.scope === "organization" ? "selected" : ""}>Whole GCP Organization</option>
              </select>
            </div>
            <div class="field">
              <label>Default Region</label>
              ${comboHtml("gcp-region", descGcp.region || "us-central1", GCP_REGIONS, { mono: true })}
            </div>
          </div>
          <div class="grid grid-2">
            <div class="field">
              <label>Project ID (Optional if auto-discovered)</label>
              ${comboHtml("gcp-project-id", descGcp.project_id || "", gcpProjects, { mono: true, placeholder: "my-gcp-project" })}
            </div>
            <div class="field">
              <label>Organization ID (For Org SIEM)</label>
              <input class="mono" id="gcp-org-id" value="${esc(descGcp.organization_id || "")}" placeholder="Optional (e.g. 123456789012)" />
            </div>
          </div>
          ${STATE.gcpConnMode === "gcloud_adc"
      ? `<div class="field"><label>gcloud Configuration (Optional)</label>${comboHtml("gcp-gcloud-cfg", descGcp.gcloud_config || "", gcpConfigs, { mono: true, placeholder: "Active configuration" })}</div>`
      : STATE.gcpConnMode === "impersonate_sa"
        ? `<div class="field"><label>Target Service Account Email</label><input class="mono" id="gcp-sa-email" value="${esc(descGcp.service_account || "")}" placeholder="identity-shield-siem@project.iam.gserviceaccount.com" /></div>`
        : STATE.gcpConnMode === "service_account_json"
          ? `<div class="notice warn">Service account private key stays in backend RAM only and is never written to SQLite or disk.</div><div class="field"><label>Service Account Key JSON</label><textarea class="mono" id="gcp-sa-json" rows="4" placeholder='{"type":"service_account","project_id":"...","client_email":"...","private_key":"-----BEGIN PRIVATE KEY-----..."}'></textarea></div>`
          : STATE.gcpConnMode === "workload_identity"
            ? `<div class="field"><label>WIF Provider Audience</label><input class="mono" id="gcp-wif-aud" placeholder="//iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/providers/oidc" /></div><div class="field"><label>External OIDC Subject Token (RAM Only)</label><input class="mono" type="password" id="gcp-wif-tok" /></div>`
            : `<div class="notice warn">OAuth token stays in backend memory for this session only.</div><div class="field"><label>GCP OAuth Access Token</label><input class="mono" type="password" id="gcp-token" placeholder="ya29...." /></div>`
    }
          <div class="row-flex" style="margin-top:4px">
            <button type="button" class="btn btn-primary" id="btn-gcp-connect">Connect &amp; Verify GCP</button>
            ${connGcp.connected ? `<button type="button" class="btn btn-secondary" id="btn-gcp-disconnect">Disconnect</button>` : ""}
          </div>
        </div>
      </div>`;
    rightCard = `
      <div class="card">
        <div class="card-header"><h3 class="card-title">GCP Session Identity</h3></div>
        ${connGcp.connected
      ? `
          <div class="table-wrap" style="margin-bottom:14px">
            <table><tbody>
              <tr><th>Verified Principal</th><td class="mono">${esc(gid.principal)}</td></tr>
              <tr><th>Project ID</th><td class="mono">${esc(gid.project_id || "-")}</td></tr>
              <tr><th>Organization ID</th><td class="mono">${esc(gid.organization_id || "-")}</td></tr>
              <tr><th>Effective Scope</th><td>${esc(gid.effective_scope)} (${esc(gid.verified_via)})</td></tr>
              <tr><th>Accessible Projects</th><td class="mono">${esc(gid.projects_accessible || 0)}</td></tr>
            </tbody></table>
          </div>
          <div class="row-flex">
            <button type="button" class="btn btn-secondary" data-goto="logs">Pull GCP Cloud Audit SIEM Logs →</button>
            <button type="button" class="btn btn-secondary" data-goto="lab">GCP Asset Census →</button>
          </div>`
      : `<div class="muted-text" style="padding:18px 0">GCP is not connected. Choose local gcloud/ADC, impersonation, SA JSON, Workload Identity, or OAuth token and verify.</div>`
    }
      </div>`;
  } else {
    const aid = connAz.identity || {};
    leftCard = `
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Connect Microsoft Azure / Entra ID</h3>
          <span class="badge ${connAz.connected ? "ok" : "warn"}">${connAz.connected ? "Connected" : "Disconnected"}</span>
        </div>
        <div class="form-grid">
          <div class="field">
            <label>Authentication Method</label>
            <select id="az-conn-mode">
              <option value="az_cli" ${STATE.azureConnMode === "az_cli" ? "selected" : ""}>Local Azure CLI (az login · ARM + Graph)</option>
              <option value="service_principal" ${STATE.azureConnMode === "service_principal" ? "selected" : ""}>Entra App Service Principal (Client Secret in RAM)</option>
              <option value="oidc_federated" ${STATE.azureConnMode === "oidc_federated" ? "selected" : ""}>Entra Workload Identity / OIDC Client Assertion</option>
              <option value="managed_identity" ${STATE.azureConnMode === "managed_identity" ? "selected" : ""}>Azure Managed Identity (Hosted VM / AKS)</option>
              <option value="in_memory_token" ${STATE.azureConnMode === "in_memory_token" ? "selected" : ""}>ARM / Entra Bearer Token(s) (Session RAM Only)</option>
            </select>
          </div>
          <div class="grid grid-2">
            <div class="field">
              <label>Scope</label>
              <select id="az-scope">
                <option value="single_subscription" ${descAz.scope === "single_subscription" ? "selected" : ""}>Single Subscription / User</option>
                <option value="organization" ${descAz.scope === "organization" ? "selected" : ""}>Whole Entra Tenant / Management Group Org</option>
              </select>
            </div>
            <div class="field">
              <label>Azure Location</label>
              ${comboHtml("az-location", descAz.location || "eastus", AZURE_LOCATIONS, { mono: true })}
            </div>
          </div>
          <div class="grid grid-2">
            <div class="field">
              <label>Subscription ID (Optional for az_cli/org)</label>
              ${comboHtml("az-sub-id", descAz.subscription_id || "", azSubs, { mono: true, placeholder: "00000000-0000-0000-0000-000000000000" })}
            </div>
            <div class="field">
              <label>Management Group ID (For Org SIEM)</label>
              <input class="mono" id="az-mg-id" value="${esc(descAz.management_group_id || "")}" placeholder="Optional org-root-mg" />
            </div>
          </div>
          ${STATE.azureConnMode === "az_cli"
      ? `<div class="notice info">Reads live ARM &amp; Microsoft Graph tokens directly from your signed-in Azure CLI ('az') without touching disk secrets.</div>`
      : STATE.azureConnMode === "service_principal"
        ? `
          <div class="grid grid-2">
            <div class="field"><label>Entra Tenant ID</label><input class="mono" id="az-tenant-id" value="${esc(descAz.tenant_id || "")}" placeholder="tenant-guid" /></div>
            <div class="field"><label>App Client ID</label><input class="mono" id="az-client-id" value="${esc(descAz.client_id || "")}" placeholder="client-guid" /></div>
          </div>
          <div class="field"><label>Client Secret (RAM Only)</label><input class="mono" type="password" id="az-client-secret" /></div>`
        : STATE.azureConnMode === "oidc_federated"
          ? `
            <div class="grid grid-2">
              <div class="field"><label>Entra Tenant ID</label><input class="mono" id="az-tenant-id" value="${esc(descAz.tenant_id || "")}" /></div>
              <div class="field"><label>App Client ID</label><input class="mono" id="az-client-id" value="${esc(descAz.client_id || "")}" /></div>
            </div>
            <div class="field"><label>Federated OIDC JWT Assertion (RAM Only)</label><input class="mono" type="password" id="az-fed-token" /></div>`
          : STATE.azureConnMode === "managed_identity"
            ? `<div class="field"><label>User-Assigned Client ID (Optional)</label><input class="mono" id="az-client-id" value="${esc(descAz.client_id || "")}" placeholder="Leave blank for system-assigned IMDS" /></div>`
            : `
              <div class="notice warn">Bearer tokens stay in backend memory only and are verified live against Azure ARM.</div>
              <div class="field"><label>Azure ARM Access Token (management.azure.com)</label><input class="mono" type="password" id="az-token" /></div>
              <div class="field"><label>Entra Microsoft Graph Token (Optional · AuditLog.Read.All)</label><input class="mono" type="password" id="az-graph-token" /></div>`
    }
          <div class="row-flex" style="margin-top:4px">
            <button type="button" class="btn btn-primary" id="btn-az-connect">Connect &amp; Verify Azure</button>
            ${connAz.connected ? `<button type="button" class="btn btn-secondary" id="btn-az-disconnect">Disconnect</button>` : ""}
          </div>
        </div>
      </div>`;
    rightCard = `
      <div class="card">
        <div class="card-header"><h3 class="card-title">Azure &amp; Entra Session Identity</h3></div>
        ${connAz.connected
      ? `
          <div class="table-wrap" style="margin-bottom:14px">
            <table><tbody>
              <tr><th>Verified Principal</th><td class="mono">${esc(aid.principal)}</td></tr>
              <tr><th>Tenant ID</th><td class="mono">${esc(aid.tenant_id || "-")}</td></tr>
              <tr><th>Subscription ID</th><td class="mono">${esc(aid.subscription_id || "-")}</td></tr>
              <tr><th>Effective Scope</th><td>${esc(aid.effective_scope)}</td></tr>
              <tr><th>Subscriptions / MGs</th><td class="mono">${esc(aid.subscriptions_accessible || 0)} subs · ${esc(aid.management_groups_accessible || 0)} MGs</td></tr>
              <tr><th>Entra Graph Logs</th><td><span class="badge ${aid.has_graph_token ? "ok" : "warn"}">${aid.has_graph_token ? "Enabled" : "ARM Only"}</span></td></tr>
            </tbody></table>
          </div>
          <div class="row-flex">
            <button type="button" class="btn btn-secondary" data-goto="logs">Pull Azure Activity &amp; Entra Logs →</button>
            <button type="button" class="btn btn-secondary" data-goto="lab">Azure Asset Census →</button>
          </div>`
      : `<div class="muted-text" style="padding:18px 0">Azure is not connected. Choose Azure CLI, Entra Service Principal, OIDC Federated, Managed Identity, or ARM Bearer Token and verify.</div>`
    }
      </div>`;
  }

  root.innerHTML = `
    <div class="card" style="margin-bottom:16px">
      <div class="space-between">
        <div class="subtabs" style="margin-bottom:0;border:none">
          <button type="button" class="subtab ${activeCloud === "aws" ? "active" : ""}" data-conn-cloud="aws">Amazon AWS <span class="badge ${connAws.connected ? "ok" : ""}">${connAws.connected ? "On" : "Off"}</span></button>
          <button type="button" class="subtab ${activeCloud === "gcp" ? "active" : ""}" data-conn-cloud="gcp">Google Cloud (GCP) <span class="badge ${connGcp.connected ? "ok" : ""}">${connGcp.connected ? "On" : "Off"}</span></button>
          <button type="button" class="subtab ${activeCloud === "azure" ? "active" : ""}" data-conn-cloud="azure">Microsoft Azure / Entra <span class="badge ${connAz.connected ? "ok" : ""}">${connAz.connected ? "On" : "Off"}</span></button>
        </div>
        <span class="small-text">All credentials verified live and kept strictly in RAM (never written to SQLite).</span>
      </div>
    </div>

    <div class="grid grid-2">
      ${leftCard}
      ${rightCard}
    </div>

    <details class="fold section-gap">
      <summary>Database &amp; Multi-Cloud SIEM Archive (${db.linked_custom_db ? "Custom" : "Local"} · ${sizeKb} KB)</summary>
      <div class="grid grid-2" style="gap:12px;margin-top:8px">
        <div class="field">
          <label>Database File Path</label>
          ${comboHtml("stor-db-path", stor.db_path || "", [
      { value: "", label: "(Default Local DB)", hint: "data/identity_shield.db" },
      { value: "data/org-prod-shield.db", hint: "Custom DB File" },
    ], { mono: true, placeholder: db.path || "data/identity_shield.db" })}
        </div>
        <div class="field">
          <label>Proxy Retention Cap</label>
          ${comboHtml("stor-max-px", stor.max_proxy_events ?? 50000, [
      { value: "5000", hint: "5k" },
      { value: "50000", hint: "50k" },
      { value: "250000", hint: "250k" },
      { value: "0", hint: "Unlimited" },
    ], { mono: true, type: "number" })}
        </div>
        <div class="field">
          <label>AWS S3 Archive Bucket (Optional)</label>
          <input class="mono" id="stor-s3-bucket" value="${esc(stor.archive_s3_bucket || "")}" placeholder="my-org-aws-siem" />
        </div>
        <div class="field">
          <label>GCP GCS Archive Bucket (Optional)</label>
          <input class="mono" id="stor-gcs-bucket" value="${esc(stor.archive_gcs_bucket || "")}" placeholder="my-org-gcp-siem" />
        </div>
        <div class="field">
          <label>Azure Storage Account / Container (Optional)</label>
          <div class="grid grid-2">
            <input class="mono" id="stor-az-account" value="${esc(stor.archive_azure_account || "")}" placeholder="storageaccount" />
            <input class="mono" id="stor-az-container" value="${esc(stor.archive_azure_container || "")}" placeholder="siem-archive" />
          </div>
        </div>
        <div class="field">
          <label>Object Prefix</label>
          <input class="mono" id="stor-s3-prefix" value="${esc(stor.archive_s3_prefix || "identity-shield-telemetry/")}" />
        </div>
      </div>

      <div class="space-between" style="margin-top:12px">
        <span class="small-text mono">${esc(db.path || "")}</span>
        <div class="row-flex">
          <button type="button" class="btn btn-secondary btn-sm" id="btn-stor-export">Export JSONL</button>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-stor-archive">Archive S3</button>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-stor-archive-gcs">Archive GCS</button>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-stor-archive-az">Archive Azure Blob</button>
          <button type="button" class="btn btn-primary btn-sm" id="btn-stor-save">Link &amp; Save</button>
        </div>
      </div>
    </details>

    <details class="fold section-gap">
      <summary>Cloud Onboarding &amp; Least-Privilege Templates (AWS / GCP / Azure)</summary>
      <div class="row-flex" style="margin-bottom:12px">
        <div class="field" style="width:280px">
          <label>Deployment Template</label>
          <select id="tpl-select">
            <option value="single-account" ${STATE.templateTab === "single-account" ? "selected" : ""}>AWS — Single Account (Terraform)</option>
            <option value="organization" ${STATE.templateTab === "organization" ? "selected" : ""}>AWS — Organization (Terraform)</option>
            <option value="gcp-single" ${STATE.templateTab === "gcp-single" ? "selected" : ""}>GCP — Single Project (gcloud / SIEM SA)</option>
            <option value="gcp-organization" ${STATE.templateTab === "gcp-organization" ? "selected" : ""}>GCP — Whole Organization (Org Viewer)</option>
            <option value="azure-single" ${STATE.templateTab === "azure-single" ? "selected" : ""}>Azure — Single Subscription (az / Reader)</option>
            <option value="azure-organization" ${STATE.templateTab === "azure-organization" ? "selected" : ""}>Azure — Whole Entra Tenant / Mgmt Group</option>
          </select>
        </div>
      </div>
      ${fileHtml}
    </details>
  `;

  root.querySelectorAll("[data-conn-cloud]").forEach((btn) => {
    btn.onclick = () => {
      STATE.connCloud = btn.dataset.connCloud;
      renderConnections(root).then(() => {
        bindCombos(root);
        bindNavigationClicks(root);
      });
    };
  });

  document.getElementById("tpl-select").onchange = (e) => {
    STATE.templateTab = e.target.value;
    renderConnections(root).then(() => {
      bindCombos(root);
      bindNavigationClicks(root);
    });
  };
  root.querySelectorAll("[data-copy]").forEach((b) => {
    b.onclick = () => {
      navigator.clipboard.writeText(b.dataset.copy);
      toast("Copied");
    };
  });

  if (activeCloud === "aws") {
    document.getElementById("conn-mode").onchange = (e) => {
      STATE.connMode = e.target.value;
      renderConnections(root).then(() => {
        bindCombos(root);
        bindNavigationClicks(root);
      });
    };
    const btnConn = document.getElementById("btn-test-connect");
    btnConn.onclick = async () => {
      btnConn.disabled = true;
      try {
        const payload = {
          auth_mode: STATE.connMode,
          region: document.getElementById("conn-region").value.trim() || "eu-west-1",
          scope: document.getElementById("conn-scope").value,
        };
        if (STATE.connMode === "profile") {
          payload.profile_name = document.getElementById("conn-profile").value.trim();
        } else if (STATE.connMode === "assume_role") {
          payload.role_arn = document.getElementById("conn-role-arn").value.trim();
          payload.external_id = document.getElementById("conn-external-id").value.trim();
          payload.profile_name = document.getElementById("conn-profile").value.trim();
        } else if (STATE.connMode === "in_memory") {
          payload.access_key = document.getElementById("conn-ak").value.trim();
          payload.secret_key = document.getElementById("conn-sk").value.trim();
          payload.session_token = document.getElementById("conn-st").value.trim();
        }
        await api("/api/connect", { method: "POST", body: JSON.stringify(payload) });
        await refreshGlobalState();
        toast("AWS connected");
        await renderCurrentView();
      } catch (e) {
        toast(e.message, "err");
      } finally {
        btnConn.disabled = false;
      }
    };
    const btnDisc = document.getElementById("btn-disconnect");
    if (btnDisc) {
      btnDisc.onclick = async () => {
        await api("/api/connect/disconnect", { method: "POST" });
        await refreshGlobalState();
        toast("AWS disconnected");
        await renderCurrentView();
      };
    }
  } else if (activeCloud === "gcp") {
    document.getElementById("gcp-conn-mode").onchange = (e) => {
      STATE.gcpConnMode = e.target.value;
      renderConnections(root).then(() => {
        bindCombos(root);
        bindNavigationClicks(root);
      });
    };
    const btnGcp = document.getElementById("btn-gcp-connect");
    btnGcp.onclick = async () => {
      btnGcp.disabled = true;
      try {
        const payload = {
          auth_mode: STATE.gcpConnMode,
          scope: document.getElementById("gcp-scope").value,
          region: document.getElementById("gcp-region").value.trim() || "us-central1",
          project_id: document.getElementById("gcp-project-id").value.trim(),
          organization_id: document.getElementById("gcp-org-id").value.trim(),
        };
        if (STATE.gcpConnMode === "gcloud_adc") {
          payload.gcloud_config = document.getElementById("gcp-gcloud-cfg").value.trim();
        } else if (STATE.gcpConnMode === "impersonate_sa") {
          payload.service_account = document.getElementById("gcp-sa-email").value.trim();
        } else if (STATE.gcpConnMode === "service_account_json") {
          payload.service_account_json = document.getElementById("gcp-sa-json").value.trim();
        } else if (STATE.gcpConnMode === "workload_identity") {
          payload.audience = document.getElementById("gcp-wif-aud").value.trim();
          payload.subject_token = document.getElementById("gcp-wif-tok").value.trim();
        } else {
          payload.access_token = document.getElementById("gcp-token").value.trim();
        }
        await api("/api/connect/gcp", { method: "POST", body: JSON.stringify(payload) });
        await refreshGlobalState();
        toast("GCP connected & verified");
        await renderCurrentView();
      } catch (e) {
        toast(e.message, "err");
      } finally {
        btnGcp.disabled = false;
      }
    };
    const btnGcpDisc = document.getElementById("btn-gcp-disconnect");
    if (btnGcpDisc) {
      btnGcpDisc.onclick = async () => {
        await api("/api/connect/gcp/disconnect", { method: "POST" });
        await refreshGlobalState();
        toast("GCP disconnected");
        await renderCurrentView();
      };
    }
  } else {
    document.getElementById("az-conn-mode").onchange = (e) => {
      STATE.azureConnMode = e.target.value;
      renderConnections(root).then(() => {
        bindCombos(root);
        bindNavigationClicks(root);
      });
    };
    const btnAz = document.getElementById("btn-az-connect");
    btnAz.onclick = async () => {
      btnAz.disabled = true;
      try {
        const payload = {
          auth_mode: STATE.azureConnMode,
          scope: document.getElementById("az-scope").value,
          location: document.getElementById("az-location").value.trim() || "eastus",
          subscription_id: document.getElementById("az-sub-id").value.trim(),
          management_group_id: document.getElementById("az-mg-id").value.trim(),
        };
        if (STATE.azureConnMode === "service_principal") {
          payload.tenant_id = document.getElementById("az-tenant-id").value.trim();
          payload.client_id = document.getElementById("az-client-id").value.trim();
          payload.client_secret = document.getElementById("az-client-secret").value.trim();
        } else if (STATE.azureConnMode === "oidc_federated") {
          payload.tenant_id = document.getElementById("az-tenant-id").value.trim();
          payload.client_id = document.getElementById("az-client-id").value.trim();
          payload.federated_token = document.getElementById("az-fed-token").value.trim();
        } else if (STATE.azureConnMode === "managed_identity") {
          payload.client_id = document.getElementById("az-client-id").value.trim();
        } else if (STATE.azureConnMode === "in_memory_token") {
          payload.access_token = document.getElementById("az-token").value.trim();
          payload.graph_token = document.getElementById("az-graph-token").value.trim();
        }
        await api("/api/connect/azure", { method: "POST", body: JSON.stringify(payload) });
        await refreshGlobalState();
        toast("Azure connected & verified");
        await renderCurrentView();
      } catch (e) {
        toast(e.message, "err");
      } finally {
        btnAz.disabled = false;
      }
    };
    const btnAzDisc = document.getElementById("btn-az-disconnect");
    if (btnAzDisc) {
      btnAzDisc.onclick = async () => {
        await api("/api/connect/azure/disconnect", { method: "POST" });
        await refreshGlobalState();
        toast("Azure disconnected");
        await renderCurrentView();
      };
    }
  }

  document.getElementById("btn-stor-save").onclick = async () => {
    try {
      const res = await api("/api/storage", {
        method: "PUT",
        body: JSON.stringify({
          db_path: document.getElementById("stor-db-path").value.trim(),
          max_proxy_events: Number(document.getElementById("stor-max-px").value || 0),
          archive_s3_bucket: document.getElementById("stor-s3-bucket").value.trim(),
          archive_gcs_bucket: document.getElementById("stor-gcs-bucket").value.trim(),
          archive_azure_account: document.getElementById("stor-az-account").value.trim(),
          archive_azure_container: document.getElementById("stor-az-container").value.trim(),
          archive_s3_prefix: document.getElementById("stor-s3-prefix").value.trim() || "identity-shield-telemetry/",
        }),
      });
      await refreshGlobalState();
      toast(`Linked DB: ${res.db.path.split(/[\\/]/).pop()}`);
      await renderCurrentView();
    } catch (e) {
      toast(e.message, "err");
    }
  };
  document.getElementById("btn-stor-export").onclick = () => {
    window.location.href = withTokenQuery("/api/storage/export");
  };
  document.getElementById("btn-stor-archive").onclick = async () => {
    try {
      const res = await api("/api/storage/archive", {
        method: "POST",
        body: JSON.stringify({
          provider: "aws",
          bucket: document.getElementById("stor-s3-bucket").value.trim(),
          prefix: document.getElementById("stor-s3-prefix").value.trim(),
        }),
      });
      toast(`Archived ${res.records} records to ${res.s3_uri}`);
    } catch (e) {
      toast(e.message, "err");
    }
  };
  document.getElementById("btn-stor-archive-gcs").onclick = async () => {
    try {
      const res = await api("/api/storage/archive", {
        method: "POST",
        body: JSON.stringify({
          provider: "gcp",
          bucket: document.getElementById("stor-gcs-bucket").value.trim(),
          prefix: document.getElementById("stor-s3-prefix").value.trim(),
        }),
      });
      toast(`Archived ${res.records} records to ${res.uri}`);
    } catch (e) {
      toast(e.message, "err");
    }
  };
  document.getElementById("btn-stor-archive-az").onclick = async () => {
    try {
      const res = await api("/api/storage/archive", {
        method: "POST",
        body: JSON.stringify({
          provider: "azure",
          storage_account: document.getElementById("stor-az-account").value.trim(),
          container: document.getElementById("stor-az-container").value.trim(),
          prefix: document.getElementById("stor-s3-prefix").value.trim(),
        }),
      });
      toast(`Archived ${res.records} records to Azure Blob`);
    } catch (e) {
      toast(e.message, "err");
    }
  };
}

/* ------------------------------------------------------------------ */
/* 3. Lab Resources                                                   */
/* ------------------------------------------------------------------ */

async function renderLab(root) {
  const res = STATE.app.resources || {};
  const th = STATE.app.thresholds || {};
  const inv = STATE.probeData?.inventory || {};
  const tfOut = STATE.probeData?.terraform_outputs || {};
  const doc = STATE.doctorData;

  const bucketOpts = Array.from(
    new Map(
      [
        ...(inv.buckets || []).map((b) => [b.name, { value: b.name, hint: b.lab_owned ? "Lab" : "Account" }]),
        ...(tfOut.data_bucket_name ? [[tfOut.data_bucket_name, { value: tfOut.data_bucket_name, hint: "Terraform" }]] : []),
        ["is-lab-crown-jewels", { value: "is-lab-crown-jewels", hint: "Default" }],
      ]
    ).values()
  );

  const keyOpts = [
    { value: "finance/q4.csv", hint: "Default" },
    { value: "sensitive/records.json", hint: "Sample" },
    { value: "secrets/config.json", hint: "Sample" },
  ];

  const trailOpts = Array.from(
    new Map(
      [
        ...(inv.trails || []).map((t) => [t.name, { value: t.name, hint: t.is_logging ? "Logging" : "Stopped" }]),
        ...(tfOut.trail_name ? [[tfOut.trail_name, { value: tfOut.trail_name, hint: "Terraform" }]] : []),
        ["identity-shield-trail", { value: "identity-shield-trail", hint: "Default" }],
      ]
    ).values()
  );

  const instanceOpts = (inv.ec2_instances || []).map((i) => ({
    value: i.instance_id,
    label: i.instance_id,
    hint: `${i.name} · ${i.state} · SSM:${i.ssm_status}`,
  }));
  if (tfOut.instance_id && !instanceOpts.some((x) => x.value === tfOut.instance_id)) {
    instanceOpts.unshift({ value: tfOut.instance_id, hint: "Terraform" });
  }

  const queueOpts = (inv.queues || []).map((q) => ({
    value: q.url,
    label: q.name,
    hint: `${q.messages_available ?? 0} msgs`,
  }));
  if (tfOut.queue_url && !queueOpts.some((x) => x.value === tfOut.queue_url)) {
    queueOpts.unshift({ value: tfOut.queue_url, label: "Terraform SQS Queue", hint: "Terraform" });
  }

  const userOpts = Array.from(
    new Map(
      [
        ...(inv.iam_users || []).map((u) => [u.name, { value: u.name, hint: u.lab_owned ? "Lab" : "IAM" }]),
        ["is-test-user", { value: "is-test-user", hint: "Default" }],
      ]
    ).values()
  );

  const roleOpts = Array.from(
    new Map(
      [
        ...(inv.iam_roles || []).map((r) => [r.name, { value: r.name, hint: "IAM Role" }]),
        ["is-admin-role", { value: "is-admin-role", hint: "Default" }],
      ]
    ).values()
  );

  root.innerHTML = `
    <div class="grid grid-2">
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Target AWS Resources</h3>
          <div class="row-flex">
            <button type="button" class="btn btn-secondary btn-sm" id="btn-run-probe">Discover AWS</button>
            <button type="button" class="btn btn-primary btn-sm" id="btn-run-mc-census">Multi-Cloud Census</button>
            <button type="button" class="btn btn-secondary btn-sm" id="btn-run-doctor">Doctor</button>
          </div>
        </div>

        <div class="form-grid">
          <div class="grid grid-2">
            <div class="field">
              <label>Target S3 Bucket</label>
              ${comboHtml("res-bucket", res.data_bucket, bucketOpts, { mono: true })}
            </div>
            <div class="field">
              <label>S3 Object Key</label>
              ${comboHtml("res-key", res.data_key, keyOpts, { mono: true })}
            </div>
          </div>

          <div class="grid grid-2">
            <div class="field">
              <label>CloudTrail Trail</label>
              ${comboHtml("res-trail", res.trail_name, trailOpts, { mono: true })}
            </div>
            <div class="field">
              <label>EC2 Instance ID</label>
              ${comboHtml("res-instance", res.instance_id, instanceOpts, { mono: true, placeholder: "i-0abc..." })}
            </div>
          </div>

          <div class="field">
            <label>SQS Queue URL</label>
            ${comboHtml("res-queue", res.queue_url, queueOpts, { mono: true, placeholder: "https://sqs.<region>.amazonaws.com/..." })}
          </div>

          <div class="grid grid-2">
            <div class="field">
              <label>Test IAM User</label>
              ${comboHtml("res-user", res.test_user_name, userOpts, { mono: true })}
            </div>
            <div class="field">
              <label>Test Admin Role</label>
              ${comboHtml("res-role", res.admin_role_name, roleOpts, { mono: true })}
            </div>
          </div>

          <div>
            <button type="button" class="btn btn-primary" id="btn-save-resources">Save Targets</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Terraform Lab</h3>
          <span class="badge">Budget: $${th.budget_usd ?? 50}</span>
        </div>

        <div class="small-text" style="margin-bottom:12px">
          Data events: <strong>${th.enable_data_events ? "On" : "Off"}</strong> ·
          EC2 target: <strong>${th.enable_instance ? "On" : "Off"}</strong> ·
          <a href="#" data-goto="rules" style="color:var(--text);font-weight:600">Edit Thresholds</a>
        </div>

        <div class="row-flex" style="margin-bottom:12px">
          <button type="button" class="btn btn-secondary" id="btn-tf-plan">Plan</button>
          <button type="button" class="btn btn-primary" id="btn-tf-up">Deploy Lab</button>
          <button type="button" class="btn btn-secondary" id="btn-tf-check">Check Residue</button>
          <button type="button" class="btn btn-danger" id="btn-tf-down">Destroy Lab</button>
        </div>

        <div id="tf-output-area">
          ${STATE.activeJobId ? `<div class="terminal" id="lab-job-term">${STATE.jobLines.map(esc).join("\n")}</div>` : ""}
        </div>
      </div>
    </div>

    ${STATE.mcCensusData
      ? `
      <div class="card section-gap">
        <div class="card-header">
          <h3 class="card-title">Connected Multi-Cloud Asset Census</h3>
          <span class="badge ${STATE.mcCensusData.connected ? "ok" : "warn"}">${STATE.mcCensusData.connected ? Object.keys(STATE.mcCensusData.clouds || {}).join(", ").toUpperCase() : "Not Connected"}</span>
        </div>
        ${STATE.mcCensusData.error ? `<div class="notice warn">${esc(STATE.mcCensusData.error)}</div>` : `<pre class="terminal" style="max-height:260px">${esc(JSON.stringify(STATE.mcCensusData.clouds || {}, null, 2))}</pre>`}
      </div>
    `
      : ""
    }

    ${doc
      ? `
      <div class="card section-gap">
        <div class="card-header">
          <h3 class="card-title">Doctor Checks</h3>
          <span class="badge ${doc.ok ? "ok" : "err"}">${doc.ok ? "OK" : "Issues"}</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Check</th><th>Status</th><th>Detail</th><th>Fix</th></tr></thead>
            <tbody>${(doc.checks || [])
        .map(
          (c) => `<tr><td class="mono">${esc(c.name)}</td><td><span class="badge ${c.status === "ok" ? "ok" : c.status === "warn" ? "warn" : "err"}">${esc(c.status)}</span></td><td>${esc(c.detail)}</td><td class="small-text">${esc(c.remedy || "")}</td></tr>`
        )
        .join("")}</tbody>
          </table>
        </div>
      </div>
    `
      : ""
    }

    ${STATE.probeData
      ? STATE.probeData.error
        ? `<div class="notice err section-gap">${esc(STATE.probeData.error)}</div>`
        : `
      <div class="card section-gap">
        <div class="card-header">
          <h3 class="card-title">Discovered AWS Inventory (${esc(STATE.probeData.region)})</h3>
          <div style="width:200px">
            <select id="probe-kind">
              <option value="buckets" ${STATE.probeTab === "buckets" ? "selected" : ""}>S3 Buckets (${(inv.buckets || []).length})</option>
              <option value="trails" ${STATE.probeTab === "trails" ? "selected" : ""}>CloudTrail Trails (${(inv.trails || []).length})</option>
              <option value="ec2" ${STATE.probeTab === "ec2" ? "selected" : ""}>EC2 Instances (${(inv.ec2_instances || []).length})</option>
              <option value="queues" ${STATE.probeTab === "queues" ? "selected" : ""}>SQS Queues (${(inv.queues || []).length})</option>
            </select>
          </div>
        </div>
        <div class="table-wrap" style="max-height:280px;overflow:auto">
          <table>
            ${STATE.probeTab === "buckets"
          ? `<thead><tr><th>Bucket</th><th>Scope</th><th></th></tr></thead><tbody>${(inv.buckets || []).map((b) => `<tr><td class="mono">${esc(b.name)}</td><td><span class="badge">${b.lab_owned ? "Lab" : "Account"}</span></td><td><button type="button" class="btn btn-secondary btn-sm" data-bind-field="data_bucket" data-bind-val="${esc(b.name)}">Use</button></td></tr>`).join("") || `<tr><td colspan="3" class="muted-text">None found.</td></tr>`}</tbody>`
          : STATE.probeTab === "trails"
            ? `<thead><tr><th>Trail</th><th>Status</th><th>Data Events</th><th>S3 Bucket</th><th></th></tr></thead><tbody>${(inv.trails || []).map((t) => `<tr><td class="mono">${esc(t.name)}</td><td><span class="badge ${t.is_logging ? "ok" : "err"}">${t.is_logging ? "Logging" : "Stopped"}</span></td><td><span class="badge ${t.s3_data_events ? "ok" : "warn"}">${t.s3_data_events ? "On" : "Off"}</span></td><td class="mono small-text">${esc(t.s3_bucket || "-")}</td><td><button type="button" class="btn btn-secondary btn-sm" data-bind-field="trail_name" data-bind-val="${esc(t.name)}">Use</button></td></tr>`).join("") || `<tr><td colspan="5" class="muted-text">None found.</td></tr>`}</tbody>`
            : STATE.probeTab === "ec2"
              ? `<thead><tr><th>Instance ID</th><th>Name</th><th>State</th><th>SSM</th><th></th></tr></thead><tbody>${(inv.ec2_instances || []).map((i) => `<tr><td class="mono">${esc(i.instance_id)}</td><td>${esc(i.name)}</td><td><span class="badge ${i.state === "running" ? "ok" : "warn"}">${esc(i.state)}</span></td><td class="mono">${esc(i.ssm_status)}</td><td><button type="button" class="btn btn-secondary btn-sm" data-bind-field="instance_id" data-bind-val="${esc(i.instance_id)}">Use</button></td></tr>`).join("") || `<tr><td colspan="5" class="muted-text">None found.</td></tr>`}</tbody>`
              : `<thead><tr><th>Queue</th><th>Messages</th><th></th></tr></thead><tbody>${(inv.queues || []).map((q) => `<tr><td class="mono">${esc(q.name)}</td><td class="mono">${q.messages_available ?? "-"}</td><td><button type="button" class="btn btn-secondary btn-sm" data-bind-field="queue_url" data-bind-val="${esc(q.url)}">Use</button></td></tr>`).join("") || `<tr><td colspan="3" class="muted-text">None found.</td></tr>`}</tbody>`
        }
          </table>
        </div>
      </div>
    `
      : ""
    }
  `;

  const probeSelect = document.getElementById("probe-kind");
  if (probeSelect) {
    probeSelect.onchange = (e) => {
      STATE.probeTab = e.target.value;
      renderCurrentView();
    };
  }
  root.querySelectorAll("[data-bind-field]").forEach((btn) => {
    btn.onclick = async () => {
      await api("/api/lab/resources", {
        method: "POST",
        body: JSON.stringify({ [btn.dataset.bindField]: btn.dataset.bindVal }),
      });
      await refreshGlobalState();
      toast(`Bound ${btn.dataset.bindField}`);
      await renderCurrentView();
    };
  });

  document.getElementById("btn-save-resources").onclick = async () => {
    await api("/api/lab/resources", {
      method: "POST",
      body: JSON.stringify({
        data_bucket: document.getElementById("res-bucket").value.trim(),
        data_key: document.getElementById("res-key").value.trim(),
        trail_name: document.getElementById("res-trail").value.trim(),
        instance_id: document.getElementById("res-instance").value.trim(),
        queue_url: document.getElementById("res-queue").value.trim(),
        test_user_name: document.getElementById("res-user").value.trim(),
        admin_role_name: document.getElementById("res-role").value.trim(),
      }),
    });
    await refreshGlobalState();
    toast("Targets saved");
  };

  document.getElementById("btn-run-probe").onclick = async (e) => {
    e.target.disabled = true;
    try {
      STATE.probeData = await api("/api/lab/census", { method: "POST" });
      toast(STATE.probeData.error ? STATE.probeData.error : "Resources discovered — check dropdowns", STATE.probeData.error ? "err" : "ok");
      await renderCurrentView();
    } catch (err) {
      toast(err.message, "err");
    } finally {
      e.target.disabled = false;
    }
  };

  document.getElementById("btn-run-mc-census").onclick = async (e) => {
    e.target.disabled = true;
    try {
      STATE.mcCensusData = await api("/api/clouds/census", { method: "POST", body: JSON.stringify({ cloud_provider: "connected" }) });
      toast(STATE.mcCensusData.error ? STATE.mcCensusData.error : "Multi-cloud asset census updated", STATE.mcCensusData.error ? "warn" : "ok");
      await renderCurrentView();
    } catch (err) {
      toast(err.message, "err");
    } finally {
      e.target.disabled = false;
    }
  };

  document.getElementById("btn-run-doctor").onclick = async (e) => {
    e.target.disabled = true;
    try {
      STATE.doctorData = await api("/api/lab/doctor", { method: "POST" });
      await renderCurrentView();
    } catch (err) {
      toast(err.message, "err");
    } finally {
      e.target.disabled = false;
    }
  };

  document.getElementById("btn-tf-plan").onclick = async (e) => {
    e.target.disabled = true;
    const area = document.getElementById("tf-output-area");
    area.innerHTML = `<div class="terminal">Running terraform plan...</div>`;
    try {
      const resPlan = await api("/api/lab/plan", { method: "POST", body: JSON.stringify({}) });
      area.innerHTML = `<div class="terminal">${esc(resPlan.output || resPlan.error || "Done")}</div>`;
      toast(resPlan.ok ? "Plan succeeded" : "Plan failed", resPlan.ok ? "ok" : "err");
    } catch (err) {
      area.innerHTML = `<div class="notice err">${esc(err.message)}</div>`;
    } finally {
      e.target.disabled = false;
    }
  };

  document.getElementById("btn-tf-up").onclick = async () => {
    if (!confirm("Deploy AWS lab resources with Terraform?")) return;
    const resUp = await api("/api/lab/up", { method: "POST", body: JSON.stringify({}) });
    attachJobStream(resUp.job_id, "lab-job-term", () => {
      document.getElementById("tf-output-area").innerHTML = `<div class="terminal" id="lab-job-term"></div>`;
    });
  };

  document.getElementById("btn-tf-down").onclick = async () => {
    if (!confirm("Destroy lab resources and check for residue?")) return;
    const resDown = await api("/api/lab/down", { method: "POST", body: JSON.stringify({ check_only: false }) });
    attachJobStream(resDown.job_id, "lab-job-term", () => {
      document.getElementById("tf-output-area").innerHTML = `<div class="terminal" id="lab-job-term"></div>`;
    });
  };

  document.getElementById("btn-tf-check").onclick = async () => {
    const resCheck = await api("/api/lab/down", { method: "POST", body: JSON.stringify({ check_only: true }) });
    attachJobStream(resCheck.job_id, "lab-job-term", () => {
      document.getElementById("tf-output-area").innerHTML = `<div class="terminal" id="lab-job-term"></div>`;
    });
  };
}

/* ------------------------------------------------------------------ */
/* 4. Attacks                                                         */
/* ------------------------------------------------------------------ */

async function renderAttacks(root) {
  const qs = STATE.attackCloud && STATE.attackCloud !== "all" ? `?cloud_provider=${encodeURIComponent(STATE.attackCloud)}` : "";
  STATE.attacksData = await api(`/api/attacks${qs}`);
  const attacks = STATE.attacksData.attacks || [];

  const rows = attacks
    .map(
      (a) => {
        const cp = (a.cloud_provider || "aws").toUpperCase();
        const isCat = a.catalogue_backed !== false;
        return `
      <tr>
        <td class="mono"><span class="badge">${esc(cp)}</span> <strong>${esc(a.technique_id)}</strong>${a.custom ? ` <span class="badge info">Custom</span>` : ""}</td>
        <td>${esc(a.name)}</td>
        <td class="mono">${esc(a.tactic)}</td>
        <td class="mono small-text">${esc((a.event_names || []).join(", "))}</td>
        <td><span class="badge ${a.enabled ? "ok" : "warn"}">${a.enabled ? "Enabled" : "Disabled"}</span></td>
        <td><span class="badge ${a.live_capability.available ? "ok" : "warn"}">${a.live_capability.available ? "Live OK" : (cp === "AWS" ? "Gated" : "Offline")}</span></td>
        <td class="mono">${a.variant_count}</td>
        <td>
          <div class="row-flex">
            <button type="button" class="btn btn-secondary btn-sm" data-inspect-attack="${esc(a.technique_id)}">Inspect</button>
            ${isCat ? `<button type="button" class="btn btn-secondary btn-sm" data-toggle-attack="${esc(a.technique_id)}" data-next="${!a.enabled}">${a.enabled ? "Disable" : "Enable"}</button>` : `<span class="small-text muted-text">Multi-Cloud</span>`}
            ${a.custom ? `<button type="button" class="btn btn-danger btn-sm" data-del-attack="${esc(a.technique_id)}">Delete</button>` : ""}
          </div>
        </td>
      </tr>
    `;
      }
    )
    .join("");

  const addPanel = STATE.showAddAttack
    ? `
      <div class="card" style="margin-bottom:16px">
        <div class="card-header">
          <h3 class="card-title">Add Custom Attack</h3>
          <button type="button" class="btn btn-ghost btn-sm" id="btn-close-add-attack">Cancel</button>
        </div>

        <div class="form-grid">
          <div class="grid grid-3">
            <div class="field">
              <label>Template Preset</label>
              <select id="atk-preset">
                <option value="">Choose a preset (optional)...</option>
                <option value="vpc_enum">VPC Discovery (ec2:describe_vpcs)</option>
                <option value="s3_probe">S3 Bucket Probe (s3:head_bucket)</option>
                <option value="secrets_enum">Secrets Manager List (secretsmanager:list_secrets)</option>
                <option value="iam_policies">IAM Policy List (iam:list_policies)</option>
                <option value="lambda_list">Lambda Functions List (lambda:list_functions)</option>
              </select>
            </div>
            <div class="field">
              <label>Technique ID</label>
              ${comboHtml("add-tid", "T9001.custom", ["T9001.custom", "T1538", "T1589", "T1555.custom", "T1087.custom", "T1530.custom"], { mono: true })}
            </div>
            <div class="field">
              <label>Tactic</label>
              <select id="add-tactic">
                <option value="discovery">discovery</option>
                <option value="initial-access">initial-access</option>
                <option value="persistence">persistence</option>
                <option value="privilege-escalation">privilege-escalation</option>
                <option value="credential-access">credential-access</option>
                <option value="collection">collection</option>
                <option value="defense-evasion">defense-evasion</option>
                <option value="exfiltration">exfiltration</option>
              </select>
            </div>
          </div>

          <div class="grid grid-3">
            <div class="field">
              <label>Attack Name</label>
              <input id="add-name" placeholder="VPC Discovery" />
            </div>
            <div class="field">
              <label>AWS Service (boto3)</label>
              ${comboHtml("add-svc", "ec2", Object.keys(SERVICE_OPERATIONS), { mono: true })}
            </div>
            <div class="field">
              <label>Boto3 Operation</label>
              ${comboHtml("add-op", "describe_vpcs", SERVICE_OPERATIONS.ec2, { mono: true })}
            </div>
          </div>

          <div class="grid grid-3">
            <div class="field">
              <label>CloudTrail Event Names</label>
              ${comboHtml("add-events", "DescribeVpcs", ["DescribeVpcs", "ListSecrets", "HeadBucket", "ListPolicies", "ListFunctions"], { mono: true })}
            </div>
            <div class="field">
              <label>Parameters (JSON)</label>
              ${comboHtml("add-kwargs", "{}", ["{}", '{"Bucket": "{bucket}"}', '{"Bucket": "{bucket}", "Key": "{key}"}', '{"MaxItems": 50}'], { mono: true })}
            </div>
            <div class="field">
              <label>Notes</label>
              <input id="add-notes" placeholder="Optional notes" />
            </div>
          </div>

          <div class="space-between">
            <label class="check-pill"><input type="checkbox" id="add-data-events" /> Requires S3 Data Events</label>
            <button type="button" class="btn btn-primary" id="btn-add-attack">Save Attack & Generate Variants</button>
          </div>
        </div>
      </div>
    `
    : "";

  root.innerHTML = `
    ${addPanel}
    <div class="card">
      <div class="card-header">
        <div class="row-flex">
          <h3 class="card-title">Attack Catalogue</h3>
          <span class="badge">${attacks.filter((a) => a.enabled).length} / ${attacks.length} enabled</span>
          <div style="width:120px">
            <select id="atk-filter-cloud">
              <option value="all" ${(STATE.attackCloud || "all") === "all" ? "selected" : ""}>All Clouds</option>
              <option value="aws" ${STATE.attackCloud === "aws" ? "selected" : ""}>AWS</option>
              <option value="gcp" ${STATE.attackCloud === "gcp" ? "selected" : ""}>GCP</option>
              <option value="azure" ${STATE.attackCloud === "azure" ? "selected" : ""}>Azure</option>
            </select>
          </div>
        </div>
        <button type="button" class="btn btn-primary btn-sm" id="btn-toggle-add-attack">
          ${STATE.showAddAttack ? "Hide Form" : "+ Add Attack"}
        </button>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Cloud &amp; ID</th><th>Name</th><th>Tactic</th><th>Audit Events</th><th>Status</th><th>Live</th><th>Variants</th><th>Actions</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </div>
  `;

  document.getElementById("atk-filter-cloud").onchange = (e) => {
    STATE.attackCloud = e.target.value;
    renderCurrentView();
  };
  document.getElementById("btn-toggle-add-attack").onclick = () => {
    STATE.showAddAttack = !STATE.showAddAttack;
    renderCurrentView();
  };

  if (STATE.showAddAttack) {
    document.getElementById("btn-close-add-attack").onclick = () => {
      STATE.showAddAttack = false;
      renderCurrentView();
    };

    const syncServiceOps = () => {
      const svc = document.getElementById("add-svc").value.trim().toLowerCase();
      const ops = SERVICE_OPERATIONS[svc] || [];
      setComboOptions("add-op", ops);
      setComboOptions("add-events", ops.map((o) => o.hint));
    };

    document.getElementById("add-svc").onchange = () => {
      syncServiceOps();
      const svc = document.getElementById("add-svc").value.trim().toLowerCase();
      const ops = SERVICE_OPERATIONS[svc] || [];
      if (ops.length) {
        document.getElementById("add-op").value = ops[0].value;
        document.getElementById("add-events").value = ops[0].hint;
      }
    };

    document.getElementById("add-op").onchange = (e) => {
      const ev = toCamelEvent(e.target.value);
      if (ev) document.getElementById("add-events").value = ev;
    };

    document.getElementById("atk-preset").onchange = (e) => {
      const p = ATTACK_PRESETS[e.target.value];
      if (!p) return;
      document.getElementById("add-tid").value = p.technique_id;
      document.getElementById("add-name").value = p.name;
      document.getElementById("add-tactic").value = p.tactic;
      document.getElementById("add-svc").value = p.service;
      syncServiceOps();
      document.getElementById("add-op").value = p.operation;
      document.getElementById("add-events").value = p.event_names;
      document.getElementById("add-kwargs").value = p.kwargs;
      document.getElementById("add-data-events").checked = p.requires_data_events;
    };

    document.getElementById("btn-add-attack").onclick = async () => {
      try {
        const kwargsObj = JSON.parse(document.getElementById("add-kwargs").value || "{}");
        await api("/api/attacks", {
          method: "POST",
          body: JSON.stringify({
            technique_id: document.getElementById("add-tid").value.trim(),
            name: document.getElementById("add-name").value.trim(),
            tactic: document.getElementById("add-tactic").value,
            event_names: document.getElementById("add-events").value,
            service: document.getElementById("add-svc").value.trim(),
            operation: document.getElementById("add-op").value.trim(),
            kwargs: kwargsObj,
            requires_data_events: document.getElementById("add-data-events").checked,
            notes: document.getElementById("add-notes").value.trim(),
          }),
        });
        STATE.showAddAttack = false;
        await refreshGlobalState();
        toast("Attack added & variants generated");
        await renderCurrentView();
      } catch (err) {
        toast(err.message, "err");
      }
    };
  }

  root.querySelectorAll("[data-inspect-attack]").forEach((b) => {
    b.onclick = () => {
      const atk = attacks.find((x) => x.technique_id === b.dataset.inspectAttack);
      if (!atk) return;
      openDrawer(
        "ATTACK",
        `${atk.technique_id} — ${atk.name}`,
        `
        <div class="form-grid">
          <div><span class="badge ${atk.enabled ? "ok" : "warn"}">${atk.enabled ? "Enabled" : "Disabled"}</span> <span class="badge ${atk.live_capability.available ? "ok" : "warn"}">${esc(atk.live_capability.reason)}</span></div>
          <div class="field"><label>Executor</label><div class="mono">${esc(atk.executor)} (${esc(atk.executor_ref || "-")})</div></div>
          <div class="field"><label>CloudTrail Events</label><div class="mono">${esc(atk.event_names.join(", "))}</div></div>
          <div class="field"><label>Required IAM Actions</label><pre class="terminal">${esc(atk.required_actions.join("\n"))}</pre></div>
          <div class="field"><label>Success Verification</label><pre class="terminal">${esc(JSON.stringify(atk.success_check, null, 2))}</pre></div>
          ${atk.api_calls?.length ? `<div class="field"><label>API Calls</label><pre class="terminal">${esc(JSON.stringify(atk.api_calls, null, 2))}</pre></div>` : ""}
          <div class="field"><label>Mapped Sigma Rules (${atk.mapped_rules.length})</label>
            <pre class="terminal">${esc(atk.mapped_rules.map((r) => `[${r.ruleset_version}] ${r.native_id} (${r.level}): ${r.title}`).join("\n") || "None mapped yet.")}</pre>
          </div>
        </div>
      `
      );
    };
  });

  root.querySelectorAll("[data-toggle-attack]").forEach((b) => {
    b.onclick = async () => {
      await api(`/api/attacks/${encodeURIComponent(b.dataset.toggleAttack)}`, {
        method: "PATCH",
        body: JSON.stringify({ enabled: b.dataset.next === "true" }),
      });
      await refreshGlobalState();
      toast(`Updated ${b.dataset.toggleAttack}`);
      await renderCurrentView();
    };
  });

  root.querySelectorAll("[data-del-attack]").forEach((b) => {
    b.onclick = async () => {
      if (!confirm(`Delete custom attack ${b.dataset.delAttack}?`)) return;
      await api(`/api/attacks/${encodeURIComponent(b.dataset.delAttack)}`, { method: "DELETE" });
      await refreshGlobalState();
      toast(`Deleted ${b.dataset.delAttack}`);
      await renderCurrentView();
    };
  });
}

/* ------------------------------------------------------------------ */
/* 5. Variants                                                        */
/* ------------------------------------------------------------------ */

async function renderVariants(root) {
  const qs = new URLSearchParams({ limit: "150" });
  if (STATE.varFilterTech) qs.set("technique_id", STATE.varFilterTech);
  if (STATE.varFilterSet) qs.set("variant_set", STATE.varFilterSet);
  const [v, atkRes] = await Promise.all([api(`/api/variants?${qs.toString()}`), api("/api/attacks")]);
  STATE.variantsData = v;
  const cov = v.coverage || {};
  const lc = cov.level_coverage || {};
  const pc = cov.pair_coverage || {};
  const activeTechs = (atkRes.attacks || []).filter((a) => a.enabled && a.catalogue_backed !== false);

  const techFilterOpts = [`<option value="">All Techniques</option>`]
    .concat(
      activeTechs.map(
        (t) => `<option value="${esc(t.technique_id)}" ${STATE.varFilterTech === t.technique_id ? "selected" : ""}>${esc(t.technique_id)} — ${esc(t.name)}</option>`
      )
    )
    .join("");

  const setFilterOpts = ["", "baseline", "ofat", "pairwise", "benign"]
    .map(
      (s) => `<option value="${s}" ${STATE.varFilterSet === s ? "selected" : ""}>${s || "All Sets"}</option>`
    )
    .join("");

  const factorRows = Object.entries(v.factors || {})
    .map(
      ([name, info]) => `
      <tr>
        <td class="mono"><strong>${esc(name)}</strong></td>
        <td class="mono">${esc(info.baseline)}</td>
        <td class="mono small-text">${esc(info.levels.join(", "))}</td>
        <td class="mono small-text">${esc(info.surface.join(", "))}</td>
      </tr>
    `
    )
    .join("");

  const varRows = (v.variants || [])
    .map(
      (row) => `
      <tr class="clickable" data-inspect-variant="${esc(row.variant_id)}">
        <td class="mono"><strong>${esc(row.variant_id)}</strong></td>
        <td class="mono">${esc(row.technique_id)}</td>
        <td><span class="badge ${row.variant_set === "baseline" ? "info" : row.variant_set === "benign" ? "ok" : ""}">${esc(row.variant_set)}</span></td>
        <td class="mono small-text">${esc(Object.entries(row.factor_levels).map(([k, val]) => `${k}=${val}`).join(" · "))}</td>
        <td class="mono small-text">${esc((row.expected_surface || []).join(", ") || "-")}</td>
      </tr>
    `
    )
    .join("");

  root.innerHTML = `
    <div class="card" style="margin-bottom:16px">
      <div class="space-between">
        <div class="row-flex">
          <div>
            <div class="kpi-label">Variants</div>
            <div class="kpi-value mono">${v.total}</div>
          </div>
          <div style="padding-left:18px;border-left:1px solid var(--border-light)">
            <div class="kpi-label">Level Coverage</div>
            <div class="kpi-value mono">${pct(lc.ratio)}</div>
          </div>
          <div style="padding-left:18px;border-left:1px solid var(--border-light)">
            <div class="kpi-label">Pairwise Min</div>
            <div class="kpi-value mono">${pct(pc.min_ratio)}</div>
          </div>
        </div>

        <div class="row-flex">
          <div class="field" style="width:130px">
            <label>Seed</label>
            ${comboHtml("var-seed", "2026", ["2026", "20261119", "42"], { mono: true, type: "number" })}
          </div>
          <div class="field" style="width:120px">
            <label>Holdout / Tech</label>
            <select id="var-holdout">
              ${[1, 2, 3, 4, 5, 8].map((n) => `<option value="${n}" ${n === 3 ? "selected" : ""}>${n}</option>`).join("")}
            </select>
          </div>
          <label class="check-pill" style="margin-top:18px"><input type="checkbox" id="var-pairwise" checked /> Pairwise</label>
          <button type="button" class="btn btn-primary" style="margin-top:18px" id="btn-gen-variants">Generate</button>
        </div>
      </div>
    </div>

    <details class="fold" style="margin-bottom:16px">
      <summary>Factor Definitions (5 Axes)</summary>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Factor</th><th>Baseline</th><th>Levels</th><th>CloudTrail Surface</th></tr></thead>
          <tbody>${factorRows}</tbody>
        </table>
      </div>
    </details>

    <div class="card">
      <div class="card-header">
        <div class="row-flex">
          <div class="field" style="width:240px">
            <select id="var-filter-tech">${techFilterOpts}</select>
          </div>
          <div class="field" style="width:150px">
            <select id="var-filter-set">${setFilterOpts}</select>
          </div>
        </div>
        <span class="small-text">Showing ${(v.variants || []).length} of ${v.filtered}</span>
      </div>
      <div class="table-wrap" style="max-height:440px;overflow:auto">
        <table>
          <thead><tr><th>Variant ID</th><th>Technique</th><th>Set</th><th>Factors</th><th>Expected Log Change</th></tr></thead>
          <tbody>${varRows || `<tr><td colspan="5" class="muted-text">No variants found. Click Generate above.</td></tr>`}</tbody>
        </table>
      </div>
    </div>
  `;

  document.getElementById("var-filter-tech").onchange = (e) => {
    STATE.varFilterTech = e.target.value;
    renderCurrentView();
  };
  document.getElementById("var-filter-set").onchange = (e) => {
    STATE.varFilterSet = e.target.value;
    renderCurrentView();
  };

  document.getElementById("btn-gen-variants").onclick = async (e) => {
    e.target.disabled = true;
    try {
      const out = await api("/api/variants/generate", {
        method: "POST",
        body: JSON.stringify({
          master_seed: Number(document.getElementById("var-seed").value || 2026),
          holdout_per_technique: Number(document.getElementById("var-holdout").value || 3),
          include_pairwise: document.getElementById("var-pairwise").checked,
        }),
      });
      await refreshGlobalState();
      toast(`Generated ${out.variants} attack + ${out.benign} benign variants`);
      await renderCurrentView();
    } catch (err) {
      toast(err.message, "err");
    } finally {
      e.target.disabled = false;
    }
  };

  root.querySelectorAll("[data-inspect-variant]").forEach((tr) => {
    tr.onclick = () => {
      const row = (v.variants || []).find((x) => x.variant_id === tr.dataset.inspectVariant);
      if (row) openDrawer("VARIANT", row.variant_id, `<pre class="terminal">${esc(JSON.stringify(row, null, 2))}</pre>`);
    };
  });
}

/* ------------------------------------------------------------------ */
/* 6. Campaigns                                                       */
/* ------------------------------------------------------------------ */

async function renderCampaigns(root) {
  const [attacksRes, clPreview, toolsSt] = await Promise.all([
    api("/api/attacks"),
    api(`/api/closed-loop/preview?mode=${encodeURIComponent(STATE.closedLoopMode || "both")}&cloud_provider=${encodeURIComponent(STATE.closedLoopCloud || "all")}`),
    api("/api/tools/status"),
  ]);
  STATE.attacksData = attacksRes;
  STATE.closedLoopPreview = clPreview;
  STATE.toolsStatus = toolsSt;
  if (!STATE.closedLoopReport && clPreview.last_report) {
    STATE.closedLoopReport = clPreview.last_report;
  }
  const enabledAttacks = (STATE.attacksData.attacks || []).filter((a) => a.enabled && a.catalogue_backed !== false);
  const conn = STATE.app.connection || {};
  const rulesets = STATE.app.db?.rulesets || [];
  const clVectors = clPreview.vectors || [];
  const clReport = STATE.closedLoopReport;
  const tools = toolsSt.tools || [];
  const cfInfo = toolsSt.cloudfox_inventory || {};

  const techChecks = enabledAttacks
    .map(
      (a) => `
      <label class="check-pill">
        <input type="checkbox" class="camp-tech" value="${esc(a.technique_id)}" checked />
        <span class="mono">${esc(a.technique_id)}</span>
        <span class="small-text">${esc(a.name)}</span>
      </label>
    `
    )
    .join("");

  root.innerHTML = `
    <div class="grid grid-2">
      <div class="card">
        <div class="card-header"><h3 class="card-title">Run Configuration</h3></div>

        <div class="form-grid">
          <div class="grid grid-2">
            <div class="field">
              <label>Preset</label>
              <select id="camp-preset">
                <option value="custom">Custom Selection</option>
                <option value="quick">Quick Sample (T1530 · Synthetic)</option>
                <option value="full">Full Benchmark (All Active · Synthetic)</option>
                <option value="discovery">Discovery Only (T1087.004, T1526, T1580)</option>
              </select>
            </div>
            <div class="field">
              <label>Execution Mode</label>
              <select id="camp-mode">
                <option value="synthetic">Synthetic (Offline Fixtures)</option>
                <option value="live">Live AWS Lab</option>
              </select>
            </div>
          </div>

          <div id="camp-live-warn" class="notice warn hidden">
            ${conn.connected
      ? `Executing live against AWS account <strong>${esc(conn.account_id)}</strong>.`
      : `AWS is offline. Connect in Connections before starting a live campaign.`
    }
          </div>

          <div class="grid grid-2">
            <div class="field">
              <label>Ruleset</label>
              <select id="camp-ruleset">
                ${(rulesets.length ? rulesets : [{ ruleset_version: "baseline-v1" }, { ruleset_version: "improved-v1" }])
      .map((r) => `<option value="${esc(r.ruleset_version)}">${esc(r.ruleset_version)}</option>`)
      .join("")}
              </select>
            </div>
            <div class="field">
              <label>Repetitions</label>
              <select id="camp-reps">
                <option value="1" selected>1</option>
                <option value="2">2</option>
                <option value="3">3</option>
                <option value="5">5</option>
              </select>
            </div>
          </div>

          <div class="field">
            <div class="space-between">
              <label>Techniques (${enabledAttacks.length} active)</label>
              <div class="row-flex">
                <button type="button" class="btn btn-ghost btn-sm" id="camp-tech-all">All</button>
                <button type="button" class="btn btn-ghost btn-sm" id="camp-tech-none">None</button>
              </div>
            </div>
            <div class="check-group">${techChecks || `<span class="muted-text">No enabled attacks.</span>`}</div>
          </div>

          <div class="field">
            <label>Variant Sets</label>
            <div class="check-group">
              ${["baseline", "ofat", "pairwise", "benign"]
      .map(
        (s) => `<label class="check-pill"><input type="checkbox" class="camp-set" value="${s}" ${s !== "benign" ? "checked" : ""} /> <span class="mono">${s}</span></label>`
      )
      .join("")}
            </div>
          </div>

          <div class="space-between" style="margin-top:4px">
            <label class="check-pill"><input type="checkbox" id="camp-force" /> Force re-run existing trials</label>
            <button type="button" class="btn btn-primary" id="btn-launch-camp">Launch Campaign</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Output</h3>
          <span class="badge ${STATE.jobStatus === "completed" ? "ok" : STATE.jobStatus === "failed" ? "err" : ""}" id="camp-job-badge">${esc(STATE.jobStatus.toUpperCase())}</span>
        </div>
        <div class="terminal" id="camp-job-term" style="min-height:360px">${STATE.jobLines.length ? STATE.jobLines.map(esc).join("\n") : "Configure parameters on the left and click Launch Campaign."
    }</div>
      </div>
    </div>

    <div class="card" style="margin-top:16px" id="closed-loop-card">
      <div class="card-header">
        <div class="row-flex">
          <h3 class="card-title">Closed-Loop Variant Engine</h3>
          <span class="badge">${clVectors.length} queued vectors</span>
          ${cfInfo.loaded ? `<span class="badge ok">CloudFox: ${esc(cfInfo.total_resources)} resources</span>` : ""}
        </div>
        <div class="row-flex">
          <div style="width:120px">
            <select id="cl-cloud">
              <option value="all" ${(STATE.closedLoopCloud || "all") === "all" ? "selected" : ""}>All Clouds</option>
              <option value="aws" ${STATE.closedLoopCloud === "aws" ? "selected" : ""}>AWS</option>
              <option value="gcp" ${STATE.closedLoopCloud === "gcp" ? "selected" : ""}>GCP</option>
              <option value="azure" ${STATE.closedLoopCloud === "azure" ? "selected" : ""}>Azure</option>
            </select>
          </div>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-cl-preview">Preview Vectors</button>
          <button type="button" class="btn btn-primary btn-sm" id="btn-cl-run">Run Closed-Loop</button>
        </div>
      </div>

      <div class="grid grid-3" style="margin-bottom:12px">
        <div class="field">
          <label>Target Source</label>
          <select id="cl-mode">
            <option value="both" ${STATE.closedLoopMode === "both" ? "selected" : ""}>Both (Alerts + Resources)</option>
            <option value="from_alerts" ${STATE.closedLoopMode === "from_alerts" ? "selected" : ""}>Flagged Alerts & Logs Only</option>
            <option value="from_resources" ${STATE.closedLoopMode === "from_resources" ? "selected" : ""}>Discovered / CloudFox Resources Only</option>
          </select>
        </div>
        <div class="field">
          <label>Harden Ruleset</label>
          <label class="check-pill" style="margin-top:4px"><input type="checkbox" id="cl-enhance" checked /> Auto-Harden Misses -> enhanced-v1</label>
        </div>
        <div class="field">
          <label>Variant Depth</label>
          <label class="check-pill" style="margin-top:4px"><input type="checkbox" id="cl-pairwise" /> Include Pairwise Matrix</label>
        </div>
      </div>

      ${clVectors.length
        ? `<div class="table-wrap" style="max-height:210px;overflow:auto;margin-bottom:12px">
            <table>
              <thead><tr><th>Source</th><th>Type</th><th>Technique</th><th>Action / Probe</th><th>Target</th><th>Reason</th></tr></thead>
              <tbody>
                ${clVectors
                  .map(
                    (v) => `
                  <tr>
                    <td><span class="badge">${esc(v.source_origin === "from_alerts" ? "Alert" : "Resource")}</span> <span class="badge">${esc((v.cloud_provider || "aws").toUpperCase())}</span></td>
                    <td><span class="badge">${esc(v.traffic_kind)}</span></td>
                    <td class="mono">${esc(v.technique_id)}</td>
                    <td class="mono small-text">${esc(v.service)}.${esc(v.operation)}</td>
                    <td class="mono small-text">${esc(v.target_resource)}</td>
                    <td class="small-text muted-text">${esc(v.reason)}</td>
                  </tr>`
                  )
                  .join("")}
              </tbody>
            </table>
          </div>`
        : `<div class="muted-text small-text" style="margin-bottom:12px">No vectors found for "${esc(STATE.closedLoopMode)}". Trigger proxy/sample alerts or bind/import CloudFox resources.</div>`
      }

      ${clReport && clReport.summary
        ? `<div class="card" style="background:var(--surface-2,rgba(255,255,255,.02));padding:12px;margin-bottom:12px">
            <div class="space-between" style="margin-bottom:8px">
              <strong class="mono small-text">Last Run: ${esc(clReport.loop_run_id)} (${esc(clReport.mode)})</strong>
              <div class="row-flex">
                <span class="badge">Before: ${esc(clReport.summary.before_rate)}%</span>
                <span class="badge ${Number(clReport.summary.after_rate) >= Number(clReport.summary.before_rate) ? "ok" : "warn"}">After: ${esc(clReport.summary.after_rate)}%</span>
                <span class="badge">${esc(clReport.summary.rules_generated || 0)} rules added</span>
              </div>
            </div>
            <div class="table-wrap" style="max-height:220px;overflow:auto">
              <table>
                <thead><tr><th>Vector</th><th>Variants</th><th>Before</th><th>After</th><th>Dynamic Hits</th><th>Status</th></tr></thead>
                <tbody>
                  ${(clReport.vectors || [])
                    .map(
                      (vr) => `
                    <tr>
                      <td class="mono small-text">${esc(vr.service)}.${esc(vr.operation)} <span class="muted-text">(${esc(vr.technique_id)})</span></td>
                      <td class="mono">${esc(vr.variants_tested)}</td>
                      <td class="mono">${esc(vr.before_rate)}%</td>
                      <td class="mono">${esc(vr.after_rate)}%</td>
                      <td class="mono">${esc(vr.dynamic_detected)}</td>
                      <td>${vr.hardened_rule ? `<span class="badge ok">Hardened</span>` : vr.evaded_after > 0 ? `<span class="badge warn">${esc(vr.evaded_after)} missed</span>` : `<span class="badge ok">Covered</span>`}</td>
                    </tr>`
                    )
                    .join("")}
                </tbody>
              </table>
            </div>
          </div>`
        : ""
      }

      <details class="fold">
        <summary>Optional Recon Tools (CloudFox JSON, Pacu Read-Only, Stratus)</summary>
        <div class="form-grid" style="margin-top:10px">
          <div class="row-flex" style="flex-wrap:wrap;gap:6px">
            ${tools
              .map(
                (t) => `<span class="badge ${t.installed ? "ok" : ""}" title="${esc(t.role)}">${esc(t.name)}: ${t.installed ? "installed" : "lazy-absent"}</span>`
              )
              .join("")}
          </div>
          <div class="grid grid-2">
            <div class="field">
              <label>Import Recon Inventory JSON</label>
              <div class="row-flex" style="margin-bottom:6px">
                <select id="cf-format">
                  <option value="cloudfox">CloudFox (AWS JSON)</option>
                  <option value="scoutsuite">ScoutSuite (AWS / GCP / Azure JSON)</option>
                </select>
              </div>
              <textarea id="cf-json-input" rows="3" placeholder='{"buckets":["prod-bucket"],"iam_roles":["AdminRole"],"secrets":["db-cred"]}'></textarea>
              <div class="space-between" style="margin-top:6px">
                <label class="check-pill"><input type="checkbox" id="cf-apply-bind" /> Apply first AWS targets to Bound Resources</label>
                <button type="button" class="btn btn-secondary btn-sm" id="btn-cf-import">Import Recon JSON</button>
              </div>
            </div>
            <div class="field">
              <label>Optional Pacu Read-Only Check (if installed)</label>
              <div class="row-flex">
                <select id="pacu-mod">
                  ${(toolsSt.allowed_pacu_modules || ["iam__enum_permissions", "iam__enum_users_roles_customers_policies", "ec2__enum", "s3__enum"])
                    .map((m) => `<option value="${esc(m)}">${esc(m)}</option>`)
                    .join("")}
                </select>
                <button type="button" class="btn btn-secondary btn-sm" id="btn-pacu-run">Run Recon</button>
              </div>
              <div class="small-text muted-text" id="pacu-status-msg" style="margin-top:6px">Zero startup overhead. Destructive Pacu modules are blocked.</div>
            </div>
          </div>
        </div>
      </details>
    </div>
  `;

  document.getElementById("camp-mode").onchange = (e) => {
    document.getElementById("camp-live-warn").classList.toggle("hidden", e.target.value !== "live");
  };

  document.getElementById("camp-tech-all").onclick = () => {
    root.querySelectorAll(".camp-tech").forEach((c) => (c.checked = true));
  };
  document.getElementById("camp-tech-none").onclick = () => {
    root.querySelectorAll(".camp-tech").forEach((c) => (c.checked = false));
  };

  document.getElementById("camp-preset").onchange = (e) => {
    const val = e.target.value;
    if (val === "quick") {
      document.getElementById("camp-mode").value = "synthetic";
      root.querySelectorAll(".camp-tech").forEach((c) => (c.checked = c.value === "T1530"));
      root.querySelectorAll(".camp-set").forEach((c) => (c.checked = c.value !== "benign"));
    } else if (val === "full") {
      document.getElementById("camp-mode").value = "synthetic";
      root.querySelectorAll(".camp-tech").forEach((c) => (c.checked = true));
      root.querySelectorAll(".camp-set").forEach((c) => (c.checked = true));
    } else if (val === "discovery") {
      root.querySelectorAll(".camp-tech").forEach((c) => (c.checked = ["T1087.004", "T1526", "T1580"].includes(c.value)));
    }
    document.getElementById("camp-live-warn").classList.toggle("hidden", document.getElementById("camp-mode").value !== "live");
  };

  document.getElementById("btn-launch-camp").onclick = async () => {
    const isSynthetic = document.getElementById("camp-mode").value === "synthetic";
    if (!isSynthetic && !conn.connected) {
      toast("Connect AWS before running live campaign", "err");
      return;
    }
    const techniques = Array.from(root.querySelectorAll(".camp-tech:checked")).map((c) => c.value);
    const sets = Array.from(root.querySelectorAll(".camp-set:checked")).map((c) => c.value);
    if (!techniques.length || !sets.length) {
      toast("Select at least one technique and one variant set", "err");
      return;
    }
    const res = await api("/api/campaigns/run", {
      method: "POST",
      body: JSON.stringify({
        synthetic: isSynthetic,
        techniques,
        sets,
        repetitions: Number(document.getElementById("camp-reps").value || 1),
        ruleset: document.getElementById("camp-ruleset").value,
        force: document.getElementById("camp-force").checked,
      }),
    });
    attachJobStream(res.job_id, "camp-job-term");
  };

  document.getElementById("cl-mode").onchange = async (e) => {
    STATE.closedLoopMode = e.target.value;
    await renderCurrentView();
  };

  document.getElementById("cl-cloud").onchange = async (e) => {
    STATE.closedLoopCloud = e.target.value;
    await renderCurrentView();
  };

  document.getElementById("btn-cl-preview").onclick = async () => {
    STATE.closedLoopMode = document.getElementById("cl-mode").value;
    STATE.closedLoopCloud = document.getElementById("cl-cloud").value;
    await renderCurrentView();
    toast("Closed-loop vectors refreshed");
  };

  document.getElementById("btn-cl-run").onclick = async () => {
    const btn = document.getElementById("btn-cl-run");
    btn.disabled = true;
    try {
      const mode = document.getElementById("cl-mode").value;
      const cloud = document.getElementById("cl-cloud").value;
      STATE.closedLoopMode = mode;
      STATE.closedLoopCloud = cloud;
      const report = await api("/api/closed-loop/run", {
        method: "POST",
        body: JSON.stringify({
          mode,
          cloud_provider: cloud,
          auto_enhance: document.getElementById("cl-enhance").checked,
          include_pairwise: document.getElementById("cl-pairwise").checked,
        }),
      });
      STATE.closedLoopReport = report;
      await refreshGlobalState();
      toast(`Closed-Loop done: ${report.summary.before_rate}% -> ${report.summary.after_rate}%`);
      await renderCurrentView();
    } catch (e) {
      toast(e.message, "err");
    } finally {
      btn.disabled = false;
    }
  };

  document.getElementById("btn-cf-import").onclick = async () => {
    const txt = document.getElementById("cf-json-input").value.trim();
    const fmt = document.getElementById("cf-format").value;
    if (!txt) {
      toast("Paste recon JSON first", "err");
      return;
    }
    try {
      const endpoint = fmt === "scoutsuite" ? "/api/tools/scoutsuite/import" : "/api/tools/cloudfox/import";
      const res = await api(endpoint, {
        method: "POST",
        body: JSON.stringify({
          json_text: txt,
          apply_bindings: fmt === "cloudfox" ? document.getElementById("cf-apply-bind").checked : false,
        }),
      });
      toast(`Imported ${res.inventory.total_resources} ${fmt} resources`);
      await renderCurrentView();
    } catch (e) {
      toast(e.message, "err");
    }
  };

  document.getElementById("btn-pacu-run").onclick = async () => {
    const msgEl = document.getElementById("pacu-status-msg");
    try {
      const res = await api("/api/tools/pacu/recon", {
        method: "POST",
        body: JSON.stringify({ module: document.getElementById("pacu-mod").value }),
      });
      msgEl.textContent = res.ok
        ? `Executed ${res.module} (exit ${res.returncode})`
        : (res.error || "Pacu not available");
      toast(res.ok ? `Pacu ${res.module} finished` : (res.error || "Pacu not installed"), res.ok ? "ok" : "warn");
    } catch (e) {
      msgEl.textContent = e.message;
      toast(e.message, "err");
    }
  };
}

function attachJobStream(jobId, targetElementId = "camp-job-term", prepareFn = null) {
  STATE.activeJobId = jobId;
  STATE.jobStatus = "running";
  STATE.jobLines = [`Attached to ${jobId}...`];
  if (prepareFn) prepareFn();

  const badgeEl = document.getElementById("camp-job-badge");
  if (badgeEl) {
    badgeEl.className = "badge";
    badgeEl.textContent = "RUNNING";
  }

  const renderTerm = () => {
    const el = document.getElementById(targetElementId);
    if (el) {
      el.textContent = STATE.jobLines.join("\n");
      el.scrollTop = el.scrollHeight;
    }
  };
  renderTerm();

  const es = new EventSource(withTokenQuery(`/api/jobs/${jobId}/stream`));
  es.onmessage = async (event) => {
    const msg = JSON.parse(event.data);
    if (msg.line) {
      STATE.jobLines.push(msg.line);
      renderTerm();
    }
    if (msg.done) {
      es.close();
      STATE.jobStatus = msg.status || "done";
      const badge = document.getElementById("camp-job-badge");
      if (badge) {
        badge.className = `badge ${msg.status === "completed" ? "ok" : "err"}`;
        badge.textContent = String(STATE.jobStatus).toUpperCase();
      }
      await refreshGlobalState();
      if (msg.status === "completed") toast("Job finished");
      else if (msg.error) toast(msg.error, "err");
    }
  };
  es.onerror = () => es.close();
}

/* ------------------------------------------------------------------ */
/* 7. Live Security Proxy                                             */
/* ------------------------------------------------------------------ */

async function renderProxy(root) {
  const qs = new URLSearchParams({
    search: STATE.proxySearch || "",
    traffic_kind: STATE.proxyKind || "",
    cloud_provider: STATE.proxyCloud && STATE.proxyCloud !== "all" ? STATE.proxyCloud : "",
    alerts_only: STATE.proxyAlertsOnly ? "true" : "false",
    limit: "100",
  });
  const profQs = STATE.proxyCloud && STATE.proxyCloud !== "all" ? `?cloud_provider=${encodeURIComponent(STATE.proxyCloud)}` : "";
  const [st, evData, profData] = await Promise.all([
    api("/api/proxy/status"),
    api(`/api/proxy/events?${qs.toString()}`),
    api(`/api/dynamic/profiles${profQs}`),
  ]);
  STATE.proxyData = evData;
  STATE.proxyProfiles = profData.profiles || [];
  const cfg = st.config || STATE.app.proxy || {};
  const stats = st.stats || {};
  const rulesets = (STATE.app.db?.rulesets || []).map((r) => r.ruleset_version);
  if (!rulesets.includes("enhanced-v1")) rulesets.push("enhanced-v1");
  if (!rulesets.includes("multicloud-v1")) rulesets.push("multicloud-v1");
  const events = evData.events || [];
  const profiles = STATE.proxyProfiles;

  const actionBadge = (act) => {
    if (act === "blocked") return `<span class="badge err">blocked</span>`;
    if (act === "alerted") return `<span class="badge warn">alerted</span>`;
    return `<span class="badge ok">allowed</span>`;
  };

  const eventRowHtml = (ev, idx) => {
    const matched = [
      ...(ev.matched_static || []).map((m) => `static:${m.native_id || m.title}`),
      ...(ev.matched_dynamic || []).map((m) => `${m.rule_id}`),
    ];
    return `
      <tr class="clickable" data-pe-idx="${idx}">
        <td class="mono small-text">${esc((ev.timestamp || "").replace("T", " ").slice(0, 19))}</td>
        <td><span class="badge">${esc((ev.cloud_provider || "unknown").toUpperCase())}</span> <span class="badge">${esc(ev.traffic_kind)}</span></td>
        <td>${actionBadge(ev.action_taken)}</td>
        <td class="mono">${Number(ev.risk_score || 0).toFixed(1)}</td>
        <td class="mono small-text"><strong>${esc(ev.method)}</strong> ${esc(ev.target_host || "")}${esc(ev.path || "/")}</td>
        <td class="mono small-text">${esc(ev.service || "-")}.${esc(ev.operation || "-")}</td>
        <td class="mono small-text">${esc(ev.principal || "-")}</td>
        <td>${matched.length ? `<span class="badge err">${esc(matched.join(", "))}</span>` : `<span class="badge">clean</span>`}</td>
      </tr>
    `;
  };

  const profileRows = profiles
    .map(
      (p, idx) => `
      <tr class="clickable" data-prof-idx="${idx}">
        <td class="mono"><span class="badge">${esc((p.cloud_provider || "aws").toUpperCase())}</span> <strong>${esc(p.principal)}</strong></td>
        <td class="mono">${p.request_count} ${p.cold_start_complete ? "" : '<span class="badge warn">cold</span>'}</td>
        <td class="mono small-text">${esc((p.known_user_agents || []).join(", ") || "-")}</td>
        <td class="mono small-text">${esc((p.known_regions || []).join(", ") || "-")}</td>
        <td class="mono small-text">${esc((p.known_services || []).join(", ") || "-")}</td>
        <td class="mono small-text">${esc((p.last_seen || "").slice(0, 19))}</td>
      </tr>
    `
    )
    .join("");

  root.innerHTML = `
    <div class="grid grid-4" style="margin-bottom:16px">
      <div class="kpi">
        <div class="kpi-label">Intercepted</div>
        <div class="kpi-value mono" id="proxy-kpi-total">${stats.total_events || 0}</div>
        <div class="kpi-foot mono">${stats.aws_events || 0} AWS · ${stats.gcp_events || 0} GCP · ${stats.azure_events || 0} AZ · ${stats.app_events || 0} Web</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Alerted</div>
        <div class="kpi-value mono" id="proxy-kpi-alerted">${stats.alerted_events || 0}</div>
        <div class="kpi-foot mono">${esc(cfg.mode || "observe")}</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Blocked (403)</div>
        <div class="kpi-value mono" id="proxy-kpi-blocked">${stats.blocked_events || 0}</div>
        <div class="kpi-foot mono">Risk >= ${esc(cfg.block_risk_threshold ?? 70)}</div>
      </div>
      <div class="kpi">
        <div class="kpi-label">Principals</div>
        <div class="kpi-value mono">${profiles.length}</div>
        <div class="kpi-foot">${cfg.learn_baseline ? "Learning on" : "Paused"}</div>
      </div>
    </div>

    <div class="card" style="margin-bottom:16px">
      <div class="card-header" style="margin-bottom:8px">
        <div class="row-flex">
          <h3 class="card-title">Proxy Control</h3>
          <span class="badge ${st.running ? "ok" : ""}">${st.running ? `LIVE ${esc(st.listen_url)}` : "STOPPED"}</span>
        </div>
        <div class="row-flex">
          ${st.running
      ? `<button type="button" class="btn btn-danger btn-sm" id="btn-proxy-stop">Stop</button>`
      : `<button type="button" class="btn btn-primary btn-sm" id="btn-proxy-start">Start Proxy</button>`
    }
          <div style="width:155px">
            <select id="proxy-sim-scenario">
              <option value="mixed" ${STATE.proxySimScenario === "mixed" ? "selected" : ""}>Mixed Burst (AWS)</option>
              <option value="multicloud_mixed" ${STATE.proxySimScenario === "multicloud_mixed" ? "selected" : ""}>Multi-Cloud Mixed</option>
              <option value="baseline" ${STATE.proxySimScenario === "baseline" ? "selected" : ""}>Clean Only</option>
              <option value="aws_attack" ${STATE.proxySimScenario === "aws_attack" ? "selected" : ""}>AWS Attack</option>
              <option value="gcp_attack" ${STATE.proxySimScenario === "gcp_attack" ? "selected" : ""}>GCP Attack</option>
              <option value="azure_attack" ${STATE.proxySimScenario === "azure_attack" ? "selected" : ""}>Azure Attack</option>
              <option value="webapp_attack" ${STATE.proxySimScenario === "webapp_attack" ? "selected" : ""}>Web Probes</option>
            </select>
          </div>
          <button type="button" class="btn btn-secondary btn-sm" id="btn-proxy-sim">Send Sample</button>
          <button type="button" class="btn btn-ghost btn-sm" id="btn-proxy-clear">Clear</button>
        </div>
      </div>

      <details class="fold">
        <summary>Settings · ${esc(cfg.mode || "observe")} · ${esc(cfg.ruleset_version || "enhanced-v1")} · port ${esc(cfg.port || 8888)}</summary>
        <div class="grid grid-3" style="gap:12px;margin-top:8px">
          <div class="field">
            <label>Host</label>
            ${comboHtml("px-host", cfg.host || "127.0.0.1", ["127.0.0.1", "::1"], { mono: true })}
          </div>
          <div class="field">
            <label>Port</label>
            ${comboHtml("px-port", cfg.port || 8888, ["8888", "8080", "9000", "3128"], { mono: true, type: "number" })}
          </div>
          <div class="field">
            <label>Mode</label>
            <select id="px-mode">
              <option value="observe" ${(cfg.mode || "observe") === "observe" ? "selected" : ""}>Observe &amp; Alert</option>
              <option value="block" ${cfg.mode === "block" ? "selected" : ""}>Block (HTTP 403)</option>
            </select>
          </div>
          <div class="field">
            <label>Ruleset</label>
            <select id="px-ruleset">
              ${rulesets.map((rs) => `<option value="${esc(rs)}" ${(cfg.ruleset_version || "enhanced-v1") === rs ? "selected" : ""}>${esc(rs)}</option>`).join("")}
            </select>
          </div>
          <div class="field">
            <label>Block Threshold</label>
            ${comboHtml("px-threshold", cfg.block_risk_threshold ?? 70, [
      { value: "45", hint: "Strict (45)" },
      { value: "70", hint: "Default (70)" },
      { value: "85", hint: "Critical (85)" },
    ], { mono: true, type: "number" })}
          </div>
          <div class="field">
            <label>Upstream App URL</label>
            ${comboHtml("px-upstream", cfg.upstream_url || "", [
      { value: "", label: "(Local Echo)", hint: "Demo" },
      { value: "http://127.0.0.1:8000", hint: "Local App" },
      { value: "https://iam.amazonaws.com", hint: "AWS IAM" },
    ], { mono: true, placeholder: "Optional http(s)://..." })}
          </div>
        </div>
        <div class="space-between" style="margin-top:12px">
          <label class="check-pill"><input type="checkbox" id="px-learn" ${cfg.learn_baseline !== false ? "checked" : ""} /> Learn baselines</label>
          <button type="button" class="btn btn-primary btn-sm" id="btn-proxy-save">Save</button>
        </div>
      </details>
    </div>

    <div class="card">
      <div class="space-between" style="margin-bottom:14px">
        <div class="subtabs" style="margin-bottom:0;border:none">
          <button type="button" class="subtab ${STATE.proxyTab === "traffic" ? "active" : ""}" data-ptab="traffic">Traffic (${events.length})</button>
          <button type="button" class="subtab ${STATE.proxyTab === "baselines" ? "active" : ""}" data-ptab="baselines">Baselines (${profiles.length})</button>
          <button type="button" class="subtab ${STATE.proxyTab === "setup" ? "active" : ""}" data-ptab="setup">Setup</button>
        </div>
        ${STATE.proxyTab === "traffic"
      ? `
          <div class="row-flex">
            <div style="width:115px">
              <select id="px-filter-cloud">
                <option value="all" ${(STATE.proxyCloud || "all") === "all" ? "selected" : ""}>All Clouds</option>
                <option value="aws" ${STATE.proxyCloud === "aws" ? "selected" : ""}>AWS</option>
                <option value="gcp" ${STATE.proxyCloud === "gcp" ? "selected" : ""}>GCP</option>
                <option value="azure" ${STATE.proxyCloud === "azure" ? "selected" : ""}>Azure</option>
              </select>
            </div>
            <div style="width:140px">
              <select id="px-filter-kind">
                <option value="">All Traffic</option>
                <option value="aws_api" ${STATE.proxyKind === "aws_api" ? "selected" : ""}>AWS API</option>
                <option value="gcp_api" ${STATE.proxyKind === "gcp_api" ? "selected" : ""}>GCP API</option>
                <option value="azure_api" ${STATE.proxyKind === "azure_api" ? "selected" : ""}>Azure API</option>
                <option value="http_app" ${STATE.proxyKind === "http_app" ? "selected" : ""}>Cloud Web App</option>
                <option value="connect_tunnel" ${STATE.proxyKind === "connect_tunnel" ? "selected" : ""}>HTTPS Tunnel</option>
              </select>
            </div>
            <div style="width:200px">
              ${comboHtml("px-filter-search", STATE.proxySearch, ["ListUsers", "CreateAccessKey", "GetObject", ".env", "etc/passwd", "curl"], { placeholder: "Search path, user, IP..." })}
            </div>
            <label class="check-pill"><input type="checkbox" id="px-filter-alerts" ${STATE.proxyAlertsOnly ? "checked" : ""} /> Alerts only</label>
            <button type="button" class="btn btn-secondary btn-sm" id="btn-px-apply">Apply</button>
            <button type="button" class="btn btn-primary btn-sm" id="btn-px-closed-loop">Test Alerts -> Variants</button>
          </div>
        `
      : ""
    }
      </div>

      ${STATE.proxyTab === "traffic"
      ? `
        <div class="table-wrap" style="max-height:460px;overflow:auto">
          <table>
            <thead><tr><th>Time</th><th>Type</th><th>Action</th><th>Risk</th><th>Target</th><th>Service / Operation</th><th>Principal</th><th>Detections</th></tr></thead>
            <tbody id="proxy-events-tbody">${events.map(eventRowHtml).join("") || `<tr><td colspan="8" class="muted-text">No intercepted requests yet. Start the proxy and click "Send Sample Traffic" or point AWS CLI / curl here.</td></tr>`}</tbody>
          </table>
        </div>
      `
      : STATE.proxyTab === "baselines"
        ? `
        <div class="table-wrap" style="max-height:460px;overflow:auto">
          <table>
            <thead><tr><th>Principal</th><th>Clean Reqs</th><th>Known User-Agents</th><th>Known Regions</th><th>Known Services</th><th>Last Seen</th></tr></thead>
            <tbody>${profileRows || `<tr><td colspan="6" class="muted-text">No baselines learned yet.</td></tr>`}</tbody>
          </table>
        </div>
      `
        : `
        <div class="form-grid">
          <div class="field">
            <label>1. AWS CLI via Live Proxy (Reverse Endpoint Inspection)</label>
            <pre class="terminal">aws iam list-users --endpoint-url ${esc(st.listen_url || "http://127.0.0.1:8888")}</pre>
          </div>
          <div class="field">
            <label>2. Python boto3 SDK via Live Proxy</label>
            <pre class="terminal">import boto3
iam = boto3.client("iam", endpoint_url="${esc(st.listen_url || "http://127.0.0.1:8888")}")
iam.list_users()</pre>
          </div>
          <div class="field">
            <label>3. Forward HTTP Proxy / Cloud Web App Reverse Proxy</label>
            <pre class="terminal"># Forward proxy for curl / Terraform / apps:
export HTTP_PROXY=${esc(st.listen_url || "http://127.0.0.1:8888")}
export HTTPS_PROXY=${esc(st.listen_url || "http://127.0.0.1:8888")}

# Or set "Reverse Upstream URL" above (e.g. http://localhost:8000) and send app traffic to ${esc(st.listen_url || "http://127.0.0.1:8888")}</pre>
          </div>
        </div>
      `
    }
    </div>
  `;

  root.querySelectorAll("[data-ptab]").forEach((b) => {
    b.onclick = () => {
      STATE.proxyTab = b.dataset.ptab;
      renderCurrentView();
    };
  });

  const saveProxyForm = async () => {
    await api("/api/proxy/config", {
      method: "PUT",
      body: JSON.stringify({
        host: document.getElementById("px-host").value.trim() || "127.0.0.1",
        port: Number(document.getElementById("px-port").value || 8888),
        mode: document.getElementById("px-mode").value,
        ruleset_version: document.getElementById("px-ruleset").value,
        block_risk_threshold: Number(document.getElementById("px-threshold").value || 70),
        upstream_url: document.getElementById("px-upstream").value.trim(),
        learn_baseline: document.getElementById("px-learn").checked,
      }),
    });
  };

  const startBtn = document.getElementById("btn-proxy-start");
  if (startBtn) {
    startBtn.onclick = async () => {
      try {
        await saveProxyForm();
        await api("/api/proxy/start", { method: "POST", body: JSON.stringify({}) });
        await refreshGlobalState();
        toast("Live Proxy started");
        await renderCurrentView();
      } catch (e) {
        toast(e.message, "err");
      }
    };
  }

  const stopBtn = document.getElementById("btn-proxy-stop");
  if (stopBtn) {
    stopBtn.onclick = async () => {
      await api("/api/proxy/stop", { method: "POST", body: JSON.stringify({}) });
      closeProxyStream();
      await refreshGlobalState();
      toast("Live Proxy stopped");
      await renderCurrentView();
    };
  }

  document.getElementById("btn-proxy-save").onclick = async () => {
    try {
      await saveProxyForm();
      await refreshGlobalState();
      toast("Proxy settings saved");
      await renderCurrentView();
    } catch (e) {
      toast(e.message, "err");
    }
  };

  document.getElementById("proxy-sim-scenario").onchange = (e) => {
    STATE.proxySimScenario = e.target.value;
  };

  document.getElementById("btn-proxy-sim").onclick = async () => {
    try {
      await saveProxyForm();
      const scen = document.getElementById("proxy-sim-scenario").value;
      const res = await api("/api/proxy/simulate", { method: "POST", body: JSON.stringify({ scenario: scen }) });
      await refreshGlobalState();
      toast(`Sent ${res.sent_count} requests (${scen})`);
      await renderCurrentView();
    } catch (e) {
      toast(e.message, "err");
    }
  };

  document.getElementById("btn-proxy-clear").onclick = async () => {
    await api("/api/proxy/clear", { method: "POST", body: JSON.stringify({}) });
    await refreshGlobalState();
    toast("Proxy log cleared");
    await renderCurrentView();
  };

  if (STATE.proxyTab === "traffic") {
    const applyFilter = () => {
      STATE.proxyCloud = document.getElementById("px-filter-cloud").value;
      STATE.proxyKind = document.getElementById("px-filter-kind").value;
      STATE.proxySearch = document.getElementById("px-filter-search").value.trim();
      STATE.proxyAlertsOnly = document.getElementById("px-filter-alerts").checked;
      renderCurrentView();
    };
    document.getElementById("px-filter-cloud").onchange = applyFilter;
    document.getElementById("px-filter-kind").onchange = applyFilter;
    document.getElementById("px-filter-alerts").onchange = applyFilter;
    document.getElementById("btn-px-apply").onclick = applyFilter;
    document.getElementById("px-filter-search").onkeydown = (e) => {
      if (e.key === "Enter") applyFilter();
    };
    document.getElementById("btn-px-closed-loop").onclick = () => {
      STATE.closedLoopMode = "from_alerts";
      navigate("campaigns");
    };

    root.querySelectorAll("[data-pe-idx]").forEach((tr) => {
      tr.onclick = () => {
        const ev = events[Number(tr.dataset.peIdx)];
        if (ev) openDrawer("PROXY EVENT", `${ev.service}.${ev.operation}`, `<pre class="terminal">${esc(JSON.stringify(ev, null, 2))}</pre>`);
      };
    });
  } else if (STATE.proxyTab === "baselines") {
    root.querySelectorAll("[data-prof-idx]").forEach((tr) => {
      tr.onclick = () => {
        const p = profiles[Number(tr.dataset.profIdx)];
        if (p) openDrawer("PRINCIPAL BASELINE", p.principal, `<pre class="terminal">${esc(JSON.stringify(p, null, 2))}</pre>`);
      };
    });
  }

  // Subscribe to SSE live traffic when proxy is running and traffic tab is visible
  closeProxyStream();
  if (st.running && STATE.proxyTab === "traffic") {
    const es = new EventSource(withTokenQuery("/api/proxy/stream"));
    STATE.proxyEventSource = es;
    es.onmessage = (msgEv) => {
      try {
        const payload = JSON.parse(msgEv.data);
        if (payload.type === "event" && payload.event && STATE.view === "proxy") {
          const ev = payload.event;
          events.unshift(ev);
          const tbody = document.getElementById("proxy-events-tbody");
          if (tbody) {
            tbody.innerHTML = events.slice(0, 100).map(eventRowHtml).join("");
            tbody.querySelectorAll("[data-pe-idx]").forEach((tr) => {
              tr.onclick = () => {
                const row = events[Number(tr.dataset.peIdx)];
                if (row) openDrawer("PROXY EVENT", `${row.service}.${row.operation}`, `<pre class="terminal">${esc(JSON.stringify(row, null, 2))}</pre>`);
              };
            });
          }
          const kpiTotal = document.getElementById("proxy-kpi-total");
          if (kpiTotal) kpiTotal.textContent = String(Number(kpiTotal.textContent || 0) + 1);
          if (ev.action_taken === "alerted") {
            const ka = document.getElementById("proxy-kpi-alerted");
            if (ka) ka.textContent = String(Number(ka.textContent || 0) + 1);
          } else if (ev.action_taken === "blocked") {
            const kb = document.getElementById("proxy-kpi-blocked");
            if (kb) kb.textContent = String(Number(kb.textContent || 0) + 1);
          }
        }
      } catch (_err) { }
    };
    es.onerror = () => es.close();
  }
}

/* ------------------------------------------------------------------ */
/* 8. Rules, Adaptive Enhancer, Dynamic Rules & Thresholds            */
/* ------------------------------------------------------------------ */

async function renderRules(root) {
  STATE.rulesData = await api("/api/rules");
  const th = STATE.app.thresholds || {};
  const allRules = STATE.rulesData.rules || [];
  const rulesets = STATE.rulesData.rulesets || [];

  if (STATE.rulesTab === "audit") {
    STATE.auditData = await api(`/api/rules/audit?ruleset=${encodeURIComponent(STATE.auditRuleset || "baseline-v1")}`);
  } else if (STATE.rulesTab === "dynamic") {
    const [dr, da] = await Promise.all([api("/api/dynamic/rules"), api("/api/dynamic/alerts?limit=60")]);
    STATE.dynamicRulesData = dr;
    STATE.dynamicAlertsData = da;
  }

  const filteredRules = allRules.filter(
    (r) =>
      (!STATE.ruleFilterCloud || STATE.ruleFilterCloud === "all" || (r.cloud_provider || "aws").toLowerCase() === STATE.ruleFilterCloud) &&
      (!STATE.ruleFilterSet || r.ruleset_version === STATE.ruleFilterSet) &&
      (!STATE.ruleFilterLevel || (r.level || "").toLowerCase() === STATE.ruleFilterLevel)
  );

  const ruleRows = filteredRules
    .map(
      (r) => `
      <tr class="clickable" data-inspect-rule="${esc(r.rule_id)}">
        <td class="mono"><span class="badge">${esc((r.cloud_provider || "aws").toUpperCase())}</span> ${esc(r.ruleset_version)}</td>
        <td class="mono">${esc(r.technique_id || "-")}</td>
        <td>${esc(r.title)}</td>
        <td><span class="badge">${esc(r.level || "-")}</span></td>
        <td class="mono small-text">${esc(r.loader)}</td>
        <td>${r.ruleset_version === "custom-v1" ? `<button type="button" class="btn btn-danger btn-sm" data-del-rule="${esc(r.path || r.native_id)}">Delete</button>` : `<span class="small-text">Inspect</span>`}</td>
      </tr>
    `
    )
    .join("");

  const presetRegions = ["eu-west-1", "us-east-1", "us-west-2", "eu-central-1", "ap-south-1", "ap-southeast-1"];
  const currentRegions = th.allowed_regions || [];
  const extraRegions = currentRegions.filter((r) => !presetRegions.includes(r)).join(", ");

  const renderAuditTab = () => {
    const ad = STATE.auditData || { rules: [], proxy_context: {} };
    const ctx = ad.proxy_context || {};
    const healthClass = (score) => (score >= 85 ? "ok" : score >= 60 ? "warn" : "err");
    const rows = (ad.rules || [])
      .map(
        (r) => `
        <tr>
          <td class="mono">${esc(r.technique_id || "-")}</td>
          <td>${esc(r.title)}</td>
          <td><span class="badge ${healthClass(r.health_score)}">${r.health_score}/100</span></td>
          <td>${(r.weaknesses || []).length ? r.weaknesses.map((w) => `<span class="badge ${w.severity === "high" ? "err" : "warn"}" title="${esc(w.detail)}" style="margin-right:4px">${esc(w.code)}</span>`).join("") : `<span class="badge ok">hardened</span>`}</td>
          <td><button type="button" class="btn btn-secondary btn-sm" data-enhance-rule="${esc(r.rule_id)}">Enhance</button></td>
        </tr>
      `
      )
      .join("");
    return `
      <div class="grid grid-4" style="margin-bottom:16px">
        <div class="kpi"><div class="kpi-label">Audited</div><div class="kpi-value mono">${ad.total_rules || 0}</div></div>
        <div class="kpi"><div class="kpi-label">Hardcoded</div><div class="kpi-value mono">${ad.weak_rules || 0}</div></div>
        <div class="kpi"><div class="kpi-label">Health</div><div class="kpi-value mono">${ad.average_health_score || 0}</div></div>
        <div class="kpi"><div class="kpi-label">Proxy Events</div><div class="kpi-value mono">${ctx.total_proxy_events || 0}</div></div>
      </div>

      <div class="card">
        <div class="card-header">
          <div class="row-flex">
            <div style="width:170px">
              <select id="audit-ruleset">
                ${rulesets.map((rs) => `<option value="${esc(rs.ruleset_version)}" ${STATE.auditRuleset === rs.ruleset_version ? "selected" : ""}>${esc(rs.ruleset_version)}</option>`).join("")}
              </select>
            </div>
            <button type="button" class="btn btn-secondary btn-sm" id="btn-audit-refresh">Re-Audit</button>
          </div>
          <button type="button" class="btn btn-primary btn-sm" id="btn-enhance-all">Auto-Enhance All → enhanced-v1</button>
        </div>
        <div class="table-wrap" style="max-height:460px;overflow:auto">
          <table>
            <thead><tr><th>Technique</th><th>Rule Title</th><th>Health</th><th>Hardcoded / Blind-Spot Issues</th><th></th></tr></thead>
            <tbody>${rows || `<tr><td colspan="5" class="muted-text">No rules found in this ruleset.</td></tr>`}</tbody>
          </table>
        </div>
      </div>
    `;
  };

  const renderDynamicTab = () => {
    const dynRules = (STATE.dynamicRulesData && STATE.dynamicRulesData.rules) || [];
    const dynAlerts = (STATE.dynamicAlertsData && STATE.dynamicAlertsData.alerts) || [];
    const drRows = dynRules
      .map(
        (r) => `
        <tr title="${esc(r.description)}">
          <td class="mono">${esc(r.rule_id)}</td>
          <td><strong>${esc(r.name)}</strong></td>
          <td><span class="badge">${esc(r.kind)}</span></td>
          <td class="mono small-text">${r.window_seconds}s / ${r.threshold}</td>
          <td><span class="badge ${r.severity === "critical" || r.severity === "high" ? "err" : "warn"}">${esc(r.severity)}</span></td>
          <td><label class="check-pill"><input type="checkbox" data-dyn-toggle="${esc(r.rule_id)}" ${r.enabled ? "checked" : ""} /> Active</label></td>
          <td><button type="button" class="btn btn-danger btn-sm" data-dyn-del="${esc(r.rule_id)}">Delete</button></td>
        </tr>
      `
      )
      .join("");
    const alRows = dynAlerts
      .map(
        (a, idx) => `
        <tr class="clickable" data-dyn-al-idx="${idx}">
          <td class="mono small-text">${esc((a.timestamp || "").replace("T", " ").slice(0, 19))}</td>
          <td class="mono">${esc(a.rule_id)}</td>
          <td><span class="badge">${esc(a.source)}</span></td>
          <td><span class="badge ${a.action_taken === "blocked" ? "err" : "warn"}">${esc(a.action_taken)}</span></td>
          <td class="mono small-text">${esc(a.principal)}</td>
          <td class="small-text">${esc(a.summary)}</td>
        </tr>
      `
      )
      .join("");
    return `
      ${STATE.showAddDynRule
        ? `
        <div class="card" style="margin-bottom:16px">
          <div class="card-header">
            <h3 class="card-title">Add / Edit Dynamic Behavioral Rule</h3>
            <button type="button" class="btn btn-ghost btn-sm" id="btn-dyn-cancel">Cancel</button>
          </div>
          <div class="grid grid-3" style="gap:12px">
            <div class="field">
              <label>Rule Kind</label>
              <select id="dyn-kind">
                <option value="velocity">Velocity (Burst Rate)</option>
                <option value="sequence">Sequence (Attack Chain)</option>
                <option value="drift">Drift (Baseline Deviation)</option>
                <option value="app_anomaly">App Anomaly (Web Probes)</option>
              </select>
            </div>
            <div class="field">
              <label>Rule Name</label>
              ${comboHtml("dyn-name", "IAM Write Burst", ["IAM Write Burst", "Recon → PrivEsc Chain", "Tool / Region Drift", "Web App Brute Force"])}
            </div>
            <div class="field">
              <label>Severity</label>
              <select id="dyn-sev">
                <option value="medium">Medium</option>
                <option value="high" selected>High</option>
                <option value="critical">Critical</option>
                <option value="low">Low</option>
              </select>
            </div>
            <div class="field">
              <label>Window (seconds)</label>
              ${comboHtml("dyn-win", "60", ["30", "60", "120", "300", "600"], { mono: true, type: "number" })}
            </div>
            <div class="field">
              <label>Threshold</label>
              ${comboHtml("dyn-thr", "3", ["2", "3", "4", "6", "10"], { mono: true, type: "number" })}
            </div>
            <div class="field">
              <label>Config JSON</label>
              <input class="mono" id="dyn-cfg" value='{"services":["iam","sts"]}' />
            </div>
          </div>
          <div class="field" style="margin-top:10px">
            <label>Description</label>
            <input id="dyn-desc" placeholder="Describe what behavioral pattern this detects..." />
          </div>
          <div style="margin-top:12px"><button type="button" class="btn btn-primary btn-sm" id="btn-dyn-save">Save Dynamic Rule</button></div>
        </div>
      `
        : ""
      }

      <div class="card" style="margin-bottom:16px">
        <div class="card-header">
          <h3 class="card-title">Dynamic Behavioral Rules</h3>
          <div class="row-flex">
            <button type="button" class="btn btn-secondary btn-sm" id="btn-dyn-replay">Run Batch Dynamic Replay</button>
            <button type="button" class="btn btn-primary btn-sm" id="btn-dyn-toggle-add">${STATE.showAddDynRule ? "Hide Form" : "+ Add Dynamic Rule"}</button>
          </div>
        </div>
        <div class="table-wrap" style="max-height:320px;overflow:auto">
          <table>
            <thead><tr><th>Rule ID</th><th>Rule</th><th>Kind</th><th>Window/Hit</th><th>Severity</th><th>State</th><th></th></tr></thead>
            <tbody>${drRows || `<tr><td colspan="7" class="muted-text">No dynamic rules.</td></tr>`}</tbody>
          </table>
        </div>
      </div>

      <div class="card">
        <div class="card-header"><h3 class="card-title">Dynamic Alerts (${dynAlerts.length})</h3></div>
        <div class="table-wrap" style="max-height:320px;overflow:auto">
          <table>
            <thead><tr><th>Time</th><th>Rule</th><th>Source</th><th>Action</th><th>Principal</th><th>Summary</th></tr></thead>
            <tbody>${alRows || `<tr><td colspan="6" class="muted-text">No dynamic alerts yet.</td></tr>`}</tbody>
          </table>
        </div>
      </div>
    `;
  };

  root.innerHTML = `
    <div class="subtabs">
      <button type="button" class="subtab ${STATE.rulesTab === "rules" ? "active" : ""}" data-rtab="rules">Sigma Rules (${allRules.length})</button>
      <button type="button" class="subtab ${STATE.rulesTab === "audit" ? "active" : ""}" data-rtab="audit">Audit &amp; Enhance</button>
      <button type="button" class="subtab ${STATE.rulesTab === "dynamic" ? "active" : ""}" data-rtab="dynamic">Dynamic Rules</button>
      <button type="button" class="subtab ${STATE.rulesTab === "thresholds" ? "active" : ""}" data-rtab="thresholds">Thresholds</button>
    </div>

    ${STATE.rulesTab === "rules"
      ? `
      ${STATE.showAddRule
        ? `
        <div class="card" style="margin-bottom:16px">
          <div class="card-header">
            <h3 class="card-title">New Custom Rule (custom-v1)</h3>
            <button type="button" class="btn btn-ghost btn-sm" id="btn-cancel-rule">Cancel</button>
          </div>
          <div class="form-grid">
            <div class="grid grid-2">
              <div class="field">
                <label>Template</label>
                <select id="rule-template">
                  <option value="vpc">VPC Discovery (DescribeVpcs)</option>
                  <option value="secrets">Secrets Enumeration (ListSecrets)</option>
                  <option value="s3_probe">S3 Bucket Probe (HeadBucket)</option>
                  <option value="blank">Blank Template</option>
                </select>
              </div>
              <div class="field">
                <label>Filename</label>
                ${comboHtml("rule-fname", "custom-vpc-enum.yml", ["custom-vpc-enum.yml", "custom-secrets-enum.yml", "custom-s3-probe.yml", "custom-rule.yml"], { mono: true })}
              </div>
            </div>
            <div class="field">
              <label>Sigma YAML</label>
              <textarea class="mono" id="rule-yaml" rows="11">${esc(SIGMA_TEMPLATES.vpc.yaml)}</textarea>
            </div>
            <div>
              <button type="button" class="btn btn-primary" id="btn-save-rule">Save & Replay</button>
            </div>
          </div>
        </div>
      `
        : ""
      }

      <div class="card">
        <div class="card-header">
          <div class="row-flex">
            <div class="field" style="width:120px">
              <select id="rule-filter-cloud">
                <option value="all" ${(STATE.ruleFilterCloud || "all") === "all" ? "selected" : ""}>All Clouds</option>
                <option value="aws" ${STATE.ruleFilterCloud === "aws" ? "selected" : ""}>AWS</option>
                <option value="gcp" ${STATE.ruleFilterCloud === "gcp" ? "selected" : ""}>GCP</option>
                <option value="azure" ${STATE.ruleFilterCloud === "azure" ? "selected" : ""}>Azure</option>
              </select>
            </div>
            <div class="field" style="width:170px">
              <select id="rule-filter-set">
                <option value="">All Rulesets</option>
                ${rulesets.map((rs) => `<option value="${esc(rs.ruleset_version)}" ${STATE.ruleFilterSet === rs.ruleset_version ? "selected" : ""}>${esc(rs.ruleset_version)}</option>`).join("")}
              </select>
            </div>
            <div class="field" style="width:140px">
              <select id="rule-filter-level">
                ${["", "low", "medium", "high", "critical"].map((lvl) => `<option value="${lvl}" ${STATE.ruleFilterLevel === lvl ? "selected" : ""}>${lvl || "All Levels"}</option>`).join("")}
              </select>
            </div>
          </div>
          <div class="row-flex">
            <button type="button" class="btn btn-secondary btn-sm" id="btn-replay-all">Replay All</button>
            <button type="button" class="btn btn-primary btn-sm" id="btn-toggle-add-rule">${STATE.showAddRule ? "Hide Form" : "+ Add Rule"}</button>
          </div>
        </div>

        <div class="table-wrap" style="max-height:460px;overflow:auto">
          <table>
            <thead><tr><th>Ruleset</th><th>Technique</th><th>Title</th><th>Level</th><th>Loader</th><th></th></tr></thead>
            <tbody>${ruleRows || `<tr><td colspan="6" class="muted-text">No matching rules.</td></tr>`}</tbody>
          </table>
        </div>
      </div>
    `
      : STATE.rulesTab === "audit"
        ? renderAuditTab()
        : STATE.rulesTab === "dynamic"
          ? renderDynamicTab()
          : `
      <div class="card">
        <div class="card-header"><h3 class="card-title">Cost & Detection Thresholds</h3></div>
        <div class="form-grid" style="max-width:760px">
          <div class="grid grid-2">
            <div class="field">
              <label>Monthly AWS Budget (USD)</label>
              ${comboHtml("th-budget", th.budget_usd ?? 50, ["10", "25", "50", "100", "250"], { mono: true, type: "number" })}
            </div>
            <div class="field">
              <label>Log Retention</label>
              <select id="th-retention">
                ${[7, 14, 30, 90, 365].map((d) => `<option value="${d}" ${(th.log_retention_days ?? 30) === d ? "selected" : ""}>${d} days</option>`).join("")}
              </select>
            </div>
          </div>

          <div class="grid grid-2">
            <div class="field">
              <label>Min Detection Rate Gate</label>
              ${comboHtml("th-min-det", th.min_detection_rate ?? 0.8, [
            { value: "0.60", hint: "60%" },
            { value: "0.70", hint: "70%" },
            { value: "0.80", hint: "80%" },
            { value: "0.85", hint: "85%" },
            { value: "0.90", hint: "90%" },
            { value: "0.95", hint: "95%" },
          ], { mono: true, type: "number" })}
            </div>
            <div class="field">
              <label>Max False Alarm Rate Gate</label>
              ${comboHtml("th-max-fa", th.max_false_alarm_rate ?? 0.05, [
            { value: "0.01", hint: "1%" },
            { value: "0.02", hint: "2%" },
            { value: "0.05", hint: "5%" },
            { value: "0.10", hint: "10%" },
          ], { mono: true, type: "number" })}
            </div>
          </div>

          <div class="grid grid-2">
            <div class="field">
              <label>Ingest Latency SLA (ms)</label>
              ${comboHtml("th-lag", th.max_ingest_lag_ms ?? 300000, [
            { value: "60000", hint: "1 min" },
            { value: "120000", hint: "2 min" },
            { value: "300000", hint: "5 min" },
            { value: "600000", hint: "10 min" },
          ], { mono: true, type: "number" })}
            </div>
            <div class="field">
              <label>Collector Timeout</label>
              <select id="th-timeout">
                ${[30, 60, 120, 180, 300].map((s) => `<option value="${s}" ${(th.collector_timeout_seconds ?? 120) === s ? "selected" : ""}>${s} seconds</option>`).join("")}
              </select>
            </div>
          </div>

          <div class="field">
            <label>Allowed Regions</label>
            <div class="check-group">
              ${presetRegions.map((r) => `<label class="check-pill"><input type="checkbox" class="th-reg" value="${r}" ${currentRegions.includes(r) ? "checked" : ""} /> <span class="mono">${r}</span></label>`).join("")}
            </div>
          </div>
          <div class="field">
            <label>Additional Regions (comma-separated, optional)</label>
            <input class="mono" id="th-extra-regions" value="${esc(extraRegions)}" placeholder="e.g. me-south-1" />
          </div>

          <div class="row-flex">
            <label class="check-pill"><input type="checkbox" id="th-data" ${th.enable_data_events ? "checked" : ""} /> Enable S3 Data Events (T1530)</label>
            <label class="check-pill"><input type="checkbox" id="th-ec2" ${th.enable_instance ? "checked" : ""} /> Enable EC2 Target (T1552.005)</label>
          </div>

          <div>
            <button type="button" class="btn btn-primary" id="btn-save-thresholds">Save Thresholds</button>
          </div>
        </div>
      </div>
    `
    }
  `;

  root.querySelectorAll("[data-rtab]").forEach((b) => {
    b.onclick = () => {
      STATE.rulesTab = b.dataset.rtab;
      renderCurrentView();
    };
  });

  if (STATE.rulesTab === "rules") {
    document.getElementById("rule-filter-cloud").onchange = (e) => {
      STATE.ruleFilterCloud = e.target.value;
      renderCurrentView();
    };
    document.getElementById("rule-filter-set").onchange = (e) => {
      STATE.ruleFilterSet = e.target.value;
      renderCurrentView();
    };
    document.getElementById("rule-filter-level").onchange = (e) => {
      STATE.ruleFilterLevel = e.target.value;
      renderCurrentView();
    };
    document.getElementById("btn-toggle-add-rule").onclick = () => {
      STATE.showAddRule = !STATE.showAddRule;
      renderCurrentView();
    };
    document.getElementById("btn-replay-all").onclick = async () => {
      await api("/api/rules/replay", { method: "POST", body: JSON.stringify({}) });
      await refreshGlobalState();
      toast("Rulesets replayed");
    };

    if (STATE.showAddRule) {
      document.getElementById("btn-cancel-rule").onclick = () => {
        STATE.showAddRule = false;
        renderCurrentView();
      };
      document.getElementById("rule-template").onchange = (e) => {
        const t = SIGMA_TEMPLATES[e.target.value];
        if (!t) return;
        document.getElementById("rule-fname").value = t.filename;
        document.getElementById("rule-yaml").value = t.yaml;
      };
      document.getElementById("btn-save-rule").onclick = async () => {
        try {
          const res = await api("/api/rules/custom", {
            method: "POST",
            body: JSON.stringify({
              filename: document.getElementById("rule-fname").value.trim(),
              yaml: document.getElementById("rule-yaml").value,
            }),
          });
          STATE.showAddRule = false;
          await refreshGlobalState();
          toast(`Saved rule: ${res.rule_title}`);
          await renderCurrentView();
        } catch (err) {
          toast(err.message, "err");
        }
      };
    }

    root.querySelectorAll("[data-inspect-rule]").forEach((tr) => {
      tr.onclick = (e) => {
        if (e.target.closest("[data-del-rule]")) return;
        const r = allRules.find((x) => x.rule_id === tr.dataset.inspectRule);
        if (!r) return;
        const bodyHtml = `
          <div class="row-flex" style="margin-bottom:10px">
            <select id="siem-target" style="max-width:220px">
              <option value="aws_cloudwatch">AWS CloudWatch Insights</option>
              <option value="gcp_logging">GCP Cloud Logging Filter</option>
              <option value="gcp_secops">Google SecOps (YARA-L 2.0)</option>
              <option value="azure_sentinel">Microsoft Sentinel (KQL)</option>
            </select>
            <button type="button" class="btn btn-primary btn-sm" id="btn-export-siem">Export SIEM Query</button>
          </div>
          <pre class="terminal" id="siem-export-out" style="margin-bottom:12px;display:none"></pre>
          <pre class="terminal">${esc(r.body)}</pre>
        `;
        openDrawer("SIGMA RULE", r.title || r.native_id, bodyHtml);
        const expBtn = document.getElementById("btn-export-siem");
        if (expBtn) {
          expBtn.onclick = async () => {
            try {
              const target = document.getElementById("siem-target").value;
              const out = await api("/api/siem/export", {
                method: "POST",
                body: JSON.stringify({ rule_id: r.rule_id, ruleset_version: r.ruleset_version, target }),
              });
              const el = document.getElementById("siem-export-out");
              const warnTxt = (out.warnings || []).length ? `\n\n// Warnings:\n// ${(out.warnings || []).join("\n// ")}` : "";
              el.textContent = (out.query || `// Unsupported: ${(out.unsupported_conditions || []).join(", ")}`) + warnTxt;
              el.style.display = "block";
            } catch (err) {
              toast(err.message, "err");
            }
          };
        }
      };
    });

    root.querySelectorAll("[data-del-rule]").forEach((btn) => {
      btn.onclick = async () => {
        await api(`/api/rules/custom/${encodeURIComponent(btn.dataset.delRule.split(/[\\/]/).pop())}`, { method: "DELETE" });
        await refreshGlobalState();
        toast("Rule deleted");
        await renderCurrentView();
      };
    });
  } else if (STATE.rulesTab === "audit") {
    document.getElementById("audit-ruleset").onchange = (e) => {
      STATE.auditRuleset = e.target.value;
      renderCurrentView();
    };
    document.getElementById("btn-audit-refresh").onclick = () => renderCurrentView();
    document.getElementById("btn-enhance-all").onclick = async () => {
      try {
        const res = await api("/api/rules/enhance/all", {
          method: "POST",
          body: JSON.stringify({ source_ruleset: STATE.auditRuleset || "baseline-v1", target_ruleset: "enhanced-v1" }),
        });
        await refreshGlobalState();
        toast(`Generated ${res.rules_generated} hardened rules in enhanced-v1`);
        await renderCurrentView();
      } catch (e) {
        toast(e.message, "err");
      }
    };
    root.querySelectorAll("[data-enhance-rule]").forEach((btn) => {
      btn.onclick = async () => {
        try {
          const prev = await api("/api/rules/enhance/preview", {
            method: "POST",
            body: JSON.stringify({ rule_id: btn.dataset.enhanceRule }),
          });
          openDrawer(
            "ADAPTIVE RULE ENHANCER",
            prev.enhanced_title,
            `
              <div class="form-grid">
                <div class="notice ok">${(prev.fixes_applied || []).map((f) => `• ${esc(f)}`).join("<br/>") || "Generalized rule ready."}</div>
                <div class="small-text"><strong>Dynamic pairing:</strong> ${esc((prev.recommended_dynamic || {}).suggestion || "")}</div>
                <div class="field">
                  <label>Target Filename (saved into enhanced-v1)</label>
                  <input class="mono" id="enh-fname" value="${esc(prev.filename)}" />
                </div>
                <div class="field">
                  <label>Enhanced Sigma YAML (editable)</label>
                  <textarea class="mono" id="enh-yaml" rows="13">${esc(prev.enhanced_yaml)}</textarea>
                </div>
                <details class="fold">
                  <summary>Original Weak Rule (${esc(prev.source_title)})</summary>
                  <pre class="terminal">${esc(prev.original_yaml)}</pre>
                </details>
                <div class="row-flex">
                  <button type="button" class="btn btn-primary" id="btn-enh-apply">Save to enhanced-v1 & Replay</button>
                </div>
              </div>
            `
          );
          document.getElementById("btn-enh-apply").onclick = async () => {
            try {
              const saved = await api("/api/rules/enhance/apply", {
                method: "POST",
                body: JSON.stringify({
                  filename: document.getElementById("enh-fname").value.trim(),
                  yaml: document.getElementById("enh-yaml").value,
                  target_ruleset: "enhanced-v1",
                  replay: true,
                }),
              });
              closeDrawer();
              await refreshGlobalState();
              toast(`Saved ${saved.rule_title} to enhanced-v1`);
              await renderCurrentView();
            } catch (err) {
              toast(err.message, "err");
            }
          };
        } catch (err) {
          toast(err.message, "err");
        }
      };
    });
  } else if (STATE.rulesTab === "dynamic") {
    document.getElementById("btn-dyn-toggle-add").onclick = () => {
      STATE.showAddDynRule = !STATE.showAddDynRule;
      renderCurrentView();
    };
    document.getElementById("btn-dyn-replay").onclick = async () => {
      try {
        const res = await api("/api/dynamic/replay", { method: "POST", body: JSON.stringify({}) });
        await refreshGlobalState();
        toast(`Scanned ${res.events_scanned} batch events -> ${res.dynamic_alerts} dynamic alerts`);
        await renderCurrentView();
      } catch (e) {
        toast(e.message, "err");
      }
    };
    if (STATE.showAddDynRule) {
      const defaultsByKind = {
        velocity: '{"services":["iam","sts"]}',
        sequence: '{"steps":["ListUsers|ListRoles|ListBuckets","CreateAccessKey|GetObject"]}',
        drift: '{"check":["user_agent","region"]}',
        app_anomaly: '{"sensitive_paths":["/.env","/admin","/../"]}',
      };
      document.getElementById("dyn-kind").onchange = (e) => {
        document.getElementById("dyn-cfg").value = defaultsByKind[e.target.value] || "{}";
      };
      document.getElementById("btn-dyn-cancel").onclick = () => {
        STATE.showAddDynRule = false;
        renderCurrentView();
      };
      document.getElementById("btn-dyn-save").onclick = async () => {
        try {
          await api("/api/dynamic/rules", {
            method: "POST",
            body: JSON.stringify({
              name: document.getElementById("dyn-name").value.trim(),
              kind: document.getElementById("dyn-kind").value,
              severity: document.getElementById("dyn-sev").value,
              window_seconds: Number(document.getElementById("dyn-win").value || 60),
              threshold: Number(document.getElementById("dyn-thr").value || 3),
              config: document.getElementById("dyn-cfg").value.trim() || "{}",
              description: document.getElementById("dyn-desc").value.trim(),
            }),
          });
          STATE.showAddDynRule = false;
          await refreshGlobalState();
          toast("Dynamic rule saved");
          await renderCurrentView();
        } catch (err) {
          toast(err.message, "err");
        }
      };
    }
    root.querySelectorAll("[data-dyn-toggle]").forEach((cb) => {
      cb.onchange = async () => {
        await api(`/api/dynamic/rules/${encodeURIComponent(cb.dataset.dynToggle)}`, {
          method: "PATCH",
          body: JSON.stringify({ enabled: cb.checked }),
        });
        toast(cb.checked ? "Dynamic rule enabled" : "Dynamic rule disabled");
      };
    });
    root.querySelectorAll("[data-dyn-del]").forEach((btn) => {
      btn.onclick = async () => {
        await api(`/api/dynamic/rules/${encodeURIComponent(btn.dataset.dynDel)}`, { method: "DELETE" });
        await refreshGlobalState();
        toast("Dynamic rule deleted");
        await renderCurrentView();
      };
    });
    const alertsList = (STATE.dynamicAlertsData && STATE.dynamicAlertsData.alerts) || [];
    root.querySelectorAll("[data-dyn-al-idx]").forEach((tr) => {
      tr.onclick = () => {
        const al = alertsList[Number(tr.dataset.dynAlIdx)];
        if (al) openDrawer("DYNAMIC ALERT", `${al.rule_id} · ${al.rule_name}`, `<pre class="terminal">${esc(JSON.stringify(al, null, 2))}</pre>`);
      };
    });
  } else {
    document.getElementById("btn-save-thresholds").onclick = async () => {
      const det = Number(document.getElementById("th-min-det").value);
      const checked = Array.from(root.querySelectorAll(".th-reg:checked")).map((c) => c.value);
      const extras = document.getElementById("th-extra-regions").value.split(",").map((s) => s.trim()).filter(Boolean);
      const regions = Array.from(new Set([...checked, ...extras]));
      await api("/api/thresholds", {
        method: "PUT",
        body: JSON.stringify({
          budget_usd: Number(document.getElementById("th-budget").value),
          log_retention_days: Number(document.getElementById("th-retention").value),
          min_detection_rate: det,
          max_evasion_rate: Number((1 - det).toFixed(4)),
          max_false_alarm_rate: Number(document.getElementById("th-max-fa").value),
          max_ingest_lag_ms: Number(document.getElementById("th-lag").value),
          collector_timeout_seconds: Number(document.getElementById("th-timeout").value),
          allowed_regions: regions.length ? regions : ["eu-west-1"],
          enable_data_events: document.getElementById("th-data").checked,
          enable_instance: document.getElementById("th-ec2").checked,
        }),
      });
      await refreshGlobalState();
      toast("Thresholds saved");
    };
  }
}

/* ------------------------------------------------------------------ */
/* 8. Logs                                                            */
/* ------------------------------------------------------------------ */

async function renderLogs(root) {
  const qs = new URLSearchParams({
    search: STATE.logsSearch || "",
    alerts_only: STATE.logsAlertsOnly ? "true" : "false",
  });
  if (STATE.logsRunId) qs.set("run_id", STATE.logsRunId);
  if (STATE.logsCloud && STATE.logsCloud !== "all") qs.set("cloud_provider", STATE.logsCloud);
  STATE.logsData = await api(`/api/logs?${qs.toString()}`);
  const d = STATE.logsData;
  const runList = STATE.app.db?.run_list || [];

  const eventsRows = (d.events || [])
    .map(
      (ev, idx) => `
      <tr class="clickable" data-ev-idx="${idx}">
        <td class="mono small-text">${esc(ev.event_time)}</td>
        <td class="mono"><span class="badge">${esc((ev.cloud_provider || "aws").toUpperCase())}</span> <strong>${esc(ev.event_name)}</strong></td>
        <td class="mono small-text">${esc(ev.event_source)}</td>
        <td class="mono small-text">${esc(ev.source_ip || "-")}</td>
        <td class="mono small-text">${esc(ev.user_identity_type || "-")}</td>
        <td>${ev.matched_rules ? `<span class="badge err">${esc(ev.matched_rules)}</span>` : `<span class="badge">none</span>`}</td>
      </tr>
    `
    )
    .join("");

  const trialRows = (d.trial_logs || [])
    .map(
      (t) => `
      <tr>
        <td class="mono small-text">${esc(t.trial_id)}</td>
        <td class="mono">${esc(t.technique_id)}</td>
        <td><span class="badge">${esc(t.variant_set)}</span></td>
        <td><span class="badge ${t.attack_succeeded === 1 ? "ok" : "err"}">${t.attack_succeeded === 1 ? "Pass" : "Fail"}</span></td>
        <td><span class="badge ${t.variant_changed === 1 ? "ok" : ""}">${t.variant_changed === 1 ? "Changed" : "Base"}</span></td>
        <td class="small-text">${esc(t.error || "-")}</td>
      </tr>
    `
    )
    .join("");

  const jobRows = (d.jobs || [])
    .map(
      (j) => `
      <tr class="clickable" data-inspect-job="${esc(j.job_id)}">
        <td class="mono">${esc(j.job_id)}</td>
        <td class="mono">${esc(j.kind)}</td>
        <td>${esc(j.title)}</td>
        <td><span class="badge ${j.status === "completed" ? "ok" : j.status === "running" ? "info" : "err"}">${esc(j.status)}</span></td>
        <td class="mono small-text">${esc(j.started_at)}</td>
        <td class="mono">${j.log_count} lines</td>
      </tr>
    `
    )
    .join("");

  root.innerHTML = `
    <div class="card">
      <div class="space-between" style="margin-bottom:14px">
        <div class="subtabs" style="margin-bottom:0;border:none">
          <button type="button" class="subtab ${STATE.logsTab === "events" ? "active" : ""}" data-ltab="events">Cloud SIEM Events (${(d.events || []).length})</button>
          <button type="button" class="subtab ${STATE.logsTab === "trials" ? "active" : ""}" data-ltab="trials">Trials (${(d.trial_logs || []).length})</button>
          <button type="button" class="subtab ${STATE.logsTab === "jobs" ? "active" : ""}" data-ltab="jobs">Jobs (${(d.jobs || []).length})</button>
        </div>

        ${STATE.logsTab === "events"
      ? `
          <div class="row-flex">
            <div style="width:120px">
              <select id="log-cloud">
                <option value="all" ${(STATE.logsCloud || "all") === "all" ? "selected" : ""}>All Clouds</option>
                <option value="aws" ${STATE.logsCloud === "aws" ? "selected" : ""}>AWS</option>
                <option value="gcp" ${STATE.logsCloud === "gcp" ? "selected" : ""}>GCP</option>
                <option value="azure" ${STATE.logsCloud === "azure" ? "selected" : ""}>Azure</option>
              </select>
            </div>
            <div style="width:155px">
              <select id="log-run">
                <option value="">All Runs</option>
                ${runList.map((r) => `<option value="${esc(r.run_id)}" ${STATE.logsRunId === r.run_id ? "selected" : ""}>${esc(r.run_id)}</option>`).join("")}
              </select>
            </div>
            <div style="width:220px">
              ${comboHtml("log-search", STATE.logsSearch, ["GetObject", "ListUsers", "DescribeInstances", "CreateAccessKey", "AssumeRole", "DescribeVpcs"], { placeholder: "Filter event, IP, agent..." })}
            </div>
            <label class="check-pill"><input type="checkbox" id="log-alerts-only" ${STATE.logsAlertsOnly ? "checked" : ""} /> Alerts only</label>
            <button type="button" class="btn btn-secondary btn-sm" id="btn-filter-logs">Apply</button>
          </div>
        `
      : ""
    }
      </div>

      ${STATE.logsTab === "events"
      ? `
        <div class="card" style="margin-bottom:12px;background:var(--surface-2,transparent);padding:12px">
          <div class="space-between">
            <div>
              <strong>Live Cloud SIEM Collector (Connected Clouds)</strong>
              <span class="small-text muted-text" style="margin-left:8px">Pulls CloudTrail, GCP Cloud Audit Logs, &amp; Azure Activity / Entra logs and evaluates detections automatically.</span>
            </div>
            <div class="row-flex">
              <select id="log-pull-cloud" style="width:165px">
                <option value="connected">All Connected Clouds</option>
                <option value="aws">AWS CloudTrail</option>
                <option value="gcp">GCP Cloud Audit Logs</option>
                <option value="azure">Azure Activity &amp; Entra</option>
              </select>
              <select id="log-pull-hours" style="width:105px">
                <option value="1">Last 1h</option>
                <option value="24" selected>Last 24h</option>
                <option value="168">Last 7d</option>
              </select>
              <button type="button" class="btn btn-primary btn-sm" id="btn-pull-cloud-logs">Pull Live Cloud Logs</button>
            </div>
          </div>
        </div>
        <details class="fold" style="margin-bottom:12px">
          <summary>Or Paste / Ingest JSON Logs Manually (AWS CloudTrail, GCP Audit, Azure Activity / Entra JSON)</summary>
          <div class="form-grid" style="margin-top:8px">
            <textarea id="log-ingest-json" rows="3" placeholder='Paste CloudTrail Records, GCP Audit entries, or Azure Activity / Entra JSON...'></textarea>
            <div class="space-between">
              <select id="log-ingest-cloud" style="max-width:160px">
                <option value="auto">Auto-Detect Cloud</option>
                <option value="aws">AWS CloudTrail</option>
                <option value="gcp">GCP Cloud Audit</option>
                <option value="azure">Azure / Entra</option>
              </select>
              <button type="button" class="btn btn-primary btn-sm" id="btn-ingest-logs">Ingest Logs</button>
            </div>
          </div>
        </details>
        <div class="table-wrap" style="max-height:520px;overflow:auto">
          <table>
            <thead><tr><th>Time</th><th>Event</th><th>Source</th><th>IP</th><th>Identity</th><th>Alerts</th></tr></thead>
            <tbody>${eventsRows || `<tr><td colspan="6" class="muted-text">No events captured.</td></tr>`}</tbody>
          </table>
        </div>
      `
      : STATE.logsTab === "trials"
        ? `
        <div class="table-wrap" style="max-height:520px;overflow:auto">
          <table>
            <thead><tr><th>Trial ID</th><th>Technique</th><th>Set</th><th>Attack</th><th>Diff</th><th>Errors</th></tr></thead>
            <tbody>${trialRows || `<tr><td colspan="6" class="muted-text">No trials recorded.</td></tr>`}</tbody>
          </table>
        </div>
      `
        : `
        <div class="table-wrap" style="max-height:520px;overflow:auto">
          <table>
            <thead><tr><th>Job ID</th><th>Type</th><th>Title</th><th>Status</th><th>Started</th><th>Output</th></tr></thead>
            <tbody>${jobRows || `<tr><td colspan="6" class="muted-text">No background jobs yet.</td></tr>`}</tbody>
          </table>
        </div>
      `
    }
    </div>
  `;

  root.querySelectorAll("[data-ltab]").forEach((b) => {
    b.onclick = () => {
      STATE.logsTab = b.dataset.ltab;
      renderCurrentView();
    };
  });

  if (STATE.logsTab === "events") {
    const applyFilter = () => {
      STATE.logsCloud = document.getElementById("log-cloud").value;
      STATE.logsRunId = document.getElementById("log-run").value;
      STATE.logsSearch = document.getElementById("log-search").value.trim();
      STATE.logsAlertsOnly = document.getElementById("log-alerts-only").checked;
      renderCurrentView();
    };
    document.getElementById("log-cloud").onchange = applyFilter;
    document.getElementById("log-run").onchange = applyFilter;
    document.getElementById("log-alerts-only").onchange = applyFilter;
    document.getElementById("btn-filter-logs").onclick = applyFilter;
    document.getElementById("log-search").onkeydown = (e) => {
      if (e.key === "Enter") applyFilter();
    };
    document.getElementById("btn-pull-cloud-logs").onclick = async (e) => {
      e.target.disabled = true;
      try {
        const res = await api("/api/clouds/pull", {
          method: "POST",
          body: JSON.stringify({
            cloud_provider: document.getElementById("log-pull-cloud").value,
            hours: Number(document.getElementById("log-pull-hours").value || 24),
            replay_rules: true,
          }),
        });
        await refreshGlobalState();
        toast(`Pulled ${res.total_ingested} cloud SIEM events (${(res.clouds_queried || []).join(", ")})`);
        await renderCurrentView();
      } catch (err) {
        toast(err.message, "err");
      } finally {
        e.target.disabled = false;
      }
    };
    document.getElementById("btn-ingest-logs").onclick = async () => {
      const txt = document.getElementById("log-ingest-json").value.trim();
      if (!txt) {
        toast("Paste JSON log events first", "err");
        return;
      }
      try {
        const res = await api("/api/clouds/ingest", {
          method: "POST",
          body: JSON.stringify({
            json_text: txt,
            cloud_provider: document.getElementById("log-ingest-cloud").value,
          }),
        });
        toast(`Ingested ${res.ingested} events`);
        await renderCurrentView();
      } catch (err) {
        toast(err.message, "err");
      }
    };
  }

  root.querySelectorAll("[data-ev-idx]").forEach((tr) => {
    tr.onclick = () => {
      const ev = d.events[Number(tr.dataset.evIdx)];
      if (ev) openDrawer("EVENT", ev.event_name, `<pre class="terminal">${esc(JSON.stringify(ev, null, 2))}</pre>`);
    };
  });

  root.querySelectorAll("[data-inspect-job]").forEach((tr) => {
    tr.onclick = async () => {
      const job = await api(`/api/jobs/${tr.dataset.inspectJob}`);
      openDrawer("JOB LOG", job.title, `<pre class="terminal">${esc((job.logs || []).join("\n"))}</pre>`);
    };
  });
}

/* ------------------------------------------------------------------ */
/* 9. CLI Console                                                     */
/* ------------------------------------------------------------------ */

function renderCli(root) {
  const presets = [
    { value: "proxy status", hint: "Live proxy status" },
    { value: "proxy simulate", hint: "Send live HTTP attack/clean burst" },
    { value: "dynamic audit --ruleset baseline-v1", hint: "Audit hardcoded rules" },
    { value: "dynamic enhance --ruleset baseline-v1", hint: "Build enhanced-v1 rules" },
    { value: "dynamic list", hint: "List dynamic behavioral rules" },
    { value: "dynamic replay", hint: "Run dynamic detection on batch events" },
    { value: "lab doctor", hint: "Diagnostics" },
    { value: "lab status", hint: "Resource census" },
    { value: "attacks list", hint: "Active techniques" },
    { value: "config show", hint: "Thresholds & targets" },
    { value: "variants generate", hint: "Build 5-factor variants" },
    { value: "runner preflight --variant-id T1530-ofat-000 --synthetic", hint: "Preflight test" },
    { value: "analyse report", hint: "Summary report" },
  ];

  root.innerHTML = `
    <div class="card">
      <div class="card-header"><h3 class="card-title">CLI Console</h3></div>

      <div class="row-flex" style="margin-bottom:12px">
        <div style="flex:1;min-width:260px">
          ${comboHtml("cli-input", "", presets, { mono: true, placeholder: "Choose a command or type e.g. attacks list" })}
        </div>
        <button type="button" class="btn btn-primary" id="btn-cli-run">Run</button>
        <button type="button" class="btn btn-secondary" id="btn-cli-clear">Clear</button>
      </div>

      <div class="terminal" id="cli-term" style="min-height:420px">${STATE.cliOutputs.length ? STATE.cliOutputs.map(esc).join("\n\n") : "Select a command from the dropdown or type any identity-shield subcommand."
    }</div>
    </div>
  `;

  const execCmd = async (cmdText) => {
    if (!cmdText.trim()) return;
    STATE.cliHistory.unshift(cmdText);
    const term = document.getElementById("cli-term");
    term.textContent = `Running: ${cmdText}...`;
    try {
      const res = await api("/api/cli/exec", { method: "POST", body: JSON.stringify({ command: cmdText }) });
      const block = `$ ${res.command}  [exit=${res.returncode}, ${res.duration_s}s]\n${res.stdout || ""}${res.stderr ? "\n[STDERR]\n" + res.stderr : ""}`;
      STATE.cliOutputs.unshift(block.trim());
      term.textContent = STATE.cliOutputs.join("\n\n------------------------------------------------------------\n\n");
      await refreshGlobalState();
    } catch (e) {
      toast(e.message, "err");
    }
  };

  document.getElementById("btn-cli-run").onclick = () => execCmd(document.getElementById("cli-input").value);
  document.getElementById("cli-input").onkeydown = (e) => {
    if (e.key === "Enter") execCmd(e.target.value);
  };
  document.getElementById("btn-cli-clear").onclick = () => {
    STATE.cliOutputs = [];
    document.getElementById("cli-term").textContent = "Cleared.";
  };
}

function bindNavigationClicks(container) {
  container.querySelectorAll("[data-goto]").forEach((el) => {
    el.onclick = (e) => {
      e.preventDefault();
      if (el.dataset.connCloud) STATE.connCloud = el.dataset.connCloud;
      navigate(el.dataset.goto);
    };
  });
}

/* ------------------------------------------------------------------ */
/* Bootstrap                                                          */
/* ------------------------------------------------------------------ */

document.addEventListener("DOMContentLoaded", async () => {
  document.addEventListener("click", () => closeAllCombos());
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeAllCombos();
      closeDrawer();
    }
  });

  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.onclick = () => navigate(btn.dataset.view);
  });
  document.querySelectorAll(".topbar [data-goto]").forEach((btn) => {
    btn.onclick = () => {
      if (btn.dataset.connCloud) STATE.connCloud = btn.dataset.connCloud;
      navigate(btn.dataset.goto);
    };
  });
  document.getElementById("drawer-close").onclick = closeDrawer;
  document.getElementById("drawer-backdrop").onclick = closeDrawer;

  document.getElementById("btn-refresh-all").onclick = async () => {
    await refreshGlobalState();
    await renderCurrentView();
    toast("Refreshed");
  };

  document.getElementById("btn-reset-db").onclick = async () => {
    if (!confirm("Reset local SQLite database to 0 runs?")) return;
    await api("/api/db/reset", { method: "POST" });
    STATE.selectedRunId = "";
    STATE.logsRunId = "";
    await refreshGlobalState();
    await renderCurrentView();
    toast("Database reset");
  };

  await refreshGlobalState();
  await renderCurrentView();
});
