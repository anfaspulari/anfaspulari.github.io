'use strict';

// ─────────────────────────────────────────────────────────────
// TERMINAL — commands registry
// ─────────────────────────────────────────────────────────────

var COMMANDS = {

  whoami: function () {
    return [
      { text: 'Anfas Pulari',                                              type: 'info' },
      { text: 'Role    : Cybersecurity Analyst, Tier 2 SOC',              type: 'out'  },
      { text: 'Company : ZeroFox — Digital Risk Protection',              type: 'out'  },
      { text: 'Focus   : Phishing | Threat Intel | Incident Response',    type: 'out'  },
    ];
  },

  help: function () {
    return [
      { text: 'Available commands:',                                            type: 'info' },
      { text: '  whoami                — current operator profile',             type: 'out'  },
      { text: '  skills                — list core competencies',               type: 'out'  },
      { text: '  projects              — active security projects',             type: 'out'  },
      { text: '  analyze phishing_case — run a sample SOC analysis',           type: 'out'  },
      { text: '  status                — current alert queue',                  type: 'out'  },
      { text: '  clear                 — clear terminal output',                type: 'out'  },
    ];
  },

  skills: function () {
    return [
      { text: 'Core competencies:',                                                       type: 'info' },
      { text: '  [SECURITY]   Phishing Analysis · Threat Intelligence · IR',             type: 'out'  },
      { text: '  [TOOLS]      Splunk · ZeroFox Platform · VirusTotal · Shodan',          type: 'out'  },
      { text: '  [CODE]       Python · Bash · Regex · YARA Rules',                       type: 'out'  },
      { text: '  [FRAMEWORK]  MITRE ATT&CK · IOC Analysis · OSINT',                     type: 'out'  },
    ];
  },

  projects: function () {
    return [
      { text: 'Security projects:',                                                   type: 'info' },
      { text: '  [01] PhishScan    — Phishing detection CLI (Python)',               type: 'out'  },
      { text: '  [02] ThreatBoard  — IOC visualization dashboard (JS/D3)',           type: 'out'  },
      { text: '  [03] LogLens      — SIEM log correlator (Python/Bash)',             type: 'out'  },
    ];
  },

  status: function () {
    var open = Math.floor(Math.random() * 10) + 5;
    return [
      { text: '[ALERT QUEUE STATUS — ' + getTimestamp() + ']', type: 'info' },
      { text: '  Open alerts    : ' + open,                    type: 'out'  },
      { text: '  Priority HIGH  : 2',                          type: 'warn' },
      { text: '  Assigned to me : 3',                          type: 'out'  },
      { text: '  Avg close time : 18 min',                     type: 'out'  },
    ];
  },

  'analyze phishing_case': function () {
    return [
      { text: '[CASE-4821] Initializing analysis...',                                      type: 'info'   },
      { text: '  Sender       : support@secure-update-portal[.]com',                      type: 'out'    },
      { text: '  Subject      : "Urgent: Verify your account credentials"',               type: 'out'    },
      { text: '  URL flagged  : hxxps://secure-login-update[.]com/verify',                type: 'warn'   },
      { text: '  IP resolved  : 185.220.101.x  (TOR exit node)',                          type: 'warn'   },
      { text: '  Kit pattern  : credential_harvester_v3 (matched 4 prior campaigns)',     type: 'warn'   },
      { text: '  VERDICT      : PHISHING CONFIRMED — takedown request submitted',         type: 'threat' },
    ];
  },

};

// ─────────────────────────────────────────────────────────────
// TERMINAL — core functions
// ─────────────────────────────────────────────────────────────

function initTerminal() {
  var historyEl = document.getElementById('terminal-history');
  var inputEl   = document.getElementById('terminal-input');
  var wrapEl    = document.getElementById('interactive-terminal');

  if (!historyEl || !inputEl || !wrapEl) return;

  // Pre-populate with realistic boot sequence
  var boot = [
    { cmd: 'whoami',               output: COMMANDS.whoami()                    },
    { cmd: 'analyze phishing_case', output: COMMANDS['analyze phishing_case']() },
  ];

  boot.forEach(function (item) {
    appendCmd(historyEl, item.cmd);
    item.output.forEach(function (line) { appendOut(historyEl, line.text, line.type); });
    appendBlank(historyEl);
  });

  scrollBottom(historyEl);

  // Click anywhere on terminal → focus input
  wrapEl.addEventListener('click', function () { inputEl.focus(); });

  // Handle Enter
  inputEl.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter') return;
    var raw = inputEl.value.trim();
    inputEl.value = '';
    if (!raw) return;

    var cmd = raw.toLowerCase();
    appendCmd(historyEl, raw);

    if (cmd === 'clear') {
      historyEl.innerHTML = '';
      return;
    }

    var handler = COMMANDS[cmd];
    if (handler) {
      handler().forEach(function (line) { appendOut(historyEl, line.text, line.type); });
    } else {
      appendOut(historyEl, 'command not found: "' + escapeHtml(raw) + '"  —  try help', 'error');
    }

    appendBlank(historyEl);
    scrollBottom(historyEl);
  });
}

function appendCmd(container, cmd) {
  var el = document.createElement('p');
  el.className = 't-line';
  el.innerHTML = '<span class="t-prompt">anfas@sec:~$</span> ' + escapeHtml(cmd);
  container.appendChild(el);
}

function appendOut(container, text, type) {
  var el = document.createElement('p');
  el.className = 't-line t-out-' + (type || 'out');
  el.textContent = text;
  container.appendChild(el);
}

function appendBlank(container) {
  var el = document.createElement('p');
  el.style.height = '4px';
  container.appendChild(el);
}

function scrollBottom(el) { el.scrollTop = el.scrollHeight; }

// ─────────────────────────────────────────────────────────────
// PROJECTS — fetch from JSON, render cards
// ─────────────────────────────────────────────────────────────

async function loadProjects() {
  var grid = document.getElementById('projects-grid');
  if (!grid) return;

  try {
    var res = await fetch('assets/data/projects.json');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    var projects = await res.json();
    renderProjects(grid, projects);
  } catch (err) {
    // Static HTML fallback remains intact
    console.warn('[portfolio] projects.json not loaded — using static fallback:', err.message);
  }
}

function renderProjects(grid, projects) {
  grid.innerHTML = projects.map(function (p) {
    var tags = p.stack.map(function (t) {
      return '<span class="project-tag">' + escapeHtml(t) + '</span>';
    }).join('');

    return (
      '<div class="project-card">' +
        '<div class="project-emoji">' + p.emoji + '</div>' +
        '<p class="project-title">'  + escapeHtml(p.name)        + '</p>' +
        '<p class="project-origin">' + escapeHtml(p.origin)      + '</p>' +
        '<p class="project-desc">'   + escapeHtml(p.description) + '</p>' +
        '<div class="project-tags">' + tags + '</div>' +
      '</div>'
    );
  }).join('');
}

// ─────────────────────────────────────────────────────────────
// ALERT STREAM — live threat simulation
// ─────────────────────────────────────────────────────────────

var ALERT_POOL = [
  { level: 'info',   label: '[INFO]  ',   msg: 'Domain reputation check initiated'                          },
  { level: 'info',   label: '[INFO]  ',   msg: 'New alert assigned — Case #'                                },
  { level: 'info',   label: '[INFO]  ',   msg: 'IOC enrichment complete — 4 indicators added to feed'       },
  { level: 'info',   label: '[INFO]  ',   msg: 'SIEM correlation rule matched — reviewing for escalation'   },
  { level: 'info',   label: '[INFO]  ',   msg: 'Case #4830 closed — false positive confirmed'               },
  { level: 'warn',   label: '[WARN]  ',   msg: 'Suspicious redirect chain detected'                         },
  { level: 'warn',   label: '[WARN]  ',   msg: 'Lookalike domain registered: paypa1-secure[.]com'           },
  { level: 'warn',   label: '[WARN]  ',   msg: 'High-volume campaign — 3 client brands targeted'            },
  { level: 'warn',   label: '[WARN]  ',   msg: 'Social media impersonation detected: LinkedIn'              },
  { level: 'warn',   label: '[WARN]  ',   msg: 'Phishing URL submitted via threat feed — analyzing'         },
  { level: 'threat', label: '[THREAT]',   msg: 'Credential harvesting page confirmed — takedown requested'  },
  { level: 'threat', label: '[THREAT]',   msg: 'Active phishing kit identified on shared host'              },
  { level: 'threat', label: '[THREAT]',   msg: 'Executive impersonation campaign — CRITICAL priority'       },
  { level: 'threat', label: '[THREAT]',   msg: 'Malicious attachment detonated in sandbox — C2 beacon seen' },
];

function initAlertStream() {
  var stream = document.getElementById('alert-stream');
  if (!stream) return;

  // Seed with 5 entries
  for (var i = 0; i < 5; i++) { addAlertEntry(stream); }

  // New entry every 3.5 seconds
  setInterval(function () {
    addAlertEntry(stream);
    // Keep at most 10 visible
    while (stream.children.length > 10) {
      stream.removeChild(stream.firstChild);
    }
  }, 3500);
}

function addAlertEntry(stream) {
  var item  = ALERT_POOL[Math.floor(Math.random() * ALERT_POOL.length)];
  var msg   = item.msg;
  if (msg.endsWith('#')) { msg += (Math.floor(Math.random() * 900) + 4800); }

  var el = document.createElement('div');
  el.className = 'alert-entry alert-' + item.level + ' alert-new';
  el.innerHTML =
    '<span class="alert-time">[' + getTimestamp() + ']</span>' +
    '<span class="alert-level">' + item.label + '</span>' +
    '<span class="alert-msg">'   + escapeHtml(msg) + '</span>';

  stream.appendChild(el);
  setTimeout(function () { el.classList.remove('alert-new'); }, 400);
}

// ─────────────────────────────────────────────────────────────
// CONTACT FORM
// ─────────────────────────────────────────────────────────────

function initContactForm() {
  var form = document.getElementById('contact-form');
  if (!form) return;

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    var btn = form.querySelector('button[type="submit"]');
    btn.textContent = 'Message sent ✓';
    btn.style.background = '#4ade80';
    btn.style.color = '#0d0d0d';
    setTimeout(function () {
      btn.textContent = 'Send Message';
      btn.style.background = '';
      btn.style.color = '';
      form.reset();
    }, 3000);
  });
}

// ─────────────────────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────────────────────

function getTimestamp() {
  return new Date().toTimeString().slice(0, 8);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;');
}

// ─────────────────────────────────────────────────────────────
// BOOT
// ─────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
  document.getElementById('year').textContent = new Date().getFullYear();
  initTerminal();
  loadProjects();
  initAlertStream();
  initContactForm();
});
