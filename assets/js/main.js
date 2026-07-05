'use strict';

// ─────────────────────────────────────────────────────────────
// TERMINAL - commands registry
// ─────────────────────────────────────────────────────────────

var COMMANDS = {

  whoami: function () {
    return [
      { text: 'Anfas Pulari',                                            type: 'info'   },
      { text: 'Role    : Cybersecurity Analyst, Tier 2 SOC',            type: 'out'    },
      { text: 'Company : Leading Digital Risk Protection Platform',      type: 'out'    },
      { text: 'Focus   : Phishing | Threat Intel | Incident Response',  type: 'out'    },
    ];
  },

  help: function () {
    return [
      { text: 'Available commands:',                                          type: 'info' },
      { text: '  whoami                - current operator profile',           type: 'out'  },
      { text: '  skills                - list core competencies',             type: 'out'  },
      { text: '  projects              - active security projects',           type: 'out'  },
      { text: '  analyze phishing_case - run a sample SOC analysis',         type: 'out'  },
      { text: '  status                - current alert queue',                type: 'out'  },
      { text: '  clear                 - clear terminal output',              type: 'out'  },
    ];
  },

  skills: function () {
    return [
      { text: 'Core competencies:',                                                     type: 'info' },
      { text: '  [SECURITY]   Phishing Analysis · Threat Intelligence · IR',           type: 'out'  },
      { text: '  [TOOLS]      Splunk · DRP Platforms · VirusTotal · Shodan',            type: 'out'  },
      { text: '  [CODE]       Python · Bash · YARA Rules',                              type: 'out'  },
      { text: '  [FRAMEWORK]  MITRE ATT&CK · OSINT · Cloud Security · IAM',           type: 'out'  },
    ];
  },

  projects: function () {
    return [
      { text: 'Security projects:',                                                 type: 'info' },
      { text: '  [01] PhishScan    - Phishing detection CLI (Python)',             type: 'out'  },
      { text: '  [02] ThreatBoard  - IOC visualization dashboard (JS/D3)',         type: 'out'  },
      { text: '  [03] LogLens      - SIEM log correlator (Python/Bash)',           type: 'out'  },
    ];
  },

  status: function () {
    return [
      { text: '[ALERT QUEUE STATUS - shift snapshot]', type: 'info' },
      { text: '  Open alerts    : 9',                  type: 'out'  },
      { text: '  Priority HIGH  : 2',                  type: 'warn' },
      { text: '  Assigned to me : 3',                  type: 'out'  },
      { text: '  Avg close time : 18 min',             type: 'out'  },
      { text: '  Snapshot     : shift handoff (static demo)', type: 'out' },
    ];
  },

  'analyze phishing_case': function () {
    return [
      { text: '[CASE-4821] Initializing analysis...',                                    type: 'info'   },
      { text: '  Sender       : support@secure-update-portal[.]com',                    type: 'out'    },
      { text: '  Subject      : "Urgent: Verify your account credentials"',             type: 'out'    },
      { text: '  URL flagged  : hxxps://secure-login-update[.]com/verify',              type: 'warn'   },
      { text: '  IP resolved  : anonymized infrastructure (TOR/Proxy detected)',        type: 'warn'   },
      { text: '  Kit pattern  : credential_harvester_v3 (4 prior campaigns matched)',   type: 'warn'   },
      { text: '  VERDICT      : PHISHING CONFIRMED - takedown request submitted',       type: 'threat' },
    ];
  },

};

// ─────────────────────────────────────────────────────────────
// TERMINAL - init + handlers
// ─────────────────────────────────────────────────────────────

function initTerminal() {
  var historyEl = document.getElementById('terminal-history');
  var inputEl   = document.getElementById('terminal-input');
  var wrapEl    = document.getElementById('interactive-terminal');

  if (!historyEl || !inputEl || !wrapEl) return;

  // Boot: run whoami only
  appendCmd(historyEl, 'whoami');
  COMMANDS.whoami().forEach(function (line) { appendOut(historyEl, line.text, line.type); });
  appendBlank(historyEl);
  scrollBottom(historyEl);

  // Focus input when clicking anywhere on terminal
  wrapEl.addEventListener('click', function () { inputEl.focus(); });

  // Handle command submission
  inputEl.addEventListener('keydown', function (e) {
    if (e.key !== 'Enter') return;

    var raw = inputEl.value.trim();
    inputEl.value = '';
    if (!raw) return;

    handleTerminalCommand(historyEl, raw);
    scrollBottom(historyEl);
  });
}

function handleTerminalCommand(historyEl, raw) {
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
    appendOut(historyEl, 'command not recognized: "' + escapeHtml(raw) + '"', 'error');
    appendOut(historyEl, 'type "help" to see available commands', 'info');
  }

  appendBlank(historyEl);
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
// PROJECTS - fetch from JSON, render cards
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
    console.warn('[portfolio] projects.json unavailable, static fallback active:', err.message);
    // Static HTML cards already in the DOM - no further action needed
  }
}

// Inline-SVG icons reused by .project-icon (1.5 stroke, currentColor - matches case-study/mc-icon style)
var PROJECT_ICONS = {
  phishing: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
              '<path d="M12 3v9"/>' +
              '<path d="M12 12a5 5 0 1 0 5 5"/>' +
              '<path d="M9 3h6"/>' +
            '</svg>',
  graph:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
              '<circle cx="6" cy="6" r="2"/>' +
              '<circle cx="18" cy="6" r="2"/>' +
              '<circle cx="12" cy="18" r="2"/>' +
              '<circle cx="6" cy="14" r="2"/>' +
              '<path d="M7.5 7.4l3 3"/>' +
              '<path d="M16.5 7.4l-3 3"/>' +
              '<path d="M12 14v2"/>' +
              '<path d="M7.5 13l3-2"/>' +
            '</svg>',
  logs:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
              '<path d="M3 5h10"/>' +
              '<path d="M3 9h8"/>' +
              '<path d="M3 13h5"/>' +
              '<circle cx="16" cy="15" r="4"/>' +
              '<path d="M19 18l3 3"/>' +
            '</svg>',
};

function renderProjects(grid, projects) {
  grid.innerHTML = projects.map(function (p) {
    var icon = PROJECT_ICONS[p.icon] || PROJECT_ICONS.graph;

    var metrics = (p.metrics || []).map(function (m) {
      return '<span class="project-metric">' + escapeHtml(m) + '</span>';
    }).join('');

    var tags = p.stack.map(function (t) {
      return '<span class="project-tag">' + escapeHtml(t) + '</span>';
    }).join('');

    var ghLink = '<a href="' + escapeHtml(p.github) + '" target="_blank" rel="noopener" class="project-link">GitHub →</a>';
    var demoBtn = p.demo
      ? '<a href="' + escapeHtml(p.demo) + '" target="_blank" rel="noopener" class="project-cta">Live demo →</a>'
      : '';

    return (
      '<div class="project-card">' +
        '<div class="project-icon">'    + icon + '</div>' +
        '<p class="project-title">'     + escapeHtml(p.name)        + '</p>' +
        '<p class="project-origin">'    + escapeHtml(p.origin)      + '</p>' +
        '<p class="project-desc">'      + escapeHtml(p.description) + '</p>' +
        '<div class="project-metrics">' + metrics + '</div>' +
        '<div class="project-tags">'    + tags + '</div>' +
        '<div class="project-footer">'  + ghLink + demoBtn + '</div>' +
        '<p class="project-disclaimer">Simulated/anonymized data only - no client material is reproduced.</p>' +
      '</div>'
    );
  }).join('');

  // Re-run scroll observer on newly rendered cards
  observeElements(document.querySelectorAll('#projects-grid .project-card'));
}

// ─────────────────────────────────────────────────────────────
// MOBILE NAV
// ─────────────────────────────────────────────────────────────

function initMobileNav() {
  var btn   = document.getElementById('hamburger-btn');
  var links = document.getElementById('nav-links');
  if (!btn || !links) return;

  btn.addEventListener('click', function () {
    var isOpen = links.classList.toggle('open');
    btn.classList.toggle('open', isOpen);
    btn.setAttribute('aria-expanded', String(isOpen));
  });

  // Close on any nav link click
  links.querySelectorAll('a').forEach(function (a) {
    a.addEventListener('click', function () {
      links.classList.remove('open');
      btn.classList.remove('open');
      btn.setAttribute('aria-expanded', 'false');
    });
  });
}

// ─────────────────────────────────────────────────────────────
// SCROLL ANIMATIONS
// ─────────────────────────────────────────────────────────────

function initScrollAnimations() {
  var targets = document.querySelectorAll(
    '.stat-box, .exp-item, .skill-group, .project-card, ' +
    '.training-card'
  );

  // Stagger siblings within the same grid
  document.querySelectorAll('.skills-grid, .projects-grid, .training-grid, .stats-row').forEach(function (grid) {
    Array.from(grid.children).forEach(function (child, i) {
      child.style.transitionDelay = (i * 0.07) + 's';
    });
  });

  observeElements(targets);
}

function observeElements(elements) {
  if (!('IntersectionObserver' in window)) {
    // Fallback: just show everything
    elements.forEach(function (el) { el.classList.add('fade-in', 'is-visible'); });
    return;
  }

  var observer = new IntersectionObserver(function (entries) {
    entries.forEach(function (entry) {
      if (entry.isIntersecting) {
        entry.target.classList.add('is-visible');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1, rootMargin: '0px 0px -40px 0px' });

  elements.forEach(function (el) {
    el.classList.add('fade-in');
    observer.observe(el);
  });
}

// ─────────────────────────────────────────────────────────────
// CONTACT FORM - Formspree AJAX submission
// ─────────────────────────────────────────────────────────────

function initContactForm() {
  var form = document.getElementById('contact-form');
  if (!form) return;

  var statusEl = document.getElementById('form-status');

  function showStatus(msg, type) {
    if (!statusEl) return;
    statusEl.textContent   = msg;
    statusEl.style.display = 'block';
    statusEl.style.padding = '0.6rem 0.8rem';
    statusEl.style.marginBottom = '0.75rem';
    statusEl.style.borderRadius = '4px';
    statusEl.style.fontSize  = '0.875rem';
    statusEl.style.fontFamily = 'var(--mono)';
    if (type === 'success') {
      statusEl.style.background = 'rgba(74,222,128,0.12)';
      statusEl.style.color      = '#4ade80';
      statusEl.style.border     = '1px solid rgba(74,222,128,0.3)';
    } else {
      statusEl.style.background = 'rgba(248,113,113,0.12)';
      statusEl.style.color      = '#f87171';
      statusEl.style.border     = '1px solid rgba(248,113,113,0.3)';
    }
  }

  function hideStatus() {
    if (statusEl) statusEl.style.display = 'none';
  }

  form.addEventListener('submit', async function (e) {
    e.preventDefault();
    hideStatus();

    // Frontend validation
    var nameVal    = form.querySelector('[name="name"]').value.trim();
    var emailVal   = form.querySelector('[name="email"]').value.trim();
    var messageVal = form.querySelector('[name="message"]').value.trim();

    if (!nameVal || !emailVal || !messageVal) {
      showStatus('All fields are required.', 'error');
      return;
    }

    var emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(emailVal)) {
      showStatus('Please enter a valid email address.', 'error');
      return;
    }

    var btn          = form.querySelector('button[type="submit"]');
    var originalText = btn.textContent;

    btn.textContent   = 'Sending...';
    btn.disabled      = true;
    btn.style.opacity = '0.7';

    try {
      var res = await fetch(form.action, {
        method:  'POST',
        body:    new FormData(form),
        headers: { 'Accept': 'application/json' },
      });

      if (res.ok) {
        showStatus("Message sent. I'll get back to you shortly.", 'success');
        form.reset();
        setTimeout(function () { hideStatus(); resetBtn(btn, originalText); }, 5000);
      } else {
        throw new Error('Server returned ' + res.status);
      }
    } catch (err) {
      console.error('[contact]', err.message);
      showStatus('Submission failed. Email me directly at anfaspulari@gmail.com', 'error');
      setTimeout(function () { hideStatus(); resetBtn(btn, originalText); }, 6000);
    }
  });
}

function resetBtn(btn, text) {
  btn.textContent      = text;
  btn.style.background = '';
  btn.style.color      = '';
  btn.style.opacity    = '';
  btn.disabled         = false;
}

// ─────────────────────────────────────────────────────────────
// RESUME - graceful disable if file missing
// ─────────────────────────────────────────────────────────────

function checkResume() {
  var links = document.querySelectorAll('a[href="resume.pdf"]');
  if (!links.length) return;

  fetch('resume.pdf', { method: 'HEAD' })
    .then(function (res) {
      if (!res.ok) disableResumeLinks(links);
    })
    .catch(function () { disableResumeLinks(links); });
}

function disableResumeLinks(links) {
  links.forEach(function (link) {
    link.removeAttribute('download');
    link.setAttribute('href', '#contact');
    link.title         = 'Resume not yet uploaded - contact me directly';
    link.style.opacity = '0.45';
  });
}

// ─────────────────────────────────────────────────────────────
// COMMAND PALETTE - Cmd+K / Ctrl+K
// Reuses the COMMANDS registry above; does not duplicate it.
// ─────────────────────────────────────────────────────────────

var COMMAND_DESC = {
  whoami:                 'current operator profile',
  help:                   'list available commands',
  skills:                 'list core competencies',
  projects:               'active security projects',
  status:                 'current alert queue',
  'analyze phishing_case':'run a sample SOC analysis',
  clear:                  'clear palette output',
};

function initCommandPalette() {
  var paletteEl = document.getElementById('cmd-palette');
  if (!paletteEl) return;

  var inputEl  = document.getElementById('cmd-palette-input');
  var listEl   = document.getElementById('cmd-palette-list');
  var outputEl = document.getElementById('cmd-palette-output');

  // 'clear' is handled inline in the terminal; surface it here too.
  var commandNames = Object.keys(COMMANDS).concat(['clear']);

  var lastTrigger  = null;
  var activeIndex  = 0;
  var filteredItems = commandNames.slice();

  function isOpen() { return !paletteEl.hasAttribute('hidden'); }

  function open() {
    if (isOpen()) return;
    lastTrigger = document.activeElement;
    paletteEl.removeAttribute('hidden');
    paletteEl.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden';
    inputEl.value = '';
    outputEl.innerHTML = '';
    activeIndex = 0;
    renderList();
    inputEl.focus();
  }

  function close() {
    if (!isOpen()) return;
    paletteEl.setAttribute('hidden', '');
    paletteEl.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = '';
    if (lastTrigger && typeof lastTrigger.focus === 'function') lastTrigger.focus();
  }

  function getMatches(query) {
    var q = (query || '').trim().toLowerCase();
    if (!q) return commandNames.slice();
    return commandNames.filter(function (name) {
      var desc = (COMMAND_DESC[name] || '').toLowerCase();
      return name.indexOf(q) !== -1 || desc.indexOf(q) !== -1;
    });
  }

  function renderList() {
    filteredItems = getMatches(inputEl.value);
    if (activeIndex >= filteredItems.length) activeIndex = Math.max(0, filteredItems.length - 1);

    if (filteredItems.length === 0) {
      listEl.innerHTML = '<li class="cmd-palette-empty">No matching commands.</li>';
      return;
    }

    listEl.innerHTML = filteredItems.map(function (name, i) {
      var desc = COMMAND_DESC[name] || '';
      return '<li role="option" id="cmd-opt-' + i + '" class="cmd-palette-item' +
             (i === activeIndex ? ' is-active' : '') +
             '" data-cmd-idx="' + i + '" aria-selected="' + (i === activeIndex) + '">' +
               '<span class="cmd-palette-name">' + escapeHtml(name) + '</span>' +
               '<span class="cmd-palette-desc">' + escapeHtml(desc) + '</span>' +
             '</li>';
    }).join('');

    if (filteredItems[activeIndex]) {
      inputEl.setAttribute('aria-activedescendant', 'cmd-opt-' + activeIndex);
    }
  }

  function execute(name) {
    if (!name) return;

    if (name === 'clear') { outputEl.innerHTML = ''; return; }

    var handler = COMMANDS[name];
    if (!handler) return;

    outputEl.innerHTML = '';

    var cmdLine = document.createElement('p');
    cmdLine.className = 't-line';
    cmdLine.innerHTML = '<span class="t-prompt">anfas@sec:~$</span> ' + escapeHtml(name);
    outputEl.appendChild(cmdLine);

    handler().forEach(function (line) {
      var el = document.createElement('p');
      el.className = 't-line t-out-' + (line.type || 'out');
      el.textContent = line.text;
      outputEl.appendChild(el);
    });

    outputEl.scrollTop = outputEl.scrollHeight;
  }

  // Global key handler - Cmd/Ctrl+K toggles, Esc closes, arrows navigate.
  document.addEventListener('keydown', function (e) {
    var isCmdK = (e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K');
    if (isCmdK) {
      e.preventDefault();
      if (isOpen()) close(); else open();
      return;
    }

    if (!isOpen()) return;

    if (e.key === 'Escape') { e.preventDefault(); close(); return; }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      if (!filteredItems.length) return;
      activeIndex = (activeIndex + 1) % filteredItems.length;
      renderList();
      return;
    }

    if (e.key === 'ArrowUp') {
      e.preventDefault();
      if (!filteredItems.length) return;
      activeIndex = (activeIndex - 1 + filteredItems.length) % filteredItems.length;
      renderList();
      return;
    }

    if (e.key === 'Enter') {
      e.preventDefault();
      if (filteredItems[activeIndex]) execute(filteredItems[activeIndex]);
      return;
    }

    // Focus trap - bounce Tab back to the only focusable element (the input).
    if (e.key === 'Tab') { e.preventDefault(); inputEl.focus(); }
  });

  inputEl.addEventListener('input', function () {
    activeIndex = 0;
    renderList();
  });

  // Outside-click closes the modal.
  paletteEl.addEventListener('click', function (e) {
    if (e.target.hasAttribute('data-cmd-close')) close();
  });

  // Click on a list item executes it.
  listEl.addEventListener('click', function (e) {
    var item = e.target.closest('.cmd-palette-item');
    if (!item) return;
    var idx = parseInt(item.getAttribute('data-cmd-idx'), 10);
    if (isNaN(idx) || !filteredItems[idx]) return;
    activeIndex = idx;
    renderList();
    execute(filteredItems[idx]);
  });
}

// ─────────────────────────────────────────────────────────────
// CASE STUDY - copy-on-click for .cs-code blocks
// ─────────────────────────────────────────────────────────────

function initCopyOnClick() {
  var blocks = document.querySelectorAll('.cs-code');
  if (!blocks.length) return;

  blocks.forEach(function (block) {
    block.setAttribute('role', 'button');
    block.setAttribute('tabindex', '0');
    block.setAttribute('aria-label', 'Click to copy this code block');

    function copy() {
      var text = block.textContent.replace(/\s+$/, '');
      var done = function () {
        block.classList.add('is-copied');
        setTimeout(function () { block.classList.remove('is-copied'); }, 1400);
      };

      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(function () {/* noop */});
      } else {
        // Fallback for older browsers / non-secure contexts
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); done(); } catch (e) {/* noop */}
        document.body.removeChild(ta);
      }
    }

    block.addEventListener('click', copy);
    block.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); copy(); }
    });
  });
}

// ─────────────────────────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g,  '&amp;')
    .replace(/</g,  '&lt;')
    .replace(/>/g,  '&gt;')
    .replace(/"/g,  '&quot;');
}

// ─────────────────────────────────────────────────────────────
// BOOT - DOMContentLoaded
// ─────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
  var yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();
  initMobileNav();
  initTerminal();
  loadProjects();
  initScrollAnimations();
  initContactForm();
  checkResume();
  initCopyOnClick();
  initCommandPalette();
});
