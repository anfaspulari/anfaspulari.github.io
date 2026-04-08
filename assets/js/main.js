'use strict';

// ─────────────────────────────────────────────────────────────
// TERMINAL — commands registry
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
    var open = Math.floor(Math.random() * 10) + 5;
    return [
      { text: '[ALERT QUEUE STATUS - ' + getTimestamp() + ']', type: 'info' },
      { text: '  Open alerts    : ' + open,                    type: 'out'  },
      { text: '  Priority HIGH  : 2',                          type: 'warn' },
      { text: '  Assigned to me : 3',                          type: 'out'  },
      { text: '  Avg close time : 18 min',                     type: 'out'  },
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
// TERMINAL — init + handlers
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
    console.warn('[portfolio] projects.json unavailable, static fallback active:', err.message);
    // Static HTML cards already in the DOM — no further action needed
  }
}

function renderProjects(grid, projects) {
  grid.innerHTML = projects.map(function (p) {
    var tags = p.stack.map(function (t) {
      return '<span class="project-tag">' + escapeHtml(t) + '</span>';
    }).join('');

    var links = '<a href="' + escapeHtml(p.github) + '" target="_blank" rel="noopener" class="project-link">GitHub</a>';
    if (p.demo) {
      links += ' <span class="project-link-sep">·</span> <a href="' + escapeHtml(p.demo) + '" target="_blank" rel="noopener" class="project-link project-link--demo">Live Demo</a>';
    }

    return (
      '<div class="project-card">' +
        '<div class="project-emoji">'  + p.emoji + '</div>' +
        '<p class="project-title">'    + escapeHtml(p.name)        + '</p>' +
        '<p class="project-origin">'   + escapeHtml(p.origin)      + '</p>' +
        '<p class="project-desc">'     + escapeHtml(p.description) + '</p>' +
        '<div class="project-tags">'   + tags + '</div>' +
        '<div class="project-links">'  + links + '</div>' +
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
    '.training-card, .mindset-card'
  );

  // Stagger siblings within the same grid
  document.querySelectorAll('.skills-grid, .projects-grid, .training-grid, .stats-row, .mindset-cards').forEach(function (grid) {
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
// CONTACT FORM — Formspree AJAX submission
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
// RESUME — graceful disable if file missing
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
// PARTICLE EFFECT — hero background
// ─────────────────────────────────────────────────────────────

function initParticles() {
  var canvas = document.getElementById('particle-canvas');
  if (!canvas || !canvas.getContext) return;

  var ctx   = canvas.getContext('2d');
  var COUNT = 50;
  var particles = [];

  function resize() {
    canvas.width  = canvas.offsetWidth;
    canvas.height = canvas.offsetHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  for (var i = 0; i < COUNT; i++) {
    particles.push({
      x:  Math.random() * canvas.width,
      y:  Math.random() * canvas.height,
      r:  Math.random() * 1.2 + 0.3,
      vy: -(Math.random() * 0.3 + 0.08),
      vx: (Math.random() - 0.5) * 0.12,
      o:  Math.random() * 0.3 + 0.06,
    });
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    particles.forEach(function (p) {
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(0,212,255,' + p.o + ')';
      ctx.fill();

      p.x += p.vx;
      p.y += p.vy;

      if (p.y < -4)               { p.y = canvas.height + 4; p.x = Math.random() * canvas.width; }
      if (p.x < -4)                 p.x = canvas.width + 4;
      if (p.x > canvas.width + 4) p.x = -4;
    });

    requestAnimationFrame(draw);
  }

  draw();
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
// BOOT — DOMContentLoaded
// ─────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
  document.getElementById('year').textContent = new Date().getFullYear();
  initParticles();
  initMobileNav();
  initTerminal();
  loadProjects();
  initScrollAnimations();
  initContactForm();
  checkResume();
});
