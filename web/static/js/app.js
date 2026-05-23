'use strict';

// ── Translations ──────────────────────────────────────────────────────────
const STRINGS = {
  en: {
    'gate.bar':            'honey — access control',
    'gate.subtitle':       'automated honeypot — ssh / telnet',
    'gate.desc':           "Verify you're human to access live attack data.",
    'gate.btn':            '[ ENTER DASHBOARD ]',
    'gate.err.verify':     'Verification failed — please try again.',
    'gate.err.network':    'Network error — please try again.',

    'nav.dashboard':       'Dashboard',
    'nav.wordlists':       'Wordlists',
    'win.all':             'All',

    'card.connections':           'Connections',
    'card.connections.meta':      'distinct attacker sessions',
    'card.auth':                  'Auth Attempts',
    'card.commands':              'Commands Run',
    'card.ips':                   'Unique IPs',
    'card.ips.meta':              'distinct source addresses',
    'card.downloads':             'File Downloads',
    'card.unique_passwords':      'Unique Passwords',
    'card.unique_passwords.meta': 'distinct passwords collected',
    'card.unique_usernames':      'Unique Usernames',
    'card.unique_usernames.meta': 'distinct usernames collected',
    'card.malware_hashes':        'Malware Hashes',
    'card.malware_hashes.meta':   'distinct file hashes collected',
    'card.novel_passwords':       'Novel Passwords',
    'card.novel_passwords.meta':  'not in common lists',

    'section.campaigns':    'Active Campaign Alerts',
    'section.geo':          'Attack Origins',
    'section.new_asns':     'New ASNs This Window',
    'chart.countries':      'Top Countries',
    'chart.asns':           'Top ASNs',
    'th.asn_org':           'Organization',
    'campaign.pattern.novel':       'Novel credentials — possible new tool',
    'campaign.pattern.established': 'Established credentials — known botnet',
    'campaign.act.creds':       'View Credentials',
    'campaign.act.asns':        'View ASN Sources',
    'campaign.act.copy':        'Copy user:pass',
    'campaign.act.copied':      'Copied ✓',
    'campaign.act.copy_fail':   'Copy failed',
    'campaign.detail.creds':    'Credentials driving this campaign',
    'campaign.detail.asns':     'ASN sources driving this campaign',
    'campaign.novel.yes':       'novel',
    'campaign.novel.no':        'seen before',
    'th.novel':                 'Novel?',

    'section.overview':        'Overview',
    'section.timeseries':      'Login Attempts Over Time',
    'section.timing':          'Timing Patterns',
    'section.credentials':     'Top Credentials',
    'section.pairs':           'Top Credential Pairs',
    'section.clients':         'SSH Client Versions',
    'section.downloads':       'Downloads',
    'section.malware_hashes':  'Malware Hashes',
    'section.telnet':            'Telnet Honeypot',
    'section.telnet_timeseries': 'Telnet Auth Over Time',
    'section.telnet_creds':      'Telnet Credentials',
    'section.logs':              'Activity Logs',

    'card.telnet_connections':       'Connections',
    'card.telnet_connections.meta':  'total telnet sessions',
    'card.telnet_ips':               'Unique IPs',
    'card.telnet_ips.meta':          'distinct telnet attacker IPs',
    'card.telnet_auth':              'Auth Attempts',
    'card.telnet_auth.meta':         'telnet login attempts',
    'card.telnet_commands':          'Unique Commands',
    'card.telnet_commands.meta':     'distinct shell inputs',
    'card.telnet_cmd_sessions':      'Sessions w/ Input',
    'card.telnet_cmd_sessions.meta': 'sessions that ran commands',

    'chart.telnet_commands':  'Top Commands',
    'chart.telnet_ips':       'Top Source IPs',
    'chart.telnet_usernames': 'Usernames',
    'chart.telnet_passwords': 'Passwords',

    'th.commands':   'Commands',

    'tab.telnet_sessions': 'Sessions',
    'tab.telnet_auth':     'Auth Log',

    'th.first_seen':   'First Seen',
    'th.downloads':    'Downloads',

    'card.ov_auth.meta': 'ssh + telnet login attempts',

    'chart.by_hour':   'Attacks by Hour of Day',
    'chart.by_dow':    'Attacks by Day of Week',
    'chart.usernames': 'Usernames',
    'chart.passwords': 'Passwords',
    'chart.top_urls':  'Top Download URLs',

    'legend.failed':     'Failed',
    'legend.successful': 'Successful',

    'th.rank':        '#',
    'th.username':    'Username',
    'th.password':    'Password',
    'th.sha256':      'SHA-256',
    'th.attempts':    'Attempts',
    'th.client':      'Client String',
    'th.connections': 'Connections',
    'th.time':        'Time',
    'th.ip':          'IP',
    'th.session':     'Session',
    'th.command':     'Command',
    'th.ok':          'OK',
    'th.url':         'URL',
    'th.sha':         'SHA-256',

    'tab.commands': 'Commands',
    'tab.auth':     'Auth Log',
    'tab.dl':       'Downloads',

    'loading.stats':      'Loading statistics…',
    'loading.stats.spin': 'loading statistics…',
    'loading.wordlists':  'Generating wordlists…',
    'tbl.nodata':         'No data for this window',

    'wl.title':         'Generated Wordlists',
    'wl.desc':          'Ranked by attack frequency — most-seen credentials first. Downloads are gzip-compressed plaintext.',
    'wl.period.daily':   'Daily',
    'wl.period.weekly':  'Weekly',
    'wl.period.monthly': 'Monthly',
    'wl.period.all':     'All Time',
    'wl.usernames':        'Usernames',
    'wl.passwords':        'Passwords',
    'wl.pairs':            'Credential Pairs',
    'wl.novel_passwords':  'Novel Passwords',
    'wl.trending_passwords': 'Trending Passwords',
    'wl.dying_passwords':    'Dying Passwords',
    'wl.entries':       'entries',
    'wl.rules':         'rules',
    'wl.period':        'period',
    'wl.size':          '~size (gz)',
    'wl.size_plain':    'size',
    'wl.hashcat_rules': 'Hashcat Rules',
    'wl.john_rules':    'John Rules',
    'wl.preview':                'preview — top 5 by frequency',
    'wl.preview.pairs':          'preview — top 5 by frequency (user:pass format)',
    'wl.preview.trending_passwords': 'preview — top 5 fastest growing',
    'wl.preview.dying_passwords':    'preview — top 5 fastest declining',
    'wl.preview.novel_passwords': 'preview — top 5 not in common lists',
    'wl.preview.rules':          'preview — top observed mutations',
    'wl.trending_passwords.tip': 'Passwords growing in attack frequency compared to the previous period — sorted by relative growth rate.',
    'wl.dying_passwords.tip':    'Passwords declining in attack frequency compared to the previous period — sorted by absolute drop in usage.',
    'wl.novel_passwords.tip': 'Passwords not found in common reference wordlists — filtered against xato-net 1 M, NCSC 100 k, Pwdb top 1 M, probable top 12 k, and darkweb 2017 top 10 k.',
    'wl.empty':         'no data collected yet',

    'meta.success_pct':  n => `${n}% success rate`,
    'meta.cmd_sessions': n => `${n} sessions with input`,
    'period.nodata':     'no data',

    'dow': ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'],
  },
  pt: {
    'gate.bar':            'honey — controle de acesso',
    'gate.subtitle':       'honeypot automatizado — ssh / telnet',
    'gate.desc':           'Verifique que você é humano para acessar os dados de ataque em tempo real.',
    'gate.btn':            '[ ENTRAR NO PAINEL ]',
    'gate.err.verify':     'Verificação falhou — tente novamente.',
    'gate.err.network':    'Erro de rede — tente novamente.',

    'nav.dashboard':       'Painel',
    'nav.wordlists':       'Wordlists',
    'win.all':             'Tudo',

    'card.connections':           'Conexões',
    'card.connections.meta':      'sessões de atacantes distintos',
    'card.auth':                  'Tentativas de Login',
    'card.commands':              'Comandos Executados',
    'card.ips':                   'IPs Únicos',
    'card.ips.meta':              'endereços de origem distintos',
    'card.downloads':             'Arquivos Baixados',
    'card.unique_passwords':      'Senhas Coletadas',
    'card.unique_passwords.meta': 'senhas distintas coletadas',
    'card.unique_usernames':      'Usuários Coletados',
    'card.unique_usernames.meta': 'usuários distintos coletados',
    'card.malware_hashes':        'Hashes de Malware',
    'card.malware_hashes.meta':   'hashes de arquivos coletados',
    'card.novel_passwords':       'Senhas Novas',
    'card.novel_passwords.meta':  'não estão em listas comuns',

    'section.campaigns':    'Alertas de Campanha Ativa',
    'section.geo':          'Origens dos Ataques',
    'section.new_asns':     'Novos ASNs Neste Período',
    'chart.countries':      'Top Países',
    'chart.asns':           'Top ASNs',
    'th.asn_org':           'Organização',
    'campaign.pattern.novel':       'Credenciais novas — possível nova ferramenta',
    'campaign.pattern.established': 'Credenciais conhecidas — botnet estabelecido',
    'campaign.act.creds':       'Ver Credenciais',
    'campaign.act.asns':        'Ver Origens ASN',
    'campaign.act.copy':        'Copiar user:pass',
    'campaign.act.copied':      'Copiado ✓',
    'campaign.act.copy_fail':   'Falha ao copiar',
    'campaign.detail.creds':    'Credenciais por trás desta campanha',
    'campaign.detail.asns':     'Origens ASN por trás desta campanha',
    'campaign.novel.yes':       'nova',
    'campaign.novel.no':        'já vista',
    'th.novel':                 'Nova?',

    'section.overview':        'Visão Geral',
    'section.timeseries':      'Tentativas de Login ao Longo do Tempo',
    'section.timing':          'Padrões Temporais',
    'section.credentials':     'Credenciais Mais Usadas',
    'section.pairs':           'Pares de Credenciais Mais Usados',
    'section.clients':         'Versões de Cliente SSH',
    'section.downloads':       'Downloads',
    'section.malware_hashes':  'Hashes de Malware',
    'section.telnet':            'Honeypot Telnet',
    'section.telnet_timeseries': 'Autenticação Telnet ao Longo do Tempo',
    'section.telnet_creds':      'Credenciais Telnet',
    'section.logs':              'Registros de Atividade',

    'card.telnet_connections':       'Conexões',
    'card.telnet_connections.meta':  'sessões telnet totais',
    'card.telnet_ips':               'IPs Únicos',
    'card.telnet_ips.meta':          'IPs de atacantes telnet distintos',
    'card.telnet_auth':              'Tentativas de Login',
    'card.telnet_auth.meta':         'tentativas de login telnet',
    'card.telnet_commands':          'Comandos Únicos',
    'card.telnet_commands.meta':     'entradas de shell distintas',
    'card.telnet_cmd_sessions':      'Sessões c/ Input',
    'card.telnet_cmd_sessions.meta': 'sessões que rodaram comandos',

    'chart.telnet_commands':  'Comandos Mais Usados',
    'chart.telnet_ips':       'IPs de Origem',
    'chart.telnet_usernames': 'Usuários',
    'chart.telnet_passwords': 'Senhas',

    'th.commands':   'Comandos',

    'tab.telnet_sessions': 'Sessões',
    'tab.telnet_auth':     'Log de Auth',

    'th.first_seen':   'Primeira Vez',
    'th.downloads':    'Downloads',

    'card.ov_auth.meta': 'tentativas ssh + telnet',

    'chart.by_hour':   'Ataques por Hora do Dia',
    'chart.by_dow':    'Ataques por Dia da Semana',
    'chart.usernames': 'Usuários',
    'chart.passwords': 'Senhas',
    'chart.top_urls':  'URLs Mais Baixadas',

    'legend.failed':     'Falhou',
    'legend.successful': 'Bem-sucedido',

    'th.rank':        '#',
    'th.username':    'Usuário',
    'th.password':    'Senha',
    'th.sha256':      'SHA-256',
    'th.attempts':    'Tentativas',
    'th.client':      'Versão do Cliente',
    'th.connections': 'Conexões',
    'th.time':        'Hora',
    'th.ip':          'IP',
    'th.session':     'Sessão',
    'th.command':     'Comando',
    'th.ok':          'OK',
    'th.url':         'URL',
    'th.sha':         'SHA-256',

    'tab.commands': 'Comandos',
    'tab.auth':     'Log de Auth',
    'tab.dl':       'Downloads',

    'loading.stats':      'Carregando estatísticas…',
    'loading.stats.spin': 'carregando estatísticas…',
    'loading.wordlists':  'Gerando wordlists…',
    'tbl.nodata':         'Sem dados para este período',

    'wl.title':         'Wordlists Geradas',
    'wl.desc':          'Ordenadas por frequência de ataque — credenciais mais vistas primeiro. Os downloads são texto comprimido com gzip.',
    'wl.period.daily':   'Diário',
    'wl.period.weekly':  'Semanal',
    'wl.period.monthly': 'Mensal',
    'wl.period.all':     'Tudo',
    'wl.usernames':        'Usuários',
    'wl.passwords':        'Senhas',
    'wl.pairs':            'Pares de Credenciais',
    'wl.novel_passwords':  'Senhas Novas',
    'wl.trending_passwords': 'Senhas em Alta',
    'wl.dying_passwords':    'Senhas em Queda',
    'wl.entries':       'entradas',
    'wl.rules':         'regras',
    'wl.period':        'período',
    'wl.size':          '~tamanho (gz)',
    'wl.size_plain':    'tamanho',
    'wl.hashcat_rules': 'Regras Hashcat',
    'wl.john_rules':    'Regras John',
    'wl.preview':                'prévia — top 20 por frequência',
    'wl.preview.pairs':          'prévia — top 20 por frequência (formato usuário:senha)',
    'wl.preview.trending_passwords': 'prévia — top 5 crescendo mais rápido',
    'wl.preview.dying_passwords':    'prévia — top 5 declinando mais rápido',
    'wl.preview.novel_passwords': 'prévia — top 5 não estão em listas comuns',
    'wl.preview.rules':          'prévia — mutações mais observadas',
    'wl.trending_passwords.tip': 'Senhas com frequência de ataque crescente em comparação ao período anterior — ordenadas pela taxa de crescimento relativo.',
    'wl.dying_passwords.tip':    'Senhas com frequência de ataque declinante em comparação ao período anterior — ordenadas pela queda absoluta no uso.',
    'wl.novel_passwords.tip': 'Senhas não encontradas em listas de referência comuns — filtradas contra xato-net 1 M, NCSC 100 k, Pwdb top 1 M, probable top 12 k e darkweb 2017 top 10 k.',
    'wl.empty':         'nenhum dado coletado ainda',

    'meta.success_pct':  n => `${n}% taxa de sucesso`,
    'meta.cmd_sessions': n => `${n} sessões com comandos`,
    'period.nodata':     'sem dados',

    'dow': ['Dom','Seg','Ter','Qua','Qui','Sex','Sáb'],
  },
};

let currentLang = localStorage.getItem('lang') || 'en';

function t(key) {
  return (STRINGS[currentLang] || STRINGS.en)[key] ?? STRINGS.en[key] ?? key;
}

function tf(key, val) {
  const v = t(key);
  return typeof v === 'function' ? v(val) : v;
}

function applyLang(lang) {
  currentLang = lang;
  document.documentElement.lang = lang;
  localStorage.setItem('lang', lang);

  document.querySelectorAll('[data-i18n]').forEach(el => {
    const val = t(el.dataset.i18n);
    if (typeof val === 'string') el.textContent = val;
  });

  document.querySelectorAll('[data-i18n-tip]').forEach(el => {
    const val = t(el.dataset.i18nTip);
    if (typeof val === 'string') el.dataset.tip = val;
  });

  document.querySelectorAll('.lang-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.lang === lang);
  });

  // Re-render live data with new language (translated DOW labels, empty states, etc.)
  if (lastData && (!$('page-ssh').hidden || !$('page-telnet').hidden)) {
    destroyCharts();
    renderAll(lastData);
  }
  if (lastWlData && !$('page-wordlists').hidden) {
    renderWordlists(lastWlData);
  }
}

// ── Gruvbox chart palette (bright — readable on light and dark) ───────────
const GBX = {
  red:    '#FB4934',
  green:  '#B8BB26',
  yellow: '#FABD2F',
  blue:   '#83A598',
  purple: '#D3869B',
  aqua:   '#8EC07C',
  orange: '#FE8019',
  gray:   '#A89984',
};

// ── Helpers ───────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

function esc(s) {
  return String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function fmtTime(iso, window) {
  const d = new Date(iso);
  if (window === '1h' || window === '6h' || window === '24h')
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (window === '7d')
    return d.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
  return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
}

function fmtTs(iso) {
  const d = new Date(iso);
  return d.toLocaleString([], {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

function fmtPeriod(oldest, newest) {
  if (!oldest) return t('period.nodata');
  const fmt = iso => new Date(iso).toLocaleDateString([], { month: 'short', day: 'numeric', year: '2-digit' });
  return `${fmt(oldest)} – ${fmt(newest)}`;
}

function fgColor() {
  return document.documentElement.dataset.theme === 'dark' ? '#A89984' : '#665C54';
}

function gridColor() {
  return document.documentElement.dataset.theme === 'dark'
    ? 'rgba(235,219,178,.06)' : 'rgba(60,56,54,.07)';
}

// ── Theme ─────────────────────────────────────────────────────────────────
const root = document.documentElement;
root.dataset.theme = localStorage.getItem('theme') || 'light';
syncThemeIcon(root.dataset.theme);

document.querySelectorAll('.theme-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const next = root.dataset.theme === 'dark' ? 'light' : 'dark';
    root.dataset.theme = next;
    localStorage.setItem('theme', next);
    syncThemeIcon(next);
    Object.values(activeCharts).forEach(c => {
      const s = c.options.scales;
      if (s) Object.values(s).forEach(ax => {
        if (ax.ticks) ax.ticks.color = fgColor();
        if (ax.grid)  ax.grid.color  = gridColor();
      });
      c.update();
    });
  });
});

function syncThemeIcon(t) {
  document.querySelectorAll('.icon-sun').forEach(el => el.style.display = t === 'dark' ? '' : 'none');
  document.querySelectorAll('.icon-moon').forEach(el => el.style.display = t === 'dark' ? 'none' : '');
}

// ── Language switcher ─────────────────────────────────────────────────────
document.querySelectorAll('.lang-tab').forEach(btn => {
  btn.addEventListener('click', () => applyLang(btn.dataset.lang));
});

// Apply stored language on load (after DOM ready, handled below)

// ── reCAPTCHA v3 ──────────────────────────────────────────────────────────
window.onRecaptchaLoad = () => {
  if (!window.__RC_SITE_KEY__) { openDashboard(); return; }
  grecaptcha.ready(() => { $('enter-btn').disabled = false; });
};
// reCAPTCHA (async) may have fired before app.js finished loading — replay now
if (window.__rcFired) window.onRecaptchaLoad();

$('enter-btn').addEventListener('click', async () => {
  $('enter-btn').disabled = true;
  $('gate-error').hidden = true;
  try {
    const token = await grecaptcha.execute(window.__RC_SITE_KEY__, { action: 'enter' });
    const res   = await fetch('/api/verify-captcha', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    const json = await res.json();
    if (json.success) {
      openDashboard();
    } else {
      showGateErr(t('gate.err.verify'));
      $('enter-btn').disabled = false;
    }
  } catch {
    showGateErr(t('gate.err.network'));
    $('enter-btn').disabled = false;
  }
});

function showGateErr(msg) { $('gate-error').textContent = msg; $('gate-error').hidden = false; }

function openDashboard() {
  const gate = $('gate');
  gate.style.transition = 'opacity .45s ease';
  gate.style.opacity = '0';
  setTimeout(() => {
    gate.hidden = true;
    $('app').hidden = false;
    $('app').style.opacity = '0';
    requestAnimationFrame(() => {
      $('app').style.transition = 'opacity .4s ease';
      $('app').style.opacity = '1';
    });
    loadStats();
  }, 450);
}

// ── Page navigation ───────────────────────────────────────────────────────
let wordlistsLoaded = false;
let lastData   = null;
let lastWlData = null;

document.querySelectorAll('.page-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.page-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const page = btn.dataset.page;
    $('page-overview').hidden  = page !== 'overview';
    $('page-ssh').hidden       = page !== 'ssh';
    $('page-telnet').hidden    = page !== 'telnet';
    $('page-wordlists').hidden = page !== 'wordlists';
    $('dashboard-controls').style.display = page === 'wordlists' ? 'none' : 'flex';
    if (page === 'wordlists' && !wordlistsLoaded) loadWordlists();
    if (page === 'telnet' || page === 'overview') requestAnimationFrame(() => Object.values(activeCharts).forEach(c => c.resize()));
  });
});

// ── Window tab selector ───────────────────────────────────────────────────
let currentWindow = '6h';
let activeCharts  = {};

document.querySelectorAll('.win-tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.win-tab').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentWindow = btn.dataset.w;
    loadStats();
  });
});

$('refresh-btn').addEventListener('click', () => loadStats());

// ── Activity log tabs ─────────────────────────────────────────────────────
document.querySelectorAll('.log-tab[data-tab]').forEach(btn => {
  btn.addEventListener('click', () => {
    const section = btn.closest('section');
    section.querySelectorAll('.log-tab').forEach(b => b.classList.remove('active'));
    section.querySelectorAll('.log-panel').forEach(p => p.hidden = true);
    btn.classList.add('active');
    $('tab-' + btn.dataset.tab).hidden = false;
  });
});

// ── Stats fetch ───────────────────────────────────────────────────────────
async function loadStats() {
  $('loading').hidden          = false;
  $('stats-root').hidden       = true;
  $('telnet-loading').hidden   = false;
  $('telnet-root').hidden      = true;
  $('overview-loading').hidden = false;
  $('overview-root').hidden    = true;
  $('loading').innerHTML          = `<div class="spinner"></div><p>${t('loading.stats.spin')}</p>`;
  $('telnet-loading').innerHTML   = `<div class="spinner"></div><p>${t('loading.stats.spin')}</p>`;
  $('overview-loading').innerHTML = `<div class="spinner"></div><p>${t('loading.stats.spin')}</p>`;

  for (;;) {
    try {
      const res  = await fetch(`/api/stats?window=${currentWindow}`);
      if (res.status === 503) {
        await new Promise(r => setTimeout(r, 3000));
        continue;
      }
      if (!res.ok) throw new Error(`server error ${res.status}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      lastData = data;
      destroyCharts();
      renderAll(data);
      $('loading').hidden          = true;
      $('stats-root').hidden       = false;
      $('telnet-loading').hidden   = true;
      $('telnet-root').hidden      = false;
      $('overview-loading').hidden = true;
      $('overview-root').hidden    = false;
      $('last-updated').textContent = new Date().toLocaleTimeString();
      return;
    } catch (err) {
      const msg = `<p style="color:var(--c-red);font-family:'JetBrains Mono',monospace;text-align:center">ERR: ${esc(err.message)}</p>`;
      $('loading').innerHTML          = msg;
      $('telnet-loading').innerHTML   = msg;
      $('overview-loading').innerHTML = msg;
      return;
    }
  }
}

function destroyCharts() {
  Object.values(activeCharts).forEach(c => c.destroy());
  activeCharts = {};
  $('country-panel').classList.remove('open');
}

// ── Dashboard render ──────────────────────────────────────────────────────
function renderAll(d) {
  const { overview } = d;

  // ── Overview (SSH + telnet are already combined in overview.* via cowrie) ──
  counter($('v-ov-unique-passwords'), overview.unique_passwords || 0);
  counter($('v-ov-unique-usernames'), overview.unique_usernames || 0);
  counter($('v-ov-unique-ips'),       overview.unique_ips       || 0);
  counter($('v-ov-auth'),             overview.auth_attempts    || 0);
  counter($('v-ov-downloads'),        overview.downloads        || 0);

  counter($('v-auth'),             overview.auth_attempts);
  counter($('v-commands'),         overview.commands);
  counter($('v-ips'),              overview.unique_ips);
  counter($('v-downloads'),        overview.downloads);
  if (overview.unique_passwords     != null) counter($('v-unique-passwords'),  overview.unique_passwords);
  if (overview.unique_usernames     != null) counter($('v-unique-usernames'),  overview.unique_usernames);
  if (overview.unique_malware_hashes != null) counter($('v-malware-hashes'),    overview.unique_malware_hashes);
  if (overview.novel_passwords       != null) counter($('v-novel-passwords'),   overview.novel_passwords);

  $('m-auth').textContent     = tf('meta.success_pct', overview.success_pct);
  $('m-commands').textContent = tf('meta.cmd_sessions', overview.cmd_sessions);

  if (d.timeseries.length) {
    const labels  = d.timeseries.map(r => fmtTime(r.t, currentWindow));
    activeCharts['ts'] = new Chart($('chart-timeseries'), {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: t('legend.failed'),
            data: d.timeseries.map(r => r.failed),
            borderColor: GBX.red, backgroundColor: GBX.red + '33',
            fill: true, tension: .35, pointRadius: 0, borderWidth: 2,
          },
          {
            label: t('legend.successful'),
            data: d.timeseries.map(r => r.successful),
            borderColor: GBX.green, backgroundColor: GBX.green + '33',
            fill: true, tension: .35, pointRadius: 0, borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: fgColor(), maxTicksLimit: 8 }, grid: { color: gridColor() } },
          y: { ticks: { color: fgColor(), stepSize: 1 },      grid: { color: gridColor() }, beginAtZero: true },
        },
      },
    });
  }

  {
    const hourCounts = new Array(24).fill(0);
    d.by_hour.forEach(r => { hourCounts[r.h] = Number(r.attempts); });
    const hourTotal = hourCounts.reduce((a, b) => a + b, 0);
    activeCharts['hour'] = areaChart(
      'chart-hour',
      hourCounts.map((_, h) => String(h).padStart(2, '0') + ':00'),
      hourCounts,
      '--c-blue',
      h => openTimePanel('hour', h, hourCounts[h], hourTotal, d),
    );
  }

  {
    const showDow = ['7d', '30d', 'all'].includes(currentWindow);
    $('card-dow').hidden = !showDow;
    if (showDow) {
      const dowLabels = t('dow');
      const dowCounts = new Array(7).fill(0);
      d.by_dow.forEach(r => { dowCounts[r.dow] = Number(r.attempts); });
      const dowTotal = dowCounts.reduce((a, b) => a + b, 0);
      activeCharts['dow'] = areaChart(
        'chart-dow',
        dowLabels,
        dowCounts,
        '--c-orange',
        i => openTimePanel('dow', i, dowCounts[i], dowTotal, d),
      );
    }
  }

  renderHBar('chart-usernames', d.top_usernames.map(r => ({
    label: r.username, value: Number(r.attempts),
  })), 'var(--c-aqua)');

  renderHBar('chart-passwords', d.top_passwords.map(r => ({
    label: r.password, value: Number(r.attempts),
  })), 'var(--c-purple)');

  if (d.top_urls.length) {
    renderHBar('chart-urls', d.top_urls.map(r => ({
      label: r.url.replace(/^https?:\/\//, '').substring(0, 50),
      value: Number(r.downloads),
    })), 'var(--c-yellow)');
  }

  fillTable('tbl-pairs', d.top_pairs, r =>
    `<td class="rank">${r._rank}</td>
     <td class="mono">${esc(r.username)}</td>
     <td class="mono">${esc(r.password)}</td>
     <td class="num mono">${r.attempts}</td>`
  );

  fillTable('tbl-clients', d.ssh_clients, r =>
    `<td class="rank">${r._rank}</td>
     <td class="mono truncate">${esc(r.client_version)}</td>
     <td class="num mono">${r.connections}</td>`
  );

  fillTable('tbl-commands', d.cmd_log, r =>
    `<td class="mono">${fmtTs(r.time)}</td>
     <td class="mono">${esc(r.ip)}</td>
     <td class="mono">${esc(r.session)}</td>
     <td class="mono truncate">${esc(r.input)}</td>`
  );

  fillTable('tbl-auth', d.auth_log, r =>
    `<td class="mono">${fmtTs(r.time)}</td>
     <td class="mono">${esc(r.ip)}</td>
     <td class="mono">${esc(r.username)}</td>
     <td class="mono">${esc(r.password)}</td>
     <td class="mono ${r.success ? 'badge-ok' : 'badge-fail'}">${r.success ? '✓' : '✗'}</td>`
  );

  fillTable('tbl-dl', d.dl_log, r =>
    `<td class="mono">${fmtTs(r.time)}</td>
     <td class="mono">${esc(r.ip)}</td>
     <td class="mono truncate">${esc(r.url)}</td>
     <td class="mono">${r.shasum ? `<span title="${esc(r.shasum)}">${esc(r.shasum.substring(0,14))}…</span>` : '<span style="color:var(--fg-dim)">—</span>'}</td>`
  );

  $('section-downloads').hidden = !d.dl_log.length && !d.top_urls.length;

  const mhd = d.malware_hashes_detail || [];
  fillTable('tbl-malware-hashes', mhd, r =>
    `<td class="rank">${r._rank}</td>
     <td class="mono truncate" title="${esc(r.shasum)}">${esc(r.shasum.substring(0, 16))}…</td>
     <td class="mono truncate">${esc(r.url || '—')}</td>
     <td class="num mono">${r.downloads}</td>
     <td class="mono">${fmtTs(r.first_seen)}</td>`
  );

  // ── Telnet honeypot ───────────────────────────────────────────────────────
  const telnet = d.telnet || {};
  const tov    = telnet.overview || {};

  if (tov.connections      != null) counter($('v-telnet-connections'),      tov.connections);
  if (tov.unique_ips       != null) counter($('v-telnet-ips'),              tov.unique_ips);
  if (tov.auth_attempts    != null) counter($('v-telnet-auth'),             tov.auth_attempts);
  if (tov.unique_commands  != null) counter($('v-telnet-commands'),         tov.unique_commands);
  if (tov.cmd_sessions     != null) counter($('v-telnet-cmd-sessions'),     tov.cmd_sessions);
  if (tov.unique_passwords != null) counter($('v-telnet-unique-passwords'), tov.unique_passwords);
  if (tov.unique_usernames != null) counter($('v-telnet-unique-usernames'), tov.unique_usernames);

  if (telnet.timeseries && telnet.timeseries.length) {
    const labels = telnet.timeseries.map(r => fmtTime(r.t, currentWindow));
    activeCharts['telnet-ts'] = new Chart($('chart-telnet-timeseries'), {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: t('legend.failed'),
            data: telnet.timeseries.map(r => r.failed),
            borderColor: GBX.red, backgroundColor: GBX.red + '33',
            fill: true, tension: .35, pointRadius: 0, borderWidth: 2,
          },
          {
            label: t('legend.successful'),
            data: telnet.timeseries.map(r => r.successful),
            borderColor: GBX.green, backgroundColor: GBX.green + '33',
            fill: true, tension: .35, pointRadius: 0, borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        interaction: { mode: 'index', intersect: false },
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: fgColor(), maxTicksLimit: 8 }, grid: { color: gridColor() } },
          y: { ticks: { color: fgColor(), stepSize: 1 },      grid: { color: gridColor() }, beginAtZero: true },
        },
      },
    });
  }

  renderHBar('chart-telnet-commands', (telnet.top_commands || []).map(r => ({
    label: r.command, value: Number(r.attempts),
  })), 'var(--c-blue)');

  renderHBar('chart-telnet-ips', (telnet.top_ips || []).map(r => ({
    label: r.ip, value: Number(r.connections),
  })), 'var(--c-orange)');

  const telnetHasCreds = (telnet.top_usernames && telnet.top_usernames.length) ||
                         (telnet.top_passwords && telnet.top_passwords.length);
  $('section-telnet-creds').hidden = !telnetHasCreds;

  renderHBar('chart-telnet-usernames', (telnet.top_usernames || []).map(r => ({
    label: r.username, value: Number(r.attempts),
  })), 'var(--c-aqua)');

  renderHBar('chart-telnet-passwords', (telnet.top_passwords || []).map(r => ({
    label: r.password, value: Number(r.attempts),
  })), 'var(--c-purple)');

  fillTable('tbl-telnet-sessions', telnet.session_log || [], r =>
    `<td class="mono">${fmtTs(r.time)}</td>
     <td class="mono">${esc(r.ip)}</td>
     <td class="mono">${esc(r.session)}</td>
     <td class="num mono">${r.commands}</td>`
  );

  fillTable('tbl-telnet-auth', telnet.auth_log || [], r =>
    `<td class="mono">${fmtTs(r.time)}</td>
     <td class="mono">${esc(r.ip)}</td>
     <td class="mono">${esc(r.username)}</td>
     <td class="mono">${esc(r.password)}</td>
     <td class="mono ${r.success ? 'badge-ok' : 'badge-fail'}">${r.success ? '✓' : '✗'}</td>`
  );

  // ── Geo / ASN ─────────────────────────────────────────────────────────────
  const geo = d.geo || {};
  const hasGeo = (geo.top_countries && geo.top_countries.length) ||
                 (geo.top_asns && geo.top_asns.length);
  $('section-geo').hidden = !hasGeo;

  if (geo.top_countries && geo.top_countries.length) {
    choroplethChart('chart-countries', geo.top_countries, geo.country_asns || {}).then(chart => {
      activeCharts['geo-countries'] = chart;
    });
  }

  renderHBar('chart-asns', (geo.top_asns || []).map(r => ({
    label: r.asn_org || `AS${r.asn}`,
    value: r.sessions,
    href:  `https://bgp.he.net/AS${r.asn}`,
  })), 'var(--c-orange)');

  const newAsns = geo.new_asns || [];
  $('section-new-asns').hidden = !newAsns.length;
  fillTable('tbl-new-asns', newAsns, r =>
    `<td class="rank">${r._rank}</td>
     <td class="mono">AS${r.asn}</td>
     <td class="mono truncate">${esc(r.asn_org || '—')}</td>
     <td class="mono">${fmtTs(r.first_seen)}</td>
     <td class="num mono">${Number(r.attempts).toLocaleString()}</td>`
  );

  // ── Campaign alerts ───────────────────────────────────────────────────────
  const campaigns = d.campaigns || [];
  $('section-campaigns').hidden = !campaigns.length;

  if (campaigns.length) {
    $('campaign-alerts-list').innerHTML = campaigns.map(c => {
      const isNovel      = c.credential_pattern === 'novel';
      const patternLabel = t(isNovel ? 'campaign.pattern.novel' : 'campaign.pattern.established');

      const asnRows = (c.new_asns || []).map(a =>
        `<tr>
          <td class="mono"><a href="https://bgp.he.net/AS${a.asn}" target="_blank" rel="noopener">AS${a.asn}</a></td>
          <td class="mono truncate">${esc(a.asn_org || '—')}</td>
          <td class="num mono">${Number(a.attempts).toLocaleString()}</td>
        </tr>`
      ).join('');

      const pairRows = (c.top_pairs || []).map(p =>
        `<tr>
          <td class="mono">${esc(p.username)}</td>
          <td class="mono">${esc(p.password)}</td>
          <td class="num mono">${Number(p.attempts).toLocaleString()}</td>
          <td class="mono ${p.novel ? 'badge-ok' : 'badge-fail'}">${p.novel ? t('campaign.novel.yes') : t('campaign.novel.no')}</td>
        </tr>`
      ).join('');

      return `
        <div class="campaign-card" data-campaign-id="${c.id}">
          <div class="campaign-header">
            <span class="campaign-label">CAMPAIGN #${c.id}</span>
            <span class="campaign-badge ${isNovel ? 'badge-campaign-novel' : 'badge-campaign-established'}">${esc(patternLabel)}</span>
          </div>
          <div class="campaign-stats">
            <div class="campaign-stat">
              <span class="campaign-stat-label">Onset</span>
              <span class="campaign-stat-val mono">${fmtTs(c.onset_time)}</span>
            </div>
            <div class="campaign-stat">
              <span class="campaign-stat-label">Z-Score</span>
              <span class="campaign-stat-val mono" style="color:var(--c-red)">${c.z_score.toFixed(2)}</span>
            </div>
            <div class="campaign-stat">
              <span class="campaign-stat-label">Peak/hr</span>
              <span class="campaign-stat-val mono">${Math.round(c.peak_rate_per_hour).toLocaleString()}</span>
            </div>
            <div class="campaign-stat">
              <span class="campaign-stat-label">Baseline/hr</span>
              <span class="campaign-stat-val mono">${Math.round(c.baseline_rate_per_hour).toLocaleString()}</span>
            </div>
            <div class="campaign-stat">
              <span class="campaign-stat-label">New ASNs</span>
              <span class="campaign-stat-val mono">${c.new_asn_count}</span>
            </div>
            <div class="campaign-stat">
              <span class="campaign-stat-label">New-ASN Traffic</span>
              <span class="campaign-stat-val mono">${Math.round(c.spike_ratio * 100)}%</span>
            </div>
          </div>

          <div class="campaign-actions">
            ${pairRows ? `<button class="campaign-action-btn" data-act="creds">${t('campaign.act.creds')}</button>` : ''}
            ${asnRows ? `<button class="campaign-action-btn" data-act="asns">${t('campaign.act.asns')}</button>` : ''}
            ${pairRows ? `<button class="campaign-action-btn" data-act="copy">${t('campaign.act.copy')}</button>` : ''}
          </div>

          ${pairRows ? `
          <div class="campaign-detail" data-detail="creds">
            <h4 class="campaign-detail-title">${t('campaign.detail.creds')}</h4>
            <table class="data-tbl">
              <thead><tr>
                <th data-i18n="th.username">Username</th>
                <th data-i18n="th.password">Password</th>
                <th data-i18n="th.attempts">Attempts</th>
                <th>${t('th.novel')}</th>
              </tr></thead>
              <tbody>${pairRows}</tbody>
            </table>
          </div>` : ''}

          ${asnRows ? `
          <div class="campaign-detail" data-detail="asns">
            <h4 class="campaign-detail-title">${t('campaign.detail.asns')}</h4>
            <table class="data-tbl">
              <thead><tr>
                <th>ASN</th>
                <th data-i18n="th.asn_org">Organization</th>
                <th data-i18n="th.attempts">Attempts</th>
              </tr></thead>
              <tbody>${asnRows}</tbody>
            </table>
          </div>` : ''}
        </div>`;
    }).join('');

    bindCampaignActions(campaigns);
  }
}

function bindCampaignActions(campaigns) {
  const byId = {};
  campaigns.forEach(c => { byId[c.id] = c; });

  document.querySelectorAll('.campaign-card').forEach(card => {
    const id = Number(card.dataset.campaignId);
    const c  = byId[id];

    const details = card.querySelectorAll('.campaign-detail');
    const buttons = card.querySelectorAll('.campaign-action-btn[data-act]');

    const showOnly = which => {
      details.forEach(d => d.hidden = d.dataset.detail !== which);
      buttons.forEach(b => b.classList.toggle('active', b.dataset.act === which));
    };

    const firstWithData = card.querySelector('.campaign-detail');
    if (firstWithData) showOnly(firstWithData.dataset.detail);

    card.querySelector('[data-act="creds"]')?.addEventListener('click', () => showOnly('creds'));
    card.querySelector('[data-act="asns"]') ?.addEventListener('click', () => showOnly('asns'));

    const copyBtn = card.querySelector('[data-act="copy"]');
    copyBtn?.addEventListener('click', async () => {
      const lines = (c.top_pairs || []).map(p => `${p.username}:${p.password}`).join('\n');
      try {
        await navigator.clipboard.writeText(lines);
        copyBtn.textContent = t('campaign.act.copied');
        setTimeout(() => { copyBtn.textContent = t('campaign.act.copy'); }, 1500);
      } catch {
        copyBtn.textContent = t('campaign.act.copy_fail');
        setTimeout(() => { copyBtn.textContent = t('campaign.act.copy'); }, 1500);
      }
    });
  });
}

// ── Wordlists ─────────────────────────────────────────────────────────────
let currentPeriod = 'daily';

document.querySelectorAll('[data-period]').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('[data-period]').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentPeriod = btn.dataset.period;
    loadWordlists();
  });
});

async function loadWordlists() {
  $('wl-loading').hidden = false;
  $('wl-root').hidden    = true;
  $('wl-loading').innerHTML = `<div class="spinner"></div><p>${t('loading.wordlists')}</p>`;

  try {
    const res  = await fetch(`/api/wordlist?period=${currentPeriod}`);
    if (!res.ok) throw new Error(`server error ${res.status}`);
    const data = await res.json();
    if (data.error) throw new Error(data.error);
    lastWlData      = data;
    wordlistsLoaded = true;
    renderWordlists(data);
    $('wl-loading').hidden = true;
    $('wl-root').hidden    = false;
  } catch (err) {
    $('wl-loading').innerHTML =
      `<p style="color:var(--c-red);font-family:'JetBrains Mono',monospace;text-align:center;line-height:1.8">
        ERR: ${esc(err.message)}
      </p>`;
  }
}

const RULE_WTYPES = new Set(['hashcat_rules', 'john_rules']);

function renderWordlists(data) {
  for (const [wtype, info] of Object.entries(data)) {
    const countEl  = $(`wl-count-${wtype}`);
    const sizeEl   = $(`wl-size-${wtype}`);
    const listEl   = $(`wl-preview-${wtype}`);
    if (!countEl) continue;

    const isRule = RULE_WTYPES.has(wtype);

    countEl.textContent = info.total ? info.total.toLocaleString() : '0';
    if (sizeEl) sizeEl.textContent = isRule ? (info.size || '—') : (info.gz_size || '—');

    if (!isRule) {
      const periodEl = $(`wl-period-${wtype}`);
      if (periodEl) {
        periodEl.textContent = info.oldest
          ? fmtPeriod(info.oldest, info.newest)
          : (info.ready ? t(`wl.period.${data.period}`) : t('period.nodata'));
      }
    }

    if (listEl) {
      listEl.innerHTML = (!info.preview || !info.preview.length)
        ? `<div class="wl-empty">${t('wl.empty')}</div>`
        : info.preview.map(v => `<div class="wl-preview-entry">${esc(v)}</div>`).join('');
    }
  }
}

document.addEventListener('click', e => {
  const btn = e.target.closest('.btn-download');
  if (!btn) return;
  const wtype = btn.dataset.wtype;
  if (!wtype) return;
  btn.disabled = true;
  const a = document.createElement('a');
  a.href = `/api/wordlist/${wtype}/download?period=${currentPeriod}`;
  a.download = `honey_${currentPeriod}_${wtype}.txt.gz`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => { btn.disabled = false; }, 2000);
});

// ── Counter animation ─────────────────────────────────────────────────────
function counter(el, target) {
  if (!el) return;
  if (!Number.isFinite(target) || target === 0) { el.textContent = target; return; }
  const step = Math.max(1, Math.ceil(target / (1100 / 16)));
  let cur = 0;
  const tick = () => {
    cur = Math.min(cur + step, target);
    el.textContent = cur.toLocaleString();
    if (cur < target) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

// ── Choropleth world map ──────────────────────────────────────────────────
let _worldAtlas = null;
async function _fetchWorldAtlas() {
  if (!_worldAtlas) {
    const res = await fetch('https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json');
    _worldAtlas = await res.json();
  }
  return _worldAtlas;
}

// ISO 3166-1 alpha-2 → numeric
const ISO2_NUM = {
  AF:4,AX:248,AL:8,DZ:12,AS:16,AD:20,AO:24,AI:660,AG:28,AR:32,AM:51,AW:533,
  AU:36,AT:40,AZ:31,BS:44,BH:48,BD:50,BB:52,BY:112,BE:56,BZ:84,BJ:204,BM:60,
  BT:64,BO:68,BQ:535,BA:70,BW:72,BR:76,IO:86,VG:92,BN:96,BG:100,BF:854,BI:108,
  CV:132,KH:116,CM:120,CA:124,KY:136,CF:140,TD:148,CL:152,CN:156,HK:344,MO:446,
  CX:162,CC:166,CO:170,KM:174,CG:178,CD:180,CK:184,CR:188,HR:191,CU:192,CW:531,
  CY:196,CZ:203,CI:384,DK:208,DJ:262,DM:212,DO:214,EC:218,EG:818,SV:222,GQ:226,
  ER:232,EE:233,SZ:748,ET:231,FK:238,FO:234,FJ:242,FI:246,FR:250,GF:254,PF:258,
  TF:260,GA:266,GM:270,GE:268,DE:276,GH:288,GI:292,GR:300,GL:304,GD:308,GP:312,
  GU:316,GT:320,GG:831,GN:324,GW:624,GY:328,HT:332,HM:334,VA:336,HN:340,HU:348,
  IS:352,IN:356,ID:360,IR:364,IQ:368,IE:372,IM:833,IL:376,IT:380,JM:388,JP:392,
  JE:832,JO:400,KZ:398,KE:404,KI:296,KP:408,KR:410,KW:414,KG:417,LA:418,LV:428,
  LB:422,LS:426,LR:430,LY:434,LI:438,LT:440,LU:442,MG:450,MW:454,MY:458,MV:462,
  ML:466,MT:470,MH:584,MQ:474,MR:478,MU:480,YT:175,MX:484,FM:583,MD:498,MC:492,
  MN:496,ME:499,MS:500,MA:504,MZ:508,MM:104,NA:516,NR:520,NP:524,NL:528,NC:540,
  NZ:554,NI:558,NE:562,NG:566,NU:570,NF:574,MK:807,MP:580,NO:578,OM:512,PK:586,
  PW:585,PS:275,PA:591,PG:598,PY:600,PE:604,PH:608,PN:612,PL:616,PT:620,PR:630,
  QA:634,RE:638,RO:642,RU:643,RW:646,BL:652,SH:654,KN:659,LC:662,MF:663,PM:666,
  VC:670,WS:882,SM:674,ST:678,SA:682,SN:686,RS:688,SC:690,SL:694,SG:702,SX:534,
  SK:703,SI:705,SB:90,SO:706,ZA:710,GS:239,SS:728,ES:724,LK:144,SD:729,SR:740,
  SJ:744,SE:752,CH:756,SY:760,TW:158,TJ:762,TZ:834,TH:764,TL:626,TG:768,TK:772,
  TO:776,TT:780,TN:788,TR:792,TM:795,TC:796,TV:798,UM:581,VI:850,UG:800,UA:804,
  AE:784,GB:826,US:840,UY:858,UZ:860,VU:548,VE:862,VN:704,WF:876,EH:732,YE:887,
  ZM:894,ZW:716,XK:383,KP:408,SS:728,
};

// Reverse map: numeric id → ISO alpha-2
const NUM_ISO = Object.fromEntries(Object.entries(ISO2_NUM).map(([k, v]) => [v, k]));

function countryFlag(iso2) {
  return [...iso2.toUpperCase()].map(c =>
    String.fromCodePoint(0x1F1E6 + c.charCodeAt(0) - 65)
  ).join('');
}

function openCountryPanel(name, iso2, sessions, rank, totalSessions, asns) {
  $('time-panel').classList.remove('open');
  document.querySelectorAll('.vbar-col.active').forEach(c => c.classList.remove('active'));
  const panel = $('country-panel');
  $('cp-flag').textContent = iso2 ? countryFlag(iso2) : '🌍';
  $('cp-name').textContent = name;

  const hasData = sessions > 0;
  $('cp-data').hidden   = !hasData;
  $('cp-nodata').hidden =  hasData;

  if (hasData) {
    $('cp-sessions').textContent = sessions.toLocaleString();
    $('cp-share').textContent    = totalSessions
      ? (sessions / totalSessions * 100).toFixed(1) + '%'
      : '—';
    $('cp-rank').textContent = '#' + rank;
    requestAnimationFrame(() => {
      $('cp-bar').style.width = (sessions / totalSessions * 100).toFixed(1) + '%';
    });

    const asnEl = $('cp-asns');
    if (asns && asns.length) {
      asnEl.innerHTML = asns.map(a =>
        `<div class="cp-asn-row">
          <a class="cp-asn-num" href="https://bgp.he.net/AS${a.asn}" target="_blank" rel="noopener">AS${a.asn}</a>
          <span class="cp-asn-org">${esc(a.asn_org || '—')}</span>
          <span class="cp-asn-sessions">${a.sessions.toLocaleString()}</span>
        </div>`
      ).join('');
      asnEl.hidden = false;
      $('cp-asns-heading').hidden = false;
    } else {
      asnEl.hidden = true;
      $('cp-asns-heading').hidden = true;
    }
  }
  panel.classList.add('open');
}

$('cp-close').addEventListener('click', () => $('country-panel').classList.remove('open'));

async function choroplethChart(canvasId, countryData, countryAsns) {
  const existing = Chart.getChart(canvasId);
  if (existing) existing.destroy();

  const topology = await _fetchWorldAtlas();
  const features = topojson.feature(topology, topology.objects.countries).features;

  const byNum = {};
  for (const r of countryData) {
    const n = ISO2_NUM[r.country_iso];
    if (n) byNum[n] = r.sessions;
  }
  const maxVal = Math.max(...Object.values(byNum), 1);
  const totalSessions = Object.values(byNum).reduce((a, b) => a + b, 0);

  // Pre-sorted rank lookup: iso2 → rank
  const rankByIso = {};
  [...countryData].sort((a, b) => b.sessions - a.sessions)
    .forEach((r, i) => { rankByIso[r.country_iso] = i + 1; });

  const dark = document.documentElement.dataset.theme === 'dark';

  // Gruvbox yellow → orange → red, two-segment gradient
  const STOPS = dark
    ? [[0xFA,0xBD,0x2F],[0xFE,0x80,0x19],[0xFB,0x49,0x34]]
    : [[0xB5,0x76,0x14],[0xAF,0x3A,0x03],[0x9D,0x00,0x06]];

  function heatColor(v) {
    if (!v) return dark ? '#1d2021' : '#ddd8c4';
    const t   = Math.sqrt(v / maxVal);           // sqrt scale — small values still show
    const seg = Math.min(Math.floor(t * 2), 1);  // 0 or 1
    const f   = t * 2 - seg;
    const lo  = STOPS[seg], hi = STOPS[seg + 1];
    return `rgb(${Math.round(lo[0]+f*(hi[0]-lo[0]))},${Math.round(lo[1]+f*(hi[1]-lo[1]))},${Math.round(lo[2]+f*(hi[2]-lo[2]))})`;
  }

  // Gradient legend strip
  const legendEl = $('countries-legend');
  if (legendEl) {
    const grad = dark
      ? 'linear-gradient(to right,#FABD2F,#FE8019,#FB4934)'
      : 'linear-gradient(to right,#B57614,#AF3A03,#9D0006)';
    legendEl.innerHTML =
      `<span>0</span>` +
      `<div style="flex:1;height:6px;background:${grad};border-radius:3px;opacity:.85"></div>` +
      `<span>${maxVal.toLocaleString()}</span>`;
  }

  return new Chart($(canvasId), {
    type: 'choropleth',
    data: {
      labels: features.map(f => f.properties.name),
      datasets: [{
        data: features.map(f => ({ feature: f, value: byNum[+f.id] ?? 0 })),
        backgroundColor(ctx) {
          return heatColor(ctx.dataset.data[ctx.dataIndex]?.value ?? 0);
        },
        borderColor: dark ? '#3a3a3a' : '#b8b0a0',
        borderWidth: 0.6,
        hoverBorderColor: dark ? '#FABD2F' : '#B57614',
        hoverBorderWidth: 1.2,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      onClick(evt, elements) {
        if (!elements.length) return;
        const dp  = elements[0].element.$context.raw;
        const feature = dp?.feature;
        if (!feature) return;
        const numId = +feature.id;
        const iso2  = NUM_ISO[numId] ?? null;
        const sessions = byNum[numId] ?? 0;
        const rank     = iso2 ? (rankByIso[iso2] ?? '—') : '—';
        const asns     = iso2 ? (countryAsns[iso2] || []) : [];
        openCountryPanel(feature.properties.name, iso2, sessions, rank, totalSessions, asns);
      },
      onHover(evt, elements) {
        const canvas = evt.native?.target;
        if (canvas) canvas.style.cursor = elements.length ? 'pointer' : 'default';
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: dark ? '#3C3836' : '#F2E5BC',
          borderColor:      dark ? '#665C54' : '#D5C4A1',
          borderWidth: 1,
          titleColor: dark ? '#EBDBB2' : '#3C3836',
          bodyColor:  dark ? '#A89984' : '#665C54',
          titleFont:  { family: "'JetBrains Mono', monospace", size: 11, weight: '700' },
          bodyFont:   { family: "'JetBrains Mono', monospace", size: 11 },
          padding: 10,
          callbacks: {
            title(items) {
              const f = items[0]?.dataset.data[items[0].dataIndex]?.feature;
              return f?.properties?.name ?? '';
            },
            label(ctx) {
              const v = ctx.dataset.data[ctx.dataIndex]?.value;
              return v ? `  ${v.toLocaleString()} sessions` : '  no data';
            },
          },
        },
      },
      scales: {
        projection: { type: 'projection', axis: 'x', projection: 'equalEarth', position: 'chartArea', display: false },
        color:      { type: 'color',      axis: 'x', display: false },
      },
    },
  });
}

// ── Area chart (filled line — same style as timeseries) ──────────────────
function getCSSVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function areaChart(canvasId, labels, data, cssVar, onClickCb) {
  const color = getCSSVar(cssVar);
  return new Chart($(canvasId), {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        data,
        backgroundColor: color + '28',
        borderColor: color,
        borderWidth: 2,
        borderRadius: 0,
        borderSkipped: 'bottom',
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: { legend: { display: false } },
      onClick: onClickCb ? (evt, elements) => {
        if (elements.length) onClickCb(elements[0].index);
      } : undefined,
      onHover: onClickCb ? (evt, elements) => {
        if (evt.native?.target) evt.native.target.style.cursor = elements.length ? 'pointer' : 'default';
      } : undefined,
      scales: {
        x: { ticks: { color: fgColor(), maxRotation: 0 }, grid: { color: gridColor() } },
        y: { ticks: { color: fgColor() }, grid: { color: gridColor() }, beginAtZero: true },
      },
    },
  });
}

// ── HTML bar charts ───────────────────────────────────────────────────────
function renderHBar(id, rows, color) {
  const el = $(id);
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = `<div class="bar-empty">${t('tbl.nodata')}</div>`;
    return;
  }
  const max = Math.max(...rows.map(r => r.value), 1);
  el.className = 'hbar-chart';
  el.innerHTML = rows.map((r, i) => {
    const pct = (r.value / max * 100).toFixed(2);
    const labelHtml = r.href
      ? `<a class="hbar-label hbar-link" href="${esc(r.href)}" target="_blank" rel="noopener">${esc(r.label)}</a>`
      : `<span class="hbar-label">${esc(r.label)}</span>`;
    return `<div class="hbar-row${r.onClick ? ' hbar-clickable' : ''}" data-i="${i}" data-pct="${pct}" style="--hbar-clr:${color}">
      <div class="hbar-label-col">${labelHtml}</div>
      <div class="hbar-track"><div class="hbar-fill"></div></div>
      <div class="hbar-val">${Number(r.value).toLocaleString()}</div>
    </div>`;
  }).join('');
  requestAnimationFrame(() =>
    el.querySelectorAll('.hbar-row').forEach(row =>
      row.querySelector('.hbar-fill').style.width = row.dataset.pct + '%'
    )
  );
  rows.forEach((r, i) => {
    if (!r.onClick) return;
    el.querySelector(`.hbar-row[data-i="${i}"]`)?.addEventListener('click', r.onClick);
  });
}

function renderVBar(id, rows, color) {
  const el = $(id);
  if (!el) return;
  if (!rows.length) {
    el.innerHTML = `<div class="bar-empty">${t('tbl.nodata')}</div>`;
    return;
  }
  const max = Math.max(...rows.map(r => r.value), 1);
  el.className = 'vbar-chart';
  el.innerHTML = rows.map((r, i) =>
    `<div class="vbar-col${r.onClick ? ' vbar-clickable' : ''}" data-i="${i}" data-pct="${(r.value / max * 100).toFixed(2)}" style="--vbar-clr:${color}" title="${Number(r.value).toLocaleString()} attempts">
      <div class="vbar-track"><div class="vbar-fill"></div></div>
      <div class="vbar-label">${esc(r.label)}</div>
    </div>`
  ).join('');
  requestAnimationFrame(() =>
    el.querySelectorAll('.vbar-col').forEach(col =>
      col.querySelector('.vbar-fill').style.height = col.dataset.pct + '%'
    )
  );
  rows.forEach((r, i) => {
    if (!r.onClick) return;
    const col = el.querySelector(`.vbar-col[data-i="${i}"]`);
    if (!col) return;
    col.addEventListener('click', () => {
      el.querySelectorAll('.vbar-col').forEach(c => c.classList.remove('active'));
      col.classList.add('active');
      r.onClick();
    });
  });
}

// ── Time detail panel ─────────────────────────────────────────────────────
function openTimePanel(type, idx, count, total, data) {
  $('country-panel').classList.remove('open');
  const dowLabels = t('dow');
  $('tp-label').textContent = type === 'hour'
    ? `${String(idx).padStart(2, '0')}:00 – ${String(idx).padStart(2, '0')}:59 UTC`
    : dowLabels[idx];
  $('tp-count').textContent = count.toLocaleString();
  $('tp-pct').textContent   = total ? (count / total * 100).toFixed(1) + '%' : '—';

  const match = type === 'hour'
    ? r => new Date(r.time).getUTCHours() === idx
    : r => new Date(r.time).getUTCDay()   === idx;

  const authRows = (data.auth_log || []).filter(match).slice(0, 15);
  $('tp-auth').innerHTML = authRows.length
    ? authRows.map(r =>
        `<div class="tp-row">
          <span class="tp-ip">${esc(r.ip)}</span>
          <span class="tp-cred">${esc(r.username)}/<wbr>${esc(r.password)}</span>
          <span class="${r.success ? 'badge-ok' : 'badge-fail'}">${r.success ? '✓' : '✗'}</span>
        </div>`).join('')
    : `<div class="tp-empty">no log entries in this ${type === 'hour' ? 'hour' : 'day'}</div>`;

  const cmdRows = (data.cmd_log || []).filter(match).slice(0, 10);
  const cmdSection = $('tp-cmd-section');
  cmdSection.hidden = !cmdRows.length;
  if (cmdRows.length) {
    $('tp-cmd').innerHTML = cmdRows.map(r =>
      `<div class="tp-row">
        <span class="tp-ip">${esc(r.ip)}</span>
        <span class="tp-cred">${esc(r.input)}</span>
      </div>`).join('');
  }
  $('time-panel').classList.add('open');
}

$('tp-close').addEventListener('click', () => {
  $('time-panel').classList.remove('open');
  document.querySelectorAll('.vbar-col.active').forEach(c => c.classList.remove('active'));
});

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  if ($('country-panel').classList.contains('open')) {
    $('country-panel').classList.remove('open');
  } else if ($('time-panel').classList.contains('open')) {
    $('time-panel').classList.remove('open');
    document.querySelectorAll('.vbar-col.active').forEach(c => c.classList.remove('active'));
  }
});

// ── Table filler ──────────────────────────────────────────────────────────
function fillTable(id, rows, rowHtml) {
  const tbl = $(id);
  if (!tbl) return;
  const tbody = tbl.querySelector('tbody');
  if (!rows.length) {
    tbody.innerHTML = `<tr><td colspan="10" style="text-align:center;color:var(--fg-dim);padding:20px">${t('tbl.nodata')}</td></tr>`;
    return;
  }
  tbody.innerHTML = rows.map((r, i) => `<tr>${rowHtml({ ...r, _rank: i + 1 })}</tr>`).join('');
}

// ── Init ──────────────────────────────────────────────────────────────────
// Apply stored language preference on page load
if (currentLang !== 'en') applyLang(currentLang);
