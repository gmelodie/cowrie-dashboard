'use strict';

// ── Admin panel translations ──────────────────────────────────────────────
const ADMIN_STRINGS = {
  en: {
    // Header / nav
    'a.nav.dashboard':       'dashboard',
    'a.nav.peers':           'peers',
    'a.nav.pending':         'pending',
    'a.nav.stats':           '← stats',
    'a.nav.logout':          'logout',

    // This node
    'a.thisnode':            'This node',
    'a.fp.share':            'FINGERPRINT — share + verify OUT-OF-BAND',
    'a.field.node_name':     'Node name',
    'a.field.contact':       'Contact',
    'a.field.pubkey':        'Pubkey',
    'a.field.version':       'Version',
    'a.share.label':         "SHARE TOKEN — paste into a peer's \"add a peer\" form",
    'a.share.copy':          'copy',
    'a.share.copied':        '✓ copied',
    'a.daemon_unreachable':  'Daemon unreachable',
    'a.daemon_warn':         'at this URL. Trust state still loads from the database, but sign-and-send actions will fail.',

    // Add a peer
    'a.addpeer':             'Add a peer',
    'a.addpeer.hint':        "Send a peering request to a remote honeypot. The remote admin must approve it on their end. Verify their fingerprint out-of-band before they approve yours.",
    'a.paste.label':         "Paste peer's share token (auto-fills fields below)",
    'a.paste.fp':            'PARSED FINGERPRINT — VERIFY OUT-OF-BAND',
    'a.paste.invalid':       'Invalid share token',
    'a.form.url':            'Remote URL',
    'a.form.node_name':      'Node name (optional)',
    'a.form.contact':        'Contact (optional)',
    'a.form.notes':          'Notes (optional)',
    'a.form.send':           'send request',

    // Pending
    'a.pending':             'Pending requests',
    'a.pending.empty':       'No pending requests.',
    'a.pending.fp':          'FINGERPRINT — VERIFY OUT-OF-BAND BEFORE APPROVING',
    'a.pending.node':        'Node',
    'a.pending.contact':     'Contact',
    'a.pending.url':         'URL',
    'a.pending.notes':       'Notes',
    'a.pending.received':    'Received',
    'a.btn.approve':         'approve',
    'a.btn.reject':          'reject',
    'a.confirm.approve':     'Did you verify the fingerprint out-of-band?',

    // Peers
    'a.peers':               'Peers',
    'a.peers.fed':           'federated entries:',
    'a.peers.empty':         'No peers yet. Add one above to start.',
    'a.th.fingerprint':      'fingerprint',
    'a.th.node':             'node',
    'a.th.contact':          'contact',
    'a.th.url':              'url',
    'a.th.status':           'status',
    'a.th.score':            'score',
    'a.th.wethey':           'we/they',
    'a.th.lastseen':         'last seen',
    'a.th.lastpull':         'last pull',
    'a.th.entries':          'entries',
    'a.th.bad':              'bad sigs',
    'a.btn.pullnow':         'pull now',
    'a.btn.score':           'score',
    'a.btn.revoke':          'revoke',
    'a.lbl.purge':           'purge entries',
    'a.confirm.revoke':      'Revoke this peer?',

    // Login
    'a.login.title':         'federation admin',
    'a.login.bar':           'honey — admin login',
    'a.login.username':      'username',
    'a.login.password':      'password',
    'a.login.btn':           '[ AUTHENTICATE ]',
    'a.login.back':          '← back to stats',
    'a.login.notconfigured': 'not configured.',
    'a.login.notconfigured.desc': "set HONEY_ADMIN_USER and HONEY_ADMIN_PASSWORD_HASH in .env, then recreate the web container.",
    'a.login.err.invalid':   'Invalid username or password.',
    'a.login.err.config':    'Admin auth is not configured on this server. Set HONEY_ADMIN_USER and HONEY_ADMIN_PASSWORD_HASH.',
  },

  pt: {
    'a.nav.dashboard':       'painel',
    'a.nav.peers':           'pares',
    'a.nav.pending':         'pendentes',
    'a.nav.stats':           '← estatísticas',
    'a.nav.logout':          'sair',

    'a.thisnode':            'Este nó',
    'a.fp.share':            'FINGERPRINT — compartilhe + verifique FORA DA BANDA',
    'a.field.node_name':     'Nome do nó',
    'a.field.contact':       'Contato',
    'a.field.pubkey':        'Chave pública',
    'a.field.version':       'Versão',
    'a.share.label':         'TOKEN DE COMPARTILHAMENTO — cole no formulário "adicionar par" de um par',
    'a.share.copy':          'copiar',
    'a.share.copied':        '✓ copiado',
    'a.daemon_unreachable':  'Daemon inacessível',
    'a.daemon_warn':         'nesta URL. Estado de confiança ainda carrega do banco, mas ações que precisam assinar falharão.',

    'a.addpeer':             'Adicionar par',
    'a.addpeer.hint':        'Envie uma requisição de peering para um honeypot remoto. O admin remoto precisa aprovar do lado dele. Verifique a fingerprint dele fora da banda antes que ele aprove a sua.',
    'a.paste.label':         'Cole o token do par (preenche os campos abaixo)',
    'a.paste.fp':            'FINGERPRINT DECODIFICADA — VERIFIQUE FORA DA BANDA',
    'a.paste.invalid':       'Token inválido',
    'a.form.url':            'URL remota',
    'a.form.node_name':      'Nome do nó (opcional)',
    'a.form.contact':        'Contato (opcional)',
    'a.form.notes':          'Notas (opcional)',
    'a.form.send':           'enviar requisição',

    'a.pending':             'Requisições pendentes',
    'a.pending.empty':       'Nenhuma requisição pendente.',
    'a.pending.fp':          'FINGERPRINT — VERIFIQUE FORA DA BANDA ANTES DE APROVAR',
    'a.pending.node':        'Nó',
    'a.pending.contact':     'Contato',
    'a.pending.url':         'URL',
    'a.pending.notes':       'Notas',
    'a.pending.received':    'Recebido',
    'a.btn.approve':         'aprovar',
    'a.btn.reject':          'rejeitar',
    'a.confirm.approve':     'Você verificou a fingerprint fora da banda?',

    'a.peers':               'Pares',
    'a.peers.fed':           'entradas federadas:',
    'a.peers.empty':         'Nenhum par ainda. Adicione um acima para começar.',
    'a.th.fingerprint':      'fingerprint',
    'a.th.node':             'nó',
    'a.th.contact':          'contato',
    'a.th.url':              'url',
    'a.th.status':           'status',
    'a.th.score':            'score',
    'a.th.wethey':           'nós/eles',
    'a.th.lastseen':         'visto',
    'a.th.lastpull':         'último pull',
    'a.th.entries':          'entradas',
    'a.th.bad':              'sigs ruins',
    'a.btn.pullnow':         'pull agora',
    'a.btn.score':           'score',
    'a.btn.revoke':          'revogar',
    'a.lbl.purge':           'purgar entradas',
    'a.confirm.revoke':      'Revogar este par?',

    'a.login.title':         'admin de federação',
    'a.login.bar':           'honey — login admin',
    'a.login.username':      'usuário',
    'a.login.password':      'senha',
    'a.login.btn':           '[ AUTENTICAR ]',
    'a.login.back':          '← voltar para estatísticas',
    'a.login.notconfigured': 'não configurado.',
    'a.login.notconfigured.desc': 'defina HONEY_ADMIN_USER e HONEY_ADMIN_PASSWORD_HASH no .env, depois recrie o container web.',
    'a.login.err.invalid':   'Usuário ou senha inválidos.',
    'a.login.err.config':    'Autenticação admin não configurada. Defina HONEY_ADMIN_USER e HONEY_ADMIN_PASSWORD_HASH.',
  },
};

let adminLang = localStorage.getItem('lang') || 'en';

function adminT(key) {
  return (ADMIN_STRINGS[adminLang] || ADMIN_STRINGS.en)[key] ?? ADMIN_STRINGS.en[key] ?? key;
}

function adminApplyLang(lang) {
  if (!ADMIN_STRINGS[lang]) lang = 'en';
  adminLang = lang;
  document.documentElement.lang = lang;
  localStorage.setItem('lang', lang);

  document.querySelectorAll('[data-i18n]').forEach(function (el) {
    el.textContent = adminT(el.dataset.i18n);
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
    el.placeholder = adminT(el.dataset.i18nPlaceholder);
  });
  document.querySelectorAll('[data-i18n-title]').forEach(function (el) {
    el.title = adminT(el.dataset.i18nTitle);
  });

  document.querySelectorAll('.lang-tab').forEach(function (btn) {
    btn.classList.toggle('active', btn.dataset.lang === lang);
  });
}

document.addEventListener('DOMContentLoaded', function () {
  adminApplyLang(adminLang);
  document.querySelectorAll('.lang-tab').forEach(function (btn) {
    btn.addEventListener('click', function () { adminApplyLang(btn.dataset.lang); });
  });
});

// Expose for inline scripts that build dynamic strings.
window.adminT = adminT;
