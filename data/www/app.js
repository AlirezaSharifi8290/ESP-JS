'use strict';

const $ = id => document.getElementById(id);
const STARTER = `// Example: blink GPIO 2 ten times.\n// Elk JS uses let, not const/var.\n\ngpio_mode(2, "output");\n\nfor (let i = 0; i < 10; i = i + 1) {\n  gpio_write(2, true);\n  delay_ms(250);\n  gpio_write(2, false);\n  delay_ms(250);\n}\nprint("finished");`;

let currentName = '';
let statusTimer = null;
let booted = false;
const cryptoWorker = new Worker('/crypto-worker.js');
let cryptoId = 0;
const cryptoPending = new Map();

cryptoWorker.onmessage = event => {
  const {id, ok, result, error} = event.data || {};
  const pending = cryptoPending.get(id);
  if (!pending) return;
  cryptoPending.delete(id);
  clearTimeout(pending.timer);
  if (ok) pending.resolve(result); else pending.reject(new Error(error || 'Crypto worker failed'));
};

cryptoWorker.onerror = event => {
  const message = event?.message || 'Crypto worker failed to start or crashed.';
  for (const [id, pending] of cryptoPending) {
    clearTimeout(pending.timer);
    pending.reject(new Error(message));
    cryptoPending.delete(id);
  }
};

function cryptoCall(op, payload) {
  return new Promise((resolve, reject) => {
    const id = ++cryptoId;
    const timer = setTimeout(() => {
      if (!cryptoPending.has(id)) return;
      cryptoPending.delete(id);
      reject(new Error('Crypto operation timed out.'));
    }, 15000);
    cryptoPending.set(id, {resolve, reject, timer});
    cryptoWorker.postMessage({id, op, ...payload});
  });
}

function setHidden(id, hidden) { $(id).classList.toggle('hidden', hidden); }
function authError(msg) { $('authError').textContent = msg || ''; }
function passwordError(msg) { $('passwordError').textContent = msg || ''; }
function showLog(msg, err=false) { $('log').hidden = false; $('log').textContent = msg; $('log').style.color = err ? '#ffbec6' : '#b8f6d7'; }
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }

async function api(path, options={}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(path, {
      cache: 'no-store',
      credentials: 'same-origin',
      ...options,
      signal: controller.signal
    });
    const text = await response.text();
    let data;
    try { data = text ? JSON.parse(text) : null; } catch (_) { data = text; }
    if (!response.ok) {
      const error = new Error((data && data.error) || text || response.statusText || `HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return data;
  } finally { clearTimeout(timeout); }
}

async function authInfo() { return api('/api/auth/info'); }
async function getChallenge(setup=false) { return api(`/api/auth/${setup ? 'setup-' : ''}challenge`); }

async function doSetup() {
  authError('');
  const code = $('setupCode').value.trim();
  const password = $('setupPassword').value;
  const password2 = $('setupPassword2').value;
  if (!/^[0-9a-fA-F]{64}$/.test(code)) return authError('Enter the 64-character setup code from Serial Monitor.');
  if (password.length < 8) return authError('Password must be at least 8 characters.');
  if (password !== password2) return authError('Passwords do not match.');
  $('setupBtn').disabled = true; $('setupBtn').textContent = 'Setting password…';
  try {
    const info = await authInfo();
    if (info.configured) throw new Error('This device is already configured.');
    const challenge = await getChallenge(true);
    const verifier = await cryptoCall('derive', {password, saltHex: info.setupSalt, iterations: info.iterations});
    const proof = await cryptoCall('hmac', {keyHex: code, dataHex: challenge.challenge});
    await api('/api/auth/setup', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({proof, verifier})});
    await bootApp();
  } catch (error) {
    authError(error.name === 'AbortError' ? 'Request timed out.' : error.message);
  } finally { $('setupBtn').disabled = false; $('setupBtn').textContent = 'Set password'; }
}

async function doLogin() {
  authError('');
  const password = $('loginPassword').value;
  if (!password) return authError('Enter your password.');
  $('loginBtn').disabled = true; $('loginBtn').textContent = 'Unlocking…';
  try {
    const info = await authInfo();
    if (!info.configured) { showAuth(true); return; }
    const challenge = await getChallenge(false);
    const verifier = await cryptoCall('derive', {password, saltHex: info.salt, iterations: info.iterations});
    const proof = await cryptoCall('hmac', {keyHex: verifier, dataHex: challenge.challenge});
    await api('/api/auth/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({proof})});
    $('loginPassword').value = '';
    await bootApp({fromLogin:true});
  } catch (error) {
    authError(error.status === 429 ? 'Temporarily locked after repeated failures. Try again shortly.' : error.name === 'AbortError' ? 'Request timed out.' : error.message);
  } finally { $('loginBtn').disabled = false; $('loginBtn').textContent = 'Unlock'; }
}

function showAuth(setup) {
  setHidden('authView', false); setHidden('appView', true);
  setHidden('setupFields', !setup); setHidden('loginFields', setup);
  $('authDescription').textContent = setup ? 'First boot: set a password using the setup code printed by the ESP32.' : 'Enter the device password to unlock the web console.';
  authError('');
  stopStatusTimer();
}

function showApp() {
  setHidden('authView', true); setHidden('appView', false); booted = true;
  if (!statusTimer) statusTimer = setInterval(updateStatus, document.visibilityState === 'visible' ? 2000 : 5000);
}

function stopStatusTimer() { if (statusTimer) { clearInterval(statusTimer); statusTimer = null; } }

async function bootApp(options = {}) {
  const fromLogin = Boolean(options.fromLogin);
  try {
    await api('/api/auth/me');
  } catch (error) {
    if (fromLogin) {
      throw new Error(
        `Password accepted by the ESP32, but the session cookie was not retained (${error.message || 'authentication check failed'}).`
      );
    }
    showAuth(false);
    return false;
  }
  showApp();
  await listApps();
  await updateStatus();
  return true;
}

async function boot() {
  try {
    const info = await authInfo();
    if (info.configured) {
      let authenticated = false;
      try { await api('/api/auth/me'); authenticated = true; } catch (_) { authenticated = false; }
      if (authenticated) await bootApp(); else showAuth(false);
    } else {
      showAuth(true);
    }
  } catch (error) {
    showAuth(true); authError(error.message);
  }
}

async function listApps() {
  try {
    const names = await api('/api/apps');
    const box = $('apps'); box.replaceChildren();
    if (!names.length) {
      const empty = document.createElement('div'); empty.className = 'empty'; empty.textContent = 'No apps installed.'; box.appendChild(empty); return;
    }
    for (const name of names) {
      const row = document.createElement('div'); row.className = 'app';
      const span = document.createElement('div'); span.className = 'name'; span.textContent = name;
      const button = document.createElement('button'); button.textContent = 'Open'; button.onclick = () => openApp(name);
      row.append(span, button); box.appendChild(row);
    }
  } catch (error) {
    if (error.status === 401) { boot(); return; }
    showLog(error.message, true);
  }
}

function saveDraft() {
  if (!currentName) return;
  try { localStorage.setItem(`espjs:draft:${currentName}`, $('code').value); } catch (_) {}
}
function loadDraft(name, serverCode) {
  try {
    const draft = localStorage.getItem(`espjs:draft:${name}`);
    if (draft !== null && draft !== serverCode && confirm(`A local draft for ${name} exists. Restore it?`)) return draft;
  } catch (_) {}
  return serverCode;
}
function clearDraft(name) { try { localStorage.removeItem(`espjs:draft:${name}`); } catch (_) {} }

async function openApp(name) {
  try {
    const data = await api(`/api/app?name=${encodeURIComponent(name)}`);
    currentName = name; $('name').value = name; $('code').value = loadDraft(name, data.code); showLog(`Loaded ${name}`);
  } catch (error) { showLog(error.message, true); }
}

async function save() {
  const name = $('name').value.trim();
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) return showLog('Invalid app name.', true);
  if (!$('code').value.length) return showLog('App code is empty.', true);
  const button = $('saveBtn'); button.disabled = true;
  try {
    await api(`/api/app?name=${encodeURIComponent(name)}`, {method:'POST', headers:{'Content-Type':'text/plain;charset=utf-8'}, body:$('code').value});
    currentName = name; clearDraft(name); await listApps(); showLog(`Saved ${name}`);
  } catch (error) { showLog(error.message, true); }
  finally { button.disabled = false; }
}

async function run() {
  const name = $('name').value.trim();
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(name)) return showLog('Open or save an app first.', true);
  try { await api(`/api/run?name=${encodeURIComponent(name)}`, {method:'POST'}); showLog(`Run requested for ${name}`); }
  catch (error) { showLog(error.message, true); }
  updateStatus();
}
async function stop() {
  try { await api('/api/stop', {method:'POST'}); showLog('Stop requested'); }
  catch (error) { showLog(error.message, true); }
  updateStatus();
}
async function removeApp() {
  const name = $('name').value.trim(); if (!name) return showLog('Nothing selected.', true);
  if (!confirm(`Delete ${name}?`)) return;
  try { await api(`/api/app?name=${encodeURIComponent(name)}`, {method:'DELETE'}); currentName=''; $('name').value=''; $('code').value=STARTER; clearDraft(name); await listApps(); showLog(`Deleted ${name}`); }
  catch (error) { showLog(error.message, true); }
}
function formatUptime(ms) {
  let s=Math.floor(ms/1000), d=Math.floor(s/86400); s%=86400; const h=Math.floor(s/3600); s%=3600; const m=Math.floor(s/60); s%=60;
  return d ? `${d}d ${h}h ${m}m` : h ? `${h}h ${m}m ${s}s` : `${m}m ${s}s`;
}
async function updateStatus() {
  if (!booted) return;
  try {
    const data = await api('/api/status');
    $('heap').textContent = `${(data.freeHeap/1024).toFixed(1)} KB`;
    $('minHeap').textContent = `${(data.minFreeHeap/1024).toFixed(1)} KB`;
    $('uptime').textContent = formatUptime(data.uptimeMs);
    $('current').textContent = data.runner.app || 'idle';
    $('stopState').textContent = data.runner.stopRequested ? 'yes' : 'no';
    $('runBadge').textContent = data.runner.running ? `running: ${data.runner.app}` : 'idle';
    $('runBadge').classList.toggle('live', data.runner.running);
    if (data.runner.error) showLog(data.runner.error, true);
  } catch (error) {
    if (error.status === 401) boot();
  }
}

async function changePassword() {
  passwordError('');
  const p1=$('newPassword').value, p2=$('newPassword2').value;
  if (p1.length < 8) return passwordError('Password must be at least 8 characters.');
  if (p1 !== p2) return passwordError('Passwords do not match.');
  const button=$('passwordSave'); button.disabled=true; button.textContent='Changing…';
  try {
    const info=await api('/api/auth/password-info');
    const verifier=await cryptoCall('derive',{password:p1,saltHex:info.salt,iterations:info.iterations});
    await api('/api/auth/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({salt:info.salt,verifier})});
    $('newPassword').value=''; $('newPassword2').value=''; $('passwordModal').classList.add('hidden'); showLog('Password changed successfully.');
  } catch (error) { passwordError(error.message); }
  finally { button.disabled=false; button.textContent='Change password'; }
}

async function logout() {
  try { await api('/api/auth/logout',{method:'POST'}); } catch (_) {}
  booted=false; stopStatusTimer(); showAuth(false);
}

$('setupBtn').onclick=doSetup;
$('loginBtn').onclick=doLogin;
$('setupPassword2').addEventListener('keydown',e=>{if(e.key==='Enter')doSetup()});
$('loginPassword').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin()});
$('newBtn').onclick=()=>{saveDraft();currentName='';$('name').value='';$('code').value=STARTER;showLog('New app')};
$('refreshBtn').onclick=listApps;
$('saveBtn').onclick=save; $('runBtn').onclick=run; $('stopBtn').onclick=stop; $('deleteBtn').onclick=removeApp;
$('passwordBtn').onclick=()=>{passwordError('');$('newPassword').value='';$('newPassword2').value='';$('passwordModal').classList.remove('hidden');$('newPassword').focus()};
$('passwordCancel').onclick=()=>$('passwordModal').classList.add('hidden');
$('passwordSave').onclick=changePassword; $('logoutBtn').onclick=logout;
$('code').addEventListener('input', saveDraft);
document.addEventListener('visibilitychange',()=>{if(booted){stopStatusTimer();statusTimer=setInterval(updateStatus,document.visibilityState==='visible'?2000:5000)}});
document.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){e.preventDefault();save()}if((e.ctrlKey||e.metaKey)&&e.key==='Enter'){e.preventDefault();run()}});
$('code').value=STARTER;
boot();
