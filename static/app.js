'use strict';

const byId = id => document.getElementById(id);
const pageStatus = byId('page-status');
let settings;
let profile;

function notice(text) {
  pageStatus.textContent = text;
  pageStatus.hidden = !text;
}

async function api(path, body) {
  const options = { cache: 'no-store', credentials: 'same-origin' };
  if (body !== undefined) {
    options.method = 'POST';
    options.headers = { 'Content-Type': 'application/json' };
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(result.error || `پاسخ سرویس: ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return result;
}

function view(section) {
  for (const name of ['setup', 'login', 'dashboard']) byId(name).hidden = name !== section;
}

async function refresh() {
  settings = await api('/api/session');
  byId('missing').textContent = settings.missing.join('\n');
  byId('host').textContent = settings.host;
  byId('path').textContent = settings.wsPath;
  view(!settings.configured ? 'setup' : settings.authenticated ? 'dashboard' : 'login');
}

async function work(button, operation) {
  button.disabled = true;
  notice('');
  try {
    await operation();
  } catch (error) {
    if (error.status === 401 && settings?.authenticated) {
      profile = undefined;
      byId('result').hidden = true;
      view('login');
    }
    notice(error.message || 'ارتباط با سرور برقرار نشد.');
  } finally {
    button.disabled = false;
  }
}

byId('login-form').addEventListener('submit', event => {
  event.preventDefault();
  const form = event.currentTarget;
  work(form.querySelector('button'), async () => {
    await api('/api/login', { password: form.elements.password.value });
    form.reset();
    await refresh();
  });
});

byId('logout').addEventListener('click', event => work(event.currentTarget, async () => {
  await api('/api/logout', {});
  profile = undefined;
  byId('result').hidden = true;
  await refresh();
}));

byId('issue-form').addEventListener('submit', event => {
  event.preventDefault();
  const form = event.currentTarget;
  work(form.querySelector('button'), async () => {
    profile = await api('/api/issue', { name: form.elements.name.value, days: Number(form.elements.days.value) });
    byId('profile-name').textContent = profile.name;
    byId('expiry').textContent = 'پایان اعتبار ' + new Date(profile.expires * 1000).toLocaleString('fa-IR');
    byId('profile-link').value = profile.link;
    byId('test-result').textContent = '';
    const qr = qrcode(0, 'M');
    qr.addData(profile.link);
    qr.make();
    byId('profile-qr').src = qr.createDataURL(4, 16);
    byId('result').hidden = false;
  });
});

byId('copy').addEventListener('click', async () => {
  if (!profile) return;
  try {
    await navigator.clipboard.writeText(profile.link);
    notice('لینک کپی شد.');
  } catch {
    byId('profile-link').select();
    notice('لینک انتخاب شد. از منوی مرورگر کپی کن.');
  }
});

byId('download').addEventListener('click', () => {
  if (!profile) return;
  const file = URL.createObjectURL(new Blob([profile.link + '\n'], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = file;
  link.download = 'Aria-Wasmer-vless.txt';
  link.click();
  setTimeout(() => URL.revokeObjectURL(file), 3000);
});

function probePacket(uuid) {
  const encode = new TextEncoder();
  const id = uuid.replaceAll('-', '').match(/../g).map(part => Number.parseInt(part, 16));
  const destination = 'example.com';
  const http = `GET / HTTP/1.1\r\nHost: ${destination}\r\nConnection: close\r\n\r\n`;
  return Uint8Array.from([0, ...id, 0, 1, 0, 80, 2, destination.length, ...encode.encode(destination), ...encode.encode(http)]);
}

byId('test').addEventListener('click', event => {
  if (!profile) return;
  const activeProfile = profile;
  const button = event.currentTarget;
  const result = byId('test-result');
  const ws = new WebSocket(`wss://${settings.host}${settings.wsPath}`);
  ws.binaryType = 'arraybuffer';
  button.disabled = true;
  result.textContent = 'در حال باز کردن WebSocket…';
  let received = [];
  let finished = false;
  let upgraded = false;
  let connected = false;
  const timeoutMessage = () => {
    if (connected) return 'TCP به مقصد آزمایشی وصل شد. پاسخ HTTP در مهلت تست نرسید.';
    return upgraded
      ? 'WebSocket باز شد. تأیید اتصال خروجی در مهلت تست نرسید.'
      : 'درخواست WebSocket در مهلت آزمایش باز نشد.';
  };
  const timer = setTimeout(() => finish(timeoutMessage()), 22000);

  function finish(message) {
    if (finished) return;
    finished = true;
    clearTimeout(timer);
    if (profile === activeProfile) result.textContent = message;
    button.disabled = false;
    if (ws.readyState < WebSocket.CLOSING) ws.close();
  }

  ws.addEventListener('open', () => {
    upgraded = true;
    result.textContent = 'WebSocket باز شد. در حال تست مقصد عمومی…';
    ws.send(probePacket(activeProfile.uuid));
  });
  ws.addEventListener('message', event => {
    received = received.concat(Array.from(new Uint8Array(event.data).slice(0, 128))).slice(0, 128);
    if (received.length < 2) return;
    if (received[0] !== 0 || received[1] !== 0) return finish('پاسخ VLESS معتبر نبود.');
    connected = true;
    if (profile === activeProfile) result.textContent = 'TCP وصل شد. در انتظار پاسخ HTTP مقصد…';
    const reply = new TextDecoder().decode(Uint8Array.from(received.slice(2)));
    const status = /^HTTP\/1\.[01] (\d{3})\b/.exec(reply);
    if (status) finish(`ارتباط برقرار شد. پاسخ HTTP ${status[1]} از example.com رسید.`);
  });
  ws.addEventListener('error', () => {
    if (!upgraded) finish('WebSocket باز نشد. دامنه و استقرار Wasmer را بررسی کن.');
  });
  ws.addEventListener('close', event => {
    const byReason = {
      'first-frame-timeout': 'WebSocket باز شد اما سرور اولین بستهٔ داده را دریافت نکرد.',
      'header-timeout': 'بخشی از بستهٔ VLESS رسید و سرآیند کامل نشد.',
      'invalid-profile': 'کانفیگ رد شد. یک لینک تازه بساز و دوباره تست کن.',
      'expired-profile': 'اعتبار کانفیگ تمام شده است. یک لینک تازه بساز.',
      'connection-rejected': 'درخواست VLESS یا مقصد از طرف پنل رد شد.',
      'outbound-dns': 'WebSocket باز شد اما DNS سرور نتوانست IP مقصد را پیدا کند.',
      'outbound-socket': 'سرور نتوانست سوکت خروجی باز کند.',
      'outbound-connect': 'سرور نتوانست اتصال TCP به مقصد آزمایشی برقرار کند.',
      'upstream-empty': 'TCP وصل شد اما مقصد قبل از ارسال داده ارتباط را بست.',
      'websocket-protocol': 'سرور در پردازش بستهٔ WebSocket خطا گرفت.',
      'tunnel-runtime': 'اجرای تونل با خطا روبه‌رو شد. Logs اپ را بررسی کن.',
      'relay-io': 'در خواندن یا نوشتن سوکت خطا رخ داد. Logs اپ را بررسی کن.',
    };
    const reason = Object.hasOwn(byReason, event.reason) ? byReason[event.reason] : '';
    const fallback = connected
      ? 'TCP به مقصد وصل شد اما پاسخ HTTP نرسید.'
      : upgraded ? 'WebSocket باز شد و قبل از تأیید اتصال خروجی بسته شد.' : 'WebSocket باز نشد.';
    finish(`${reason || fallback} کد ${event.code}`);
  });
});

refresh().then(() => notice('')).catch(error => notice(error.message || 'وضعیت پنل دریافت نشد.'));
