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

function probePacket(uuid, command, port, address, payload) {
  const id = uuid.replaceAll('-', '').match(/../g).map(part => Number.parseInt(part, 16));
  return Uint8Array.from([0, ...id, 0, command, port >> 8, port & 255, ...address, ...payload]);
}

function webProbe(uuid) {
  const encode = new TextEncoder();
  const destination = 'example.com';
  const http = `GET / HTTP/1.1\r\nHost: ${destination}\r\nConnection: close\r\n\r\n`;
  return {
    label: 'وب',
    packet: probePacket(uuid, 1, 80, [2, destination.length, ...encode.encode(destination)], encode.encode(http)),
    limit: 128,
    reply(bytes) {
      const reply = new TextDecoder().decode(bytes);
      const status = /^HTTP\/1\.[01] (\d{3})\b/.exec(reply);
      if (status) return `پاسخ HTTP ${status[1]} از ${destination} رسید.`;
    },
  };
}

function dnsProbe(uuid) {
  const id = crypto.getRandomValues(new Uint8Array(2));
  const encoder = new TextEncoder();
  const name = [7, ...encoder.encode('example'), 3, ...encoder.encode('com'), 0];
  // Standard recursive A query with a single question.
  const query = [...id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, ...name, 0, 1, 0, 1];
  return {
    label: 'DNS',
    packet: probePacket(uuid, 2, 53, [1, 1, 1, 1, 1], [0, query.length, ...query]),
    limit: 65535 + 4,
    reply(bytes) {
      if (bytes.length < 2) return;
      const length = bytes[0] * 256 + bytes[1];
      if (length < 12) return 'طول پاسخ DNS معتبر نیست.';
      if (bytes.length < length + 2) return;
      if (bytes[2] !== id[0] || bytes[3] !== id[1] || !(bytes[4] & 128)) {
        return 'پاسخ DNS با درخواست آزمایشی مطابقت ندارد.';
      }
      const rcode = bytes[5] & 15;
      if (rcode !== 0) return `سرور DNS خطای ${rcode} برگرداند.`;
      if (bytes[8] === 0 && bytes[9] === 0) return 'DNS برای دامنهٔ آزمایشی پاسخی برنگرداند.';
      return 'پاسخ معتبر از 1.1.1.1 از طریق تونل رسید.';
    },
  };
}

const closeMessages = {
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

function testSocket(activeProfile, result, probe) {
  return new Promise(resolve => {
    const ws = new WebSocket(`wss://${settings.host}${settings.wsPath}`);
    ws.binaryType = 'arraybuffer';
    const received = new Uint8Array(probe.limit);
    let size = 0;
    let finished = false;
    let upgraded = false;
    let connected = false;
    const show = message => {
      if (profile === activeProfile) result.textContent = `${probe.label} · ${message}`;
    };
    const connectionState = () => {
      if (connected) return 'TCP به مقصد وصل شد اما پاسخ نرسید.';
      return upgraded ? 'WebSocket باز شد اما تأیید اتصال خروجی نرسید.' : 'WebSocket باز نشد.';
    };
    const timer = setTimeout(() => finish(`مهلت تست تمام شد. ${connectionState()}`), 22000);

    function finish(message) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      show(message);
      if (ws.readyState < WebSocket.CLOSING) ws.close();
      resolve();
    }

    show('در حال باز کردن WebSocket…');
    ws.addEventListener('open', () => {
      upgraded = true;
      show('WebSocket باز شد. در حال تست مقصد…');
      ws.send(probe.packet);
    });
    ws.addEventListener('message', event => {
      if (finished) return;
      const chunk = new Uint8Array(event.data).subarray(0, received.length - size);
      received.set(chunk, size);
      size += chunk.length;
      if (size < 2) return;
      if (received[0] !== 0 || received[1] !== 0) return finish('پاسخ VLESS معتبر نبود.');
      connected = true;
      show('TCP وصل شد. در انتظار پاسخ مقصد…');
      const reply = probe.reply(received.subarray(2, size));
      if (reply) finish(reply);
    });
    ws.addEventListener('close', event => {
      const reason = Object.hasOwn(closeMessages, event.reason) ? closeMessages[event.reason] : connectionState();
      finish(`${reason} کد ${event.code}`);
    });
  });
}

byId('test').addEventListener('click', event => {
  if (!profile) return;
  const activeProfile = profile;
  return work(event.currentTarget, () => {
    const webResult = document.createElement('span');
    const dnsResult = document.createElement('span');
    byId('test-result').replaceChildren(webResult, document.createElement('br'), dnsResult);
    return Promise.all([
      testSocket(activeProfile, webResult, webProbe(activeProfile.uuid)),
      testSocket(activeProfile, dnsResult, dnsProbe(activeProfile.uuid)),
    ]);
  });
});

refresh().then(() => notice('')).catch(error => notice(error.message || 'وضعیت پنل دریافت نشد.'));
