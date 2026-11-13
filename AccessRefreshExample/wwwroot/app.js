const $ = id => document.getElementById(id);
let accessToken = null;
let refreshToken = null;
let expiresAt = 0;
let queue = Promise.resolve();

function action(work) {
  queue = queue.then(work).catch(error => log(error.message));
  return queue;
}

function log(message) {
  $('log').textContent += `${new Date().toLocaleTimeString()} ${message}\n`;
}

function clearTokens() {
  accessToken = null;
  refreshToken = null;
  expiresAt = 0;
}

async function auth(operation, body) {
  const response = await fetch(`/auth/${operation}`, {
    method: 'POST',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined
  });
  log(`POST /auth/${operation} → ${response.status}`);

  if (!response.ok) {
    clearTokens();
    throw new Error(response.status === 401 ? 'Нужен вход.' : `Ошибка ${response.status}`);
  }

  if (operation !== 'logout') {
    const tokens = await response.json();
    accessToken = tokens.accessToken;
    refreshToken = tokens.refreshToken;
    expiresAt = Date.now() + tokens.expiresIn * 1000;
  }
}

async function api(path) {
  if (!accessToken) await auth('refresh', { refreshToken });

  const send = () => fetch(path, {
    headers: { Authorization: `Bearer ${accessToken}` }
  });
  let response = await send();
  log(`GET ${path} → ${response.status}`);

  if (response.status === 401) {
    await auth('refresh', { refreshToken });
    response = await send();
    log(`Повтор GET ${path} → ${response.status}`);
  }
  if (response.status === 401) clearTokens();
  if (response.status === 403) throw new Error('Недостаточно прав.');
  if (!response.ok) throw new Error(`Ошибка ${response.status}`);
  log(JSON.stringify(await response.json(), null, 2));
}

$('account').addEventListener('change', event => {
  const student = event.target.value === 'student';
  $('userName').value = student ? 'student' : 'teacher';
  $('password').value = student ? 'Student-123!' : 'Teacher-123!';
});

$('login').addEventListener('submit', event => {
  event.preventDefault();
  action(async () => {
    await auth('login', {
      userName: $('userName').value,
      password: $('password').value
    });
    await api('/api/profile');
  });
});

document.querySelectorAll('[data-path]').forEach(button =>
  button.addEventListener('click', () => action(() => api(button.dataset.path))));

$('logout').addEventListener('click', () => action(async () => {
  try {
    await auth('logout', { refreshToken });
  } finally {
    clearTokens();
  }
}));

setInterval(() => {
  const seconds = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
  $('status').textContent = !accessToken
    ? 'Нет access-токена'
    : seconds > 0 ? `Access действует ещё ${seconds} с` : 'Access истёк.';
}, 250);
