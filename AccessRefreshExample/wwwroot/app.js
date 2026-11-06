// Небольшой DOM-helper, чтобы не повторять document.getElementById.
const $ = id => document.getElementById(id);
// Access-токен не пишется в localStorage: после закрытия вкладки он исчезает.
let accessToken = null;
let expiresAt = 0;
// Все действия одной страницы последовательны: refresh и logout не гоняются.
let queue = Promise.resolve();
function action(work) {
  // Последовательность предотвращает двойной обмен одного refresh-токена.
  queue = queue.then(work).catch(error => log(error.message));
  return queue;
}
function log(message) {
  // Журнал помогает увидеть порядок login → API → 401 → refresh → retry.
  $('log').textContent += `${new Date().toLocaleTimeString()} ${message}\n`;
}
function clearAccess() { accessToken = null; expiresAt = 0; }
async function auth(operation, body) {
  // Cookie передаётся браузером автоматически; JS получает только access из JSON.
  const response = await fetch(`/web/auth/${operation}`, {
    method: 'POST', credentials: 'same-origin',
    headers: { 'X-Requested-With': 'lab12-web', ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined
  });
  log(`POST /web/auth/${operation} → ${response.status}`);
  if (!response.ok) {
    clearAccess();
    throw new Error(response.status === 401 ? 'Нужен вход: сессия отсутствует или истекла.' : `Ошибка ${response.status}`);
  }
  if (operation !== 'logout') {
    // expiresIn приходит с сервера и используется только для индикатора UI.
    const pair = await response.json();
    accessToken = pair.accessToken;
    expiresAt = Date.now() + pair.expiresIn * 1000;
  }
}
async function api(path) {
  // Если access отсутствует (например, после reload), сначала восстанавливаем его.
  if (!accessToken) await auth('refresh');
  // API принимает access в стандартном Bearer-заголовке.
  const send = () => fetch(path, { headers: { Authorization: `Bearer ${accessToken}` } });
  let response = await send();
  log(`GET ${path} → ${response.status}`);
  if (response.status === 401) {
    // Access истёк или был отвергнут: один раз ротируем refresh и повторяем GET.
    clearAccess();
    await auth('refresh');
    response = await send(); // Только одна повторная попытка.
    log(`Повтор GET ${path} → ${response.status}`);
  }
  if (response.status === 401) clearAccess();
  if (response.status === 403) throw new Error('Недостаточно прав для этого маршрута.');
  if (!response.ok) throw new Error(`Ошибка ${response.status}`);
  log(JSON.stringify(await response.json(), null, 2));
}
$('account').addEventListener('change', event => {
  // Переключатель заполняет только учебные демонстрационные данные.
  const student = event.target.value === 'student';
  $('userName').value = student ? 'student' : 'teacher';
  $('password').value = student ? 'Student-123!' : 'Teacher-123!';
});
$('login').addEventListener('submit', event => {
  event.preventDefault();
  const body = { userName: $('userName').value, password: $('password').value };
  action(async () => { await auth('login', body); await api('/api/profile'); });
});
document.querySelectorAll('[data-path]').forEach(button => {
  // Все три кнопки используют один и тот же механизм с Bearer-токеном.
  button.addEventListener('click', () => action(() => api(button.dataset.path)));
});
$('logout').addEventListener('click', () => action(async () => {
  // При сетевой ошибке cookie может оставаться: об этом сообщит журнал.
  try { await auth('logout'); } finally { clearAccess(); }
}));
setInterval(() => {
  // Таймер не обновляет токен сам — refresh выполняется при следующем API-запросе.
  const seconds = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
  $('status').textContent = !accessToken ? 'Нет access-токена' : seconds > 0
    ? `Access действует ещё ${seconds} с` : 'Access истёк. Следующий запрос запустит refresh.';
}, 250);
// После перезагрузки страницы восстанавливаем access по HttpOnly cookie.
action(async () => { await auth('refresh'); await api('/api/profile'); });
