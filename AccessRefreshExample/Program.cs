using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

// Создаём стандартный конвейер ASP.NET Core Minimal API.
var builder = WebApplication.CreateBuilder(args);
// Учебный ключ живёт до перезапуска процесса. В реальном приложении ключ
// должен приходить из секретного хранилища и быть одинаковым у всех экземпляров.
var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
// Эти значения попадают в claims iss и aud и затем проверяются при каждом запросе.
const string issuer = "lab12";
const string audience = "lab12-api";
// Небольшой срок access удобно наблюдать в браузере; значение можно переопределить.
var lifetime = builder.Configuration.GetValue("AccessSeconds", 10);
if (lifetime <= 0) throw new InvalidOperationException("AccessSeconds must be positive.");
// Оба хранилища демонстрационные и живут только в памяти процесса.
var users = new UserStore();
var refresh = new RefreshStore();
// JWT Bearer извлекает токен из Authorization: Bearer ...,
// проверяет подпись и claims, а затем строит ClaimsPrincipal.
builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer(options =>
    {
      options.MapInboundClaims = false;
      options.TokenValidationParameters = new()
      {
        // Разрешаем только наш issuer и audience.
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        ValidAudience = audience,
        // Фиксируем подпись и алгоритм, чтобы payload нельзя было подменить.
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        ValidateLifetime = true,
        RequireExpirationTime = true,
        RequireSignedTokens = true,
        ClockSkew = TimeSpan.Zero,
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        // Эти имена определяют Identity.Name и claim роли.
        NameClaimType = "name",
        RoleClaimType = "role"
      };
    });
builder.Services.AddAuthorization();
var app = builder.Build();
// Раздаём index.html и app.js из каталога wwwroot.
app.UseDefaultFiles();
app.UseStaticFiles();
// Authentication должен выполняться раньше Authorization.
app.UseAuthentication();
app.UseAuthorization();

// Выпускает короткоживущий подписанный access-токен.
string Access(User user)
{
  var now = DateTime.UtcNow;
  // sub — id, name — имя UI, role — claim авторизации, jti — уникальный id токена.
  var token = new JwtSecurityToken(issuer, audience,
      [new("sub", user.Id), new("name", user.Name), new("role", user.Role),
         new("jti", Guid.NewGuid().ToString("N"))],
      notBefore: now, expires: now.AddSeconds(lifetime),
      signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
  return new JwtSecurityTokenHandler().WriteToken(token);
}
// JSON-ответ для небраузерного клиента: refresh возвращается в теле.
object Pair(User user, string token) => new
{
  accessToken = Access(user),
  refreshToken = token,
  tokenType = "Bearer",
  expiresIn = lifetime
};

// Веб-клиент получает только access; refresh передаётся в HttpOnly cookie.
// JavaScript страницы не может прочитать такой cookie через document.cookie.
const string cookieName = "lab12.refresh";
// Cookie действует только на auth-маршрутах и автоматически истекает через 7 дней.
CookieOptions RefreshCookie(HttpContext context) => new()
{
  HttpOnly = true,
  Secure = context.Request.IsHttps,
  SameSite = SameSiteMode.Strict,
  Path = "/web/auth",
  MaxAge = TimeSpan.FromDays(7)
};
IResult BrowserPair(HttpContext context, User user, string token)
{
  // Access остаётся в памяти браузера, refresh отправляется заголовком Set-Cookie.
  context.Response.Cookies.Append(cookieName, token, RefreshCookie(context));
  return Results.Ok(new { accessToken = Access(user), tokenType = "Bearer", expiresIn = lifetime });
}
var webAuth = app.MapGroup("/web/auth");
// Нестандартный заголовок требует CORS preflight для чужого origin.
// CORS здесь не включён; обычная HTML-форма также не может задать этот заголовок.
webAuth.AddEndpointFilter(async (context, next) =>
{
  context.HttpContext.Response.Headers.CacheControl = "no-store";
  if (context.HttpContext.Request.Headers["X-Requested-With"] != "lab12-web")
    return Results.StatusCode(403);
  return await next(context);
});

webAuth.MapPost("/login", (LoginRequest input, HttpContext context) =>
{
  // Роль берётся из серверной записи пользователя, а не из запроса клиента.
  var user = users.Validate(input.UserName, input.Password);
  if (user is null) return Results.Unauthorized();
  refresh.Revoke(context.Request.Cookies[cookieName]);
  return BrowserPair(context, user, refresh.Issue(user.Id));
});

webAuth.MapPost("/refresh", (HttpContext context) =>
{
  // Ротация делает прежний refresh одноразовым и выдаёт новую cookie.
  var rotation = refresh.Rotate(context.Request.Cookies[cookieName]);
  if (rotation is null)
  {
    context.Response.Cookies.Delete(cookieName, RefreshCookie(context));
    return Results.Unauthorized();
  }
  var user = users.Find(rotation.Value.UserId);
  return user is null ? Results.Unauthorized() : BrowserPair(context, user, rotation.Value.Token);
});

webAuth.MapPost("/logout", (HttpContext context) =>
{
  // Logout отзывает всю семью refresh-токенов и удаляет cookie.
  refresh.Revoke(context.Request.Cookies[cookieName]);
  context.Response.Cookies.Delete(cookieName, RefreshCookie(context));
  return Results.NoContent();
});

app.MapPost("/auth/login", (LoginRequest input) =>
{
  // JSON API оставлен для PowerShell, тестов и не браузерных клиентов.
  var user = users.Validate(input.UserName, input.Password);
  return user is null ? Results.Unauthorized() : Results.Ok(Pair(user, refresh.Issue(user.Id)));
});

// Любой аутентифицированный пользователь может получить свой профиль.
app.MapGet("/api/profile", (ClaimsPrincipal user) => Results.Ok(new
{
  id = user.FindFirst("sub")?.Value,
  name = user.Identity?.Name,
  role = user.FindFirst("role")?.Value
})).RequireAuthorization();

// RequireRole возвращает 403, если role claim не совпадает.
app.MapGet("/api/student", (ClaimsPrincipal user) => Results.Ok(new
{
  name = user.Identity?.Name,
  role = user.FindFirst("role")?.Value,
  message = "Student endpoint"
})).RequireAuthorization(policy => policy.RequireRole("Student"));

app.MapGet("/api/teacher", (ClaimsPrincipal user) => Results.Ok(new
{
  name = user.Identity?.Name,
  role = user.FindFirst("role")?.Value,
  message = "Teacher endpoint"
})).RequireAuthorization(policy => policy.RequireRole("Teacher"));

app.MapPost("/auth/refresh", (RefreshRequest input) =>
{
  // JSON-вариант ротации принимает refresh в теле запроса.
  var rotation = refresh.Rotate(input.RefreshToken);
  if (rotation is null) return Results.Unauthorized();
  var user = users.Find(rotation.Value.UserId);
  return user is null ? Results.Unauthorized() : Results.Ok(Pair(user, rotation.Value.Token));
});

app.MapPost("/auth/logout", (RefreshRequest input) =>
{
  // JSON-вариант logout отзывает цепочку, но не удаляет cookie.
  refresh.Revoke(input.RefreshToken);
  return Results.NoContent();
});

app.Run();

record LoginRequest(string? UserName, string? Password);