using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
const string issuer = "lab12";
const string audience = "lab12-api";
var key = new SymmetricSecurityKey(RandomNumberGenerator.GetBytes(32));
var lifetime = builder.Configuration.GetValue("AccessSeconds", 900);
if (lifetime <= 0) throw new InvalidOperationException("AccessSeconds must be positive.");

builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer(options =>
    {
      options.MapInboundClaims = false;
      options.TokenValidationParameters = new()
      {
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = key,
        ValidateLifetime = true,
        RequireExpirationTime = true,
        RequireSignedTokens = true,
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        ClockSkew = TimeSpan.Zero,
        NameClaimType = "name",
        RoleClaimType = "role"
      };
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseDefaultFiles();
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();

var store = new AuthStore();

string CreateAccess(User user)
{
  var now = DateTime.UtcNow;
  var claims = new[]
  {
        new Claim("sub", user.Id),
        new Claim("name", user.Name),
        new Claim("role", user.Role),
        new Claim("jti", Guid.NewGuid().ToString("N"))
    };
  var token = new JwtSecurityToken(
      issuer,
      audience,
      claims,
      now,
      now.AddSeconds(lifetime),
      new SigningCredentials(key, SecurityAlgorithms.HmacSha256));
  return new JwtSecurityTokenHandler().WriteToken(token);
}

object Tokens(User user, string refreshToken) => new
{
  accessToken = CreateAccess(user),
  refreshToken,
  tokenType = "Bearer",
  expiresIn = lifetime
};

app.MapPost("/auth/login", (LoginRequest input) =>
{
  var user = store.Validate(input.UserName, input.Password);
  return user is null
      ? Results.Unauthorized()
      : Results.Ok(Tokens(user, store.Issue(user.Id)));
});

app.MapPost("/auth/refresh", (RefreshRequest input) =>
{
  var result = store.Rotate(input.RefreshToken);
  if (result is null) return Results.Unauthorized();

  var user = store.Find(result.Value.UserId);
  return user is null
      ? Results.Unauthorized()
      : Results.Ok(Tokens(user, result.Value.Token));
});

app.MapPost("/auth/logout", (RefreshRequest input) =>
{
  store.Revoke(input.RefreshToken);
  return Results.NoContent();
});

app.MapGet("/api/profile", (ClaimsPrincipal user) => Results.Ok(new
{
  id = user.FindFirst("sub")?.Value,
  name = user.Identity?.Name,
  role = user.FindFirst("role")?.Value
})).RequireAuthorization();

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

app.Run();

record LoginRequest(string? UserName, string? Password);
record RefreshRequest(string? RefreshToken);
