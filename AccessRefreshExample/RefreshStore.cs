using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;


record RefreshRequest(string? RefreshToken);


sealed class RefreshStore
{
  // В Entry хранится hash refresh-токена, а не сам секрет.
  private sealed record Entry(string UserId, string Family, DateTime Expires)
  {
    public bool Used { get; set; }
  }
  // Проверка и замена под одной блокировкой атомарны при параллельных запросах.
  private readonly object gate = new();
  private readonly Dictionary<string, Entry> tokens = [];
  private readonly HashSet<string> revoked = [];
  private static string Hash(string token) => Convert.ToHexString(SHA256.HashData(
      System.Text.Encoding.UTF8.GetBytes(token)));
  // Выпускает криптографически случайный токен и привязывает его к family.
  private string NewToken(string user, string family)
  {
    var raw = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
    tokens.Add(Hash(raw), new(user, family, DateTime.UtcNow.AddDays(7)));
    return raw;
  }
  // Первый refresh начинает новую семью токенов.
  public string Issue(string user)
  {
    lock (gate) return NewToken(user, Guid.NewGuid().ToString("N"));
  }
  // Старый токен становится Used; повтор старого отзывается вся family.
  public (string UserId, string Token)? Rotate(string? raw)
  {
    if (string.IsNullOrWhiteSpace(raw) || raw.Length > 256) return null;
    lock (gate)
    {
      if (!tokens.TryGetValue(Hash(raw), out var entry)) return null;
      if (entry.Used) { revoked.Add(entry.Family); return null; }
      if (revoked.Contains(entry.Family) || entry.Expires <= DateTime.UtcNow) return null;
      entry.Used = true;
      return (entry.UserId, NewToken(entry.UserId, entry.Family));
    }
  }
  // Отзывает family, к которой относится переданный токен.
  public void Revoke(string? raw)
  {
    if (string.IsNullOrWhiteSpace(raw) || raw.Length > 256) return;
    lock (gate)
      if (tokens.TryGetValue(Hash(raw), out var entry)) revoked.Add(entry.Family);
  }
}
