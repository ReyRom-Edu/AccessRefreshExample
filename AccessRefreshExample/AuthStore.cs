using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

record User(string Id, string Name, string Role, string Password);

sealed class AuthStore
{
  private sealed record RefreshEntry(string UserId, DateTime Expires);

  private readonly User[] users;
  private readonly Dictionary<string, RefreshEntry> refreshTokens = [];
  private readonly object gate = new();

  public AuthStore()
  {
    users =
    [
        new("1", "student", "Student", "Student-123!"),
            new("2", "teacher", "Teacher", "Teacher-123!")
    ];
  }

  public User? Find(string id) => users.FirstOrDefault(user => user.Id == id);

  public User? Validate(string? name, string? password)
  {
    if (string.IsNullOrWhiteSpace(name) || string.IsNullOrEmpty(password)) return null;

    var user = users.FirstOrDefault(item => item.Name == name);
    return user is not null && user.Password == password
        ? user
        : null;
  }

  public string Issue(string userId)
  {
    lock (gate) return NewRefreshToken(userId);
  }

  public (string UserId, string Token)? Rotate(string? rawToken)
  {
    if (string.IsNullOrWhiteSpace(rawToken) || rawToken.Length > 256) return null;

    lock (gate)
    {
      if (!refreshTokens.Remove(rawToken, out var entry) || entry.Expires <= DateTime.UtcNow)
        return null;

      return (entry.UserId, NewRefreshToken(entry.UserId));
    }
  }

  public void Revoke(string? rawToken)
  {
    if (string.IsNullOrWhiteSpace(rawToken) || rawToken.Length > 256) return;

    lock (gate)
      refreshTokens.Remove(rawToken);
  }

  private string NewRefreshToken(string userId)
  {
    var token = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
    refreshTokens.Add(token, new(userId, DateTime.UtcNow.AddDays(7)));
    return token;
  }
}
