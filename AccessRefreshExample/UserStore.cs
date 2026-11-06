using Microsoft.AspNetCore.Identity;



// PasswordHash хранится только на сервере и не сериализуется в ответы.
record User(string Id, string Name, string Role, string PasswordHash);


sealed class UserStore
{
  private readonly PasswordHasher<string> hasher = new();
  private readonly User[] users;
  public UserStore()
  {
    users = [new("1", "student", "Student", hasher.HashPassword("student", "Student-123!")),
                 new("2", "teacher", "Teacher", hasher.HashPassword("teacher", "Teacher-123!"))];
  }
  public User? Find(string id) => users.FirstOrDefault(user => user.Id == id);
  // PasswordHasher сравнивает пароль с хешем, открытый пароль не хранится.
  public User? Validate(string? name, string? password)
  {
    if (string.IsNullOrWhiteSpace(name) || string.IsNullOrEmpty(password)) return null;
    var user = users.FirstOrDefault(user => user.Name == name);
    return user is not null && hasher.VerifyHashedPassword(user.Name, user.PasswordHash, password)
        != PasswordVerificationResult.Failed ? user : null;
  }
}
