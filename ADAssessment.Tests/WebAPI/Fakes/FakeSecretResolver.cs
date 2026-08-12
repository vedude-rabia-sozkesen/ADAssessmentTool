using System;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.Tests.WebAPI.Fakes
{
    /// <summary>
    /// ISecretResolver'ın test projesindeki elle yazılmış sahte implementasyonu.
    /// Harici bir mocking kütüphanesi (Moq/NSubstitute) eklemeden controller'ları
    /// izole test edebilmek için kullanılır.
    /// </summary>
    internal sealed class FakeSecretResolver : ISecretResolver
    {
        public string Username { get; }
        public string PlainPassword { get; }
        public string JwtKey { get; }

        public FakeSecretResolver(string username = "testuser", string plainPassword = "TestPassword!1", string? jwtKey = null)
        {
            Username = username;
            PlainPassword = plainPassword;
            JwtKey = jwtKey ?? "UnitTestOnlyFixedSigningKeyThatIs32PlusChars!";
        }

        public LdapConnectionOptions ResolveLdapOptions() =>
            throw new NotSupportedException("AssessmentController/AuthController testlerinde LDAP options kullanılmıyor.");

        public JwtSigningOptions ResolveJwtSigningOptions() => new() { Key = JwtKey };

        public ApiCredentialOptions ResolveApiCredentials() => new()
        {
            Username = Username,
            PasswordHash = PasswordHasher.Hash(PlainPassword)
        };
    }
}
