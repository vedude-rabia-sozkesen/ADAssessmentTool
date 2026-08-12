namespace ADAssessment.Infrastructure.Configuration
{
    /// <summary>
    /// WebAPI giriş uç noktasının doğrulama yapacağı tekil servis hesabını temsil eder.
    /// Parola hiçbir zaman düz metin olarak taşınmaz, sadece PBKDF2 hash'i tutulur.
    /// </summary>
    public sealed class ApiCredentialOptions
    {
        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
    }
}
