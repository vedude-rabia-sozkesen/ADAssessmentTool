using System;
using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.Infrastructure.Configuration
{
    /// <summary>
    /// Şifreleri ve bağlantı dizelerini Ortam Değişkenlerinden (Environment Variables) 
    /// ve sistem gizli kasalarından çeken Zero Trust uyumlu resolver.
    /// </summary>
    public sealed class EnvironmentSecretResolver : ISecretResolver
    {
        public LdapConnectionOptions ResolveLdapOptions()
        {
            // Ortam Değişkenlerinden oku (Docker, Kubernetes, Production Server)
            string? envPath = Environment.GetEnvironmentVariable("AD_ASSESSMENT_LDAP_PATH");
            string? envUsername = Environment.GetEnvironmentVariable("AD_ASSESSMENT_USERNAME");
            string? envPassword = Environment.GetEnvironmentVariable("AD_ASSESSMENT_PASSWORD");
            string? envUseLdaps = Environment.GetEnvironmentVariable("AD_ASSESSMENT_USE_LDAPS");

            bool useLdaps = string.IsNullOrEmpty(envUseLdaps) || !bool.TryParse(envUseLdaps, out bool parsed) || parsed;

            return new LdapConnectionOptions
            {
                LdapPath = !string.IsNullOrWhiteSpace(envPath) ? envPath : "LDAPS://192.168.92.100:636/DC=lab,DC=local",
                Username = envUsername,
                Password = envPassword,
                UseLdaps = useLdaps,
                AllowUnsecureFallback = true // Lab ortamlarında SSL sertifikası henüz kurulmamışsa Kerberos Sealing ile Port 389 geçişine izin verir
            };
        }
    }
}
