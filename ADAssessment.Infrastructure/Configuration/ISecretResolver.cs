using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.Infrastructure.Configuration
{
    /// <summary>
    /// Şifreler ve bağlantı bilgilerinin kod içinde hardcoded kalmasını önleyen,
    /// Ortam Değişkenleri (Environment Variables) ve güvenli depolardan okuma yapan arayüz.
    /// </summary>
    public interface ISecretResolver
    {
        /// <summary>
        /// Ortam değişkenlerinden veya konfigürasyondan LdapConnectionOptions nesnesini çözer.
        /// </summary>
        LdapConnectionOptions ResolveLdapOptions();

        /// <summary>
        /// WebAPI JWT token imzalama anahtarını çözer. Production'da anahtar
        /// tanımlı değilse çağıran taraf başlatmayı durdurmalıdır (fail-closed).
        /// </summary>
        JwtSigningOptions ResolveJwtSigningOptions();

        /// <summary>
        /// WebAPI giriş uç noktasının doğrulayacağı servis hesabı bilgilerini çözer.
        /// Parola daima hash olarak döner, düz metin hiçbir zaman taşınmaz.
        /// </summary>
        ApiCredentialOptions ResolveApiCredentials();
    }
}
