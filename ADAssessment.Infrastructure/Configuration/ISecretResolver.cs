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
    }
}
