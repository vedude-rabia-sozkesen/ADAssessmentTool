using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.Infrastructure.Configuration
{
    /// <summary>
    /// Uygulama başladıktan SONRA, dashboard üzerinden girilen AD bağlantı ayarlarını
    /// (hangi AD, hangi hesap) bellekte tutan depo. Ortam değişkenlerinin (env var)
    /// aksine, uygulama çalışırken değiştirilebilir ve diske hiç yazılmaz - Zero Trust
    /// gereği, AD parolasının hiçbir zaman diskte kalıcı hale gelmemesi bilinçli bir
    /// tercihtir: uygulama yeniden başladığında bu ayar sıfırlanır, tekrar girilmesi gerekir.
    /// </summary>
    public interface IAdConnectionSettingsStore
    {
        /// <summary>Şu an aktif olan ayar, ya da hiç yapılandırılmadıysa null.</summary>
        LdapConnectionOptions? GetCurrent();

        void Set(LdapConnectionOptions options);

        void Clear();
    }
}
