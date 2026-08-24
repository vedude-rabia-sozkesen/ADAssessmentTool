using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.Infrastructure.Configuration
{
    /// <summary>
    /// IAdConnectionSettingsStore'un tek gerçek implementasyonu - basit, kilitli bir
    /// alan. AddSingleton olarak kaydedilir (uygulamanın tüm ömrü boyunca tek örnek,
    /// tıpkı EnvironmentSecretResolver'ın kendisi gibi), bu yüzden birden fazla eşzamanlı
    /// istek arasında paylaşılan durumu bir kilitle (EnvironmentSecretResolver'daki
    /// _jwtCacheLock/_credentialCacheLock ile aynı desen) korur.
    /// </summary>
    public sealed class InMemoryAdConnectionSettingsStore : IAdConnectionSettingsStore
    {
        private readonly object _lock = new();
        private LdapConnectionOptions? _current;

        public LdapConnectionOptions? GetCurrent()
        {
            lock (_lock)
            {
                return _current;
            }
        }

        public void Set(LdapConnectionOptions options)
        {
            lock (_lock)
            {
                _current = options;
            }
        }

        public void Clear()
        {
            lock (_lock)
            {
                _current = null;
            }
        }
    }
}
