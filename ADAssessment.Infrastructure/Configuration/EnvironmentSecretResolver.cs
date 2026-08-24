using System;
using System.Security.Cryptography;
using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.Infrastructure.Configuration
{
    /// <summary>
    /// Şifreleri ve bağlantı dizelerini Ortam Değişkenlerinden (Environment Variables)
    /// ve sistem gizli kasalarından çeken Zero Trust uyumlu resolver.
    /// </summary>
    public sealed class EnvironmentSecretResolver : ISecretResolver
    {
        private const int MinJwtSecretLength = 32;

        // Development ortamında env var tanımlı değilse üretilen rastgele değerler, bu
        // resolver örneğinin (Singleton olarak DI'a kaydedilmelidir) ömrü boyunca sabit
        // kalması için önbelleğe alınır. Aksi halde her Resolve çağrısında farklı bir
        // değer üretilir ve daha önce alınan token/parola geçersiz kalır.
        private readonly object _jwtCacheLock = new();
        private JwtSigningOptions? _cachedJwtOptions;

        private readonly object _credentialCacheLock = new();
        private ApiCredentialOptions? _cachedApiCredentials;

        private readonly IAdConnectionSettingsStore? _adConnectionSettingsStore;

        /// <summary>
        /// settingsStore opsiyoneldir - ConsoleApp gibi tüketiciler bunu hiç geçmeden
        /// (parametresiz) örnek oluşturmaya devam edebilir, tamamen eski (sadece env-var)
        /// davranışı korunur. WebAPI ise dashboard'dan girilen ayarları önceliklendirmek
        /// için gerçek, paylaşılan bir store örneği geçer.
        /// </summary>
        public EnvironmentSecretResolver(IAdConnectionSettingsStore? settingsStore = null)
        {
            _adConnectionSettingsStore = settingsStore;
        }

        public LdapConnectionOptions ResolveLdapOptions()
        {
            // Dashboard üzerinden arayüzden bir AD bağlantı ayarı girilmişse (bkz.
            // AdConnectionController), o ayar env var'lardan daima önceliklidir - kullanıcı
            // uygulamayı açtıktan sonra "hangi AD'ye bağlanmak istediğini" burada belirtmiş
            // demektir.
            var dynamicOptions = _adConnectionSettingsStore?.GetCurrent();
            if (dynamicOptions != null)
            {
                return dynamicOptions;
            }

            // Ortam Değişkenlerinden oku (Docker, Kubernetes, Production Server)
            string? envPath = Environment.GetEnvironmentVariable("AD_ASSESSMENT_LDAP_PATH");
            string? envUsername = Environment.GetEnvironmentVariable("AD_ASSESSMENT_USERNAME");
            string? envPassword = Environment.GetEnvironmentVariable("AD_ASSESSMENT_PASSWORD");
            string? envUseLdaps = Environment.GetEnvironmentVariable("AD_ASSESSMENT_USE_LDAPS");
            string? envAllowFallback = Environment.GetEnvironmentVariable("AD_ASSESSMENT_ALLOW_INSECURE_FALLBACK");

            bool useLdaps = string.IsNullOrEmpty(envUseLdaps) || !bool.TryParse(envUseLdaps, out bool parsed) || parsed;

            // Zero Trust: Sadece açıkça "true" set edilmişse Port 389 düşüşüne izin verilir.
            // Varsayılan (env var tanımsız/geçersiz) daima false'tur - fail-closed.
            bool allowInsecureFallback = bool.TryParse(envAllowFallback, out bool allowFallback) && allowFallback;

            return new LdapConnectionOptions
            {
                LdapPath = !string.IsNullOrWhiteSpace(envPath) ? envPath : "LDAPS://192.168.92.100:636/DC=lab,DC=local",
                Username = envUsername,
                Password = envPassword,
                UseLdaps = useLdaps,
                AllowUnsecureFallback = allowInsecureFallback
            };
        }

        public JwtSigningOptions ResolveJwtSigningOptions()
        {
            string? envKey = Environment.GetEnvironmentVariable("AD_ASSESSMENT_JWT_SECRET");

            if (!string.IsNullOrWhiteSpace(envKey) && envKey.Length >= MinJwtSecretLength)
            {
                return new JwtSigningOptions { Key = envKey };
            }

            if (IsDevelopmentEnvironment())
            {
                lock (_jwtCacheLock)
                {
                    if (_cachedJwtOptions != null)
                    {
                        return _cachedJwtOptions;
                    }

                    string devKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
                    Console.WriteLine("[!] [DEV UYARISI] AD_ASSESSMENT_JWT_SECRET tanımlı değil. " +
                        "Geliştirme oturumu için rastgele bir imzalama anahtarı üretildi (her başlatmada değişir, " +
                        "önceki token'lar geçersiz olur). Production'da bu değişken zorunludur.");
                    _cachedJwtOptions = new JwtSigningOptions { Key = devKey };
                    return _cachedJwtOptions;
                }
            }

            throw new InvalidOperationException(
                "ZERO TRUST UYARISI: AD_ASSESSMENT_JWT_SECRET ortam değişkeni tanımlı değil veya " +
                $"{MinJwtSecretLength} karakterden kısa. Production ortamında güçlü (>= {MinJwtSecretLength} " +
                "karakter) bir imzalama anahtarı zorunludur.");
        }

        public ApiCredentialOptions ResolveApiCredentials()
        {
            string? envUsername = Environment.GetEnvironmentVariable("AD_ASSESSMENT_API_USERNAME");
            string? envPasswordHash = Environment.GetEnvironmentVariable("AD_ASSESSMENT_API_PASSWORD_HASH");

            if (!string.IsNullOrWhiteSpace(envUsername) && !string.IsNullOrWhiteSpace(envPasswordHash))
            {
                return new ApiCredentialOptions { Username = envUsername, PasswordHash = envPasswordHash };
            }

            if (IsDevelopmentEnvironment())
            {
                lock (_credentialCacheLock)
                {
                    if (_cachedApiCredentials != null)
                    {
                        return _cachedApiCredentials;
                    }

                    string devUsername = "devadmin";
                    string devPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(12));
                    string devPasswordHash = PasswordHasher.Hash(devPassword);

                    Console.WriteLine("[!] [DEV UYARISI] AD_ASSESSMENT_API_USERNAME/AD_ASSESSMENT_API_PASSWORD_HASH " +
                        "tanımlı değil. Geliştirme oturumu için otomatik kimlik bilgisi üretildi:");
                    Console.WriteLine($"    Kullanıcı adı : {devUsername}");
                    Console.WriteLine($"    Parola        : {devPassword}");
                    Console.WriteLine("    Bu bilgiler bu uygulama oturumu boyunca geçerlidir ve tekrar gösterilmeyecektir.");

                    _cachedApiCredentials = new ApiCredentialOptions { Username = devUsername, PasswordHash = devPasswordHash };
                    return _cachedApiCredentials;
                }
            }

            throw new InvalidOperationException(
                "ZERO TRUST UYARISI: AD_ASSESSMENT_API_USERNAME ve AD_ASSESSMENT_API_PASSWORD_HASH ortam " +
                "değişkenleri Production ortamında zorunludur. Hash üretmek için " +
                "'ADAssessment.ConsoleApp.exe hash-password' komutunu kullanın.");
        }

        private static bool IsDevelopmentEnvironment()
        {
            string? env = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            return string.Equals(env, "Development", StringComparison.OrdinalIgnoreCase);
        }
    }
}
