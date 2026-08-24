using System;
using System.DirectoryServices.Protocols;
using System.Net;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Sysvol;

namespace ADAssessment.Infrastructure.Ldap
{
    /// <summary>
    /// Domain Controller'ın LDAP protokolü seviyesindeki güvenlik davranışını, gerçek bir
    /// bağlantı denemesiyle (LDAP özniteliği okuyarak değil) tespit eden altyapı sınıfı.
    /// System.DirectoryServices.Protocols kullanır (System.DirectoryServices/ADSI'nin COM
    /// katmanı yerine wldap32'ye daha doğrudan bağlanan alt seviye kütüphane - bu oturumda
    /// LDAPS hata ayıklamasında netleşen gerçek hata kodlarına burada da ihtiyaç var).
    /// </summary>
    public sealed class LdapProtocolSecurityChecker : ILdapProtocolSecurityChecker
    {
        // LDAP sonuç kodu 8 = strongerAuthRequired. DC, imzasız/şifresiz bir kanal
        // üzerinden gelen basit bind isteklerini bu kodla reddeder - kimlik bilgilerinin
        // geçerli olup olmadığına hiç bakılmaz, bağlantının GÜVENLİ OLMAMASI yeterlidir.
        private const int StrongerAuthRequiredResultCode = 8;

        private readonly LdapConnectionOptions _options;

        public LdapProtocolSecurityChecker(LdapConnectionOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            _options = options;
        }

        public LdapProtocolSecuritySettings CheckProtocolSecurity()
        {
            (string server, _) = SysvolDataExtractor.ParseServerAndDomain(_options.LdapPath);

            string baseDn = ExtractBaseDn(_options.LdapPath);

            return new LdapProtocolSecuritySettings
            {
                DomainController = server,
                IsSigningEnforced = IsSigningEnforced(server),
                IsChannelBindingEnforced = IsChannelBindingEnforced(server),
                IsAnonymousBindAllowed = IsAnonymousBindAllowed(server, baseDn)
            };
        }

        /// <summary>
        /// LDAP path'inden ("LDAP://192.0.2.1/DC=contoso,DC=local") arama tabanı
        /// (base DN, "DC=contoso,DC=local") kısmını çıkarır - SysvolDataExtractor.
        /// ParseServerAndDomain'in nokta ayraçlı ("contoso.local") formu döndürmesinin
        /// aksine, burada LDAP arama isteğine doğrudan verilebilecek DN formu gerekiyor.
        /// Public: saf/I-O'suz bir yardımcı fonksiyon olduğundan doğrudan birim testiyle
        /// doğrulanabilir (bkz. SysvolDataExtractor.ParseServerAndDomain - aynı desen).
        /// </summary>
        public static string ExtractBaseDn(string ldapPath)
        {
            string withoutScheme = ldapPath
                .Replace("LDAPS://", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Replace("LDAP://", string.Empty, StringComparison.OrdinalIgnoreCase);

            int slashIndex = withoutScheme.IndexOf('/');
            return slashIndex >= 0 ? withoutScheme[(slashIndex + 1)..] : string.Empty;
        }

        /// <summary>
        /// Kasıtlı olarak GERÇEK OLMAYAN (var olmayan kullanıcı adı + rastgele üretilmiş
        /// şifre) kimlik bilgileriyle, düz (şifresiz/imzasız) port 389 üzerinden bir basit
        /// bind denemesi yapar. Amaç kimlik doğrulamayı BAŞARILI kılmak değil - DC'nin
        /// güvensiz kanalı reddedip reddetmediğini gözlemlemek. Bu tasarım sayesinde gerçek
        /// bir servis hesabı şifresi hiçbir zaman şifresiz ağda dolaşmaz.
        /// </summary>
        private static bool IsSigningEnforced(string server)
        {
            var identifier = new LdapDirectoryIdentifier(server, 389);
            var probeCredential = new NetworkCredential(
                "adassessment-probe-" + Guid.NewGuid().ToString("N")[..8],
                Guid.NewGuid().ToString());

            using var connection = new LdapConnection(identifier, probeCredential, AuthType.Basic);
            connection.SessionOptions.SecureSocketLayer = false;
            connection.SessionOptions.Sealing = false;
            connection.SessionOptions.Signing = false;
            connection.Timeout = TimeSpan.FromSeconds(5);

            try
            {
                connection.Bind();

                // Buraya kadar geldiyse (istisna atılmadıysa) rastgele üretilmiş kimlik
                // bilgileriyle bind "başarılı" sayılmış demektir ki bu normalde beklenmez;
                // yine de DC güvensiz kanalı reddetmediğinden imzalama zorunlu değil kabul edilir.
                return false;
            }
            catch (LdapException ex) when (ex.ErrorCode == StrongerAuthRequiredResultCode)
            {
                return true;
            }
            catch (LdapException)
            {
                // Örn. invalidCredentials (49) - DC bind isteğini normal şekilde
                // değerlendirdi (yani güvensiz kanalı reddetmedi), sadece kimlik
                // bilgileri (beklendiği gibi) geçersiz çıktı.
                return false;
            }
        }

        /// <summary>
        /// Aynı prensip, bu sefer LDAPS (port 636, TLS şifreli) üzerinden: kasıtlı olarak
        /// sahte kimlik bilgileriyle bind dener, ama Channel Binding Token (CBT) hiç
        /// eklemeden - System.DirectoryServices.Protocols'un CBT için yerleşik/kolay bir
        /// desteği olmadığından, normal bir bağlantı zaten bunu doğal olarak yapmıyor.
        /// DC "channel binding her zaman zorunlu" (LdapEnforceChannelBinding=2) ise, TLS
        /// zaten kurulmuş olsa bile bind'i CBT eksikliği yüzünden aynı strongerAuthRequired
        /// koduyla reddeder.
        /// </summary>
        private static bool IsChannelBindingEnforced(string server)
        {
            var identifier = new LdapDirectoryIdentifier(server, 636);
            var probeCredential = new NetworkCredential(
                "adassessment-probe-" + Guid.NewGuid().ToString("N")[..8],
                Guid.NewGuid().ToString());

            using var connection = new LdapConnection(identifier, probeCredential, AuthType.Basic);
            connection.SessionOptions.SecureSocketLayer = true;
            connection.Timeout = TimeSpan.FromSeconds(5);

            try
            {
                connection.Bind();
                return false;
            }
            catch (LdapException ex) when (ex.ErrorCode == StrongerAuthRequiredResultCode)
            {
                return true;
            }
            catch (LdapException)
            {
                return false;
            }
        }

        /// <summary>
        /// Anonim (kimlik doğrulamasız) bir bind dener, ama tek başına bunun başarılı
        /// olması yeterli sinyal değil - AD'nin RootDSE'si (dizin kök meta verisi) zaten
        /// tasarım gereği anonim erişime açıktır, bu bir zafiyet değildir. Asıl önemli
        /// olan, anonim oturumun domain'in KENDİ veri bölümünde gerçek nesneleri
        /// (kullanıcılar) arayabilmesi - bu yüzden RootDSE değil, doğrudan base DN
        /// içinde bir kullanıcı araması deneniyor.
        /// </summary>
        private static bool IsAnonymousBindAllowed(string server, string baseDn)
        {
            if (string.IsNullOrEmpty(baseDn))
            {
                return false;
            }

            var identifier = new LdapDirectoryIdentifier(server, 389);
            using var connection = new LdapConnection(identifier);
            connection.AuthType = AuthType.Anonymous;
            connection.SessionOptions.SecureSocketLayer = false;
            connection.Timeout = TimeSpan.FromSeconds(5);

            try
            {
                connection.Bind();

                var searchRequest = new SearchRequest(baseDn, "(objectClass=user)", SearchScope.Subtree, "sAMAccountName")
                {
                    SizeLimit = 1
                };
                var response = (SearchResponse)connection.SendRequest(searchRequest);
                return response.Entries.Count > 0;
            }
            catch (LdapException)
            {
                return false;
            }
            catch (DirectoryOperationException)
            {
                return false;
            }
        }
    }
}
