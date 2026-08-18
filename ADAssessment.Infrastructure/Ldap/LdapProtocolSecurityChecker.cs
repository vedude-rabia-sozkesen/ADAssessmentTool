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

            return new LdapProtocolSecuritySettings
            {
                DomainController = server,
                IsSigningEnforced = IsSigningEnforced(server),
                IsChannelBindingEnforced = IsChannelBindingEnforced(server)
            };
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
    }
}
