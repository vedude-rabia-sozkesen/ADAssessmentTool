using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.Infrastructure.Sysvol
{
    /// <summary>
    /// SYSVOL paylaşımından ("\\sunucu\SYSVOL\domain\Policies\{GUID}\...") GPO güvenlik
    /// ayarlarını salt-okunur olarak çeken altyapı sınıfı. LDAP bağlantı bilgilerini
    /// (LdapConnectionOptions) yeniden kullanır - ayrı env var gerekmez, aynı servis
    /// hesabı hem LDAP hem SYSVOL için kullanılır.
    ///
    /// .NET'in dosya API'leri alternatif kimlik bilgisiyle UNC paylaşımına bağlanmayı
    /// desteklemediğinden (DirectoryEntry'nin aksine), Windows'un WNetAddConnection2
    /// API'si (P/Invoke - net use'ın arka planda yaptığı şey, ek NuGet paketi gerektirmez)
    /// ile açık bir ağ bağlantısı kurulur ve iş bitince mutlaka kapatılır.
    /// </summary>
    public sealed class SysvolDataExtractor : ISysvolDataExtractor
    {
        // Her Active Directory domain'inde aynı, sabit ve herkese açık bir GUID'e
        // sahip olan Default Domain Policy - domain-geneli parola/kilitleme
        // politikasının asıl kaynağı budur.
        private const string DefaultDomainPolicyGuid = "{31B2F340-016D-11D2-945F-00C04FB984F9}";
        private const string GptTmplRelativePath = @"MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf";

        private readonly LdapConnectionOptions _options;

        public SysvolDataExtractor(LdapConnectionOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            _options = options;
        }

        public IReadOnlyList<GroupPolicySecuritySettings> GetSecuritySettings()
        {
            (string server, string domainDnsName) = ParseServerAndDomain(_options.LdapPath);
            string sysvolShareRoot = $@"\\{server}\SYSVOL";
            string policiesPath = $@"{sysvolShareRoot}\{domainDnsName}\Policies";

            bool connected = false;
            try
            {
                if (!string.IsNullOrEmpty(_options.Username))
                {
                    connected = ConnectShare(sysvolShareRoot, _options.Username, _options.Password);
                }

                var results = new List<GroupPolicySecuritySettings>();

                if (!Directory.Exists(policiesPath))
                {
                    return results;
                }

                foreach (string gpoFolder in Directory.GetDirectories(policiesPath))
                {
                    string gpoGuid = Path.GetFileName(gpoFolder);
                    string gptTmplPath = Path.Combine(gpoFolder, GptTmplRelativePath);

                    if (!File.Exists(gptTmplPath))
                    {
                        continue;
                    }

                    string content = File.ReadAllText(gptTmplPath);
                    string gpoName = string.Equals(gpoGuid, DefaultDomainPolicyGuid, StringComparison.OrdinalIgnoreCase)
                        ? "Default Domain Policy"
                        : gpoGuid;

                    results.Add(GptTmplParser.Parse(content, gpoName, gpoGuid));
                }

                return results;
            }
            finally
            {
                if (connected)
                {
                    DisconnectShare(sysvolShareRoot);
                }
            }
        }

        /// <summary>
        /// LDAP path'inden ("LDAP://192.168.92.100/DC=lab,DC=local") SYSVOL erişimi
        /// için gereken sunucu adresini ve domain DNS adını ("lab.local") çıkarır.
        /// Public: saf/I-O'suz bir yardımcı fonksiyon olduğundan doğrudan birim
        /// testiyle doğrulanabilir.
        /// </summary>
        public static (string Server, string DomainDnsName) ParseServerAndDomain(string ldapPath)
        {
            string withoutScheme = ldapPath
                .Replace("LDAPS://", string.Empty, StringComparison.OrdinalIgnoreCase)
                .Replace("LDAP://", string.Empty, StringComparison.OrdinalIgnoreCase);

            int slashIndex = withoutScheme.IndexOf('/');
            string hostPart = slashIndex >= 0 ? withoutScheme[..slashIndex] : withoutScheme;
            string dnPart = slashIndex >= 0 ? withoutScheme[(slashIndex + 1)..] : string.Empty;

            // Host kısmındaki olası ":636"/":389" port bilgisini at.
            int colonIndex = hostPart.IndexOf(':');
            string server = colonIndex >= 0 ? hostPart[..colonIndex] : hostPart;

            var domainComponents = new List<string>();
            foreach (string component in dnPart.Split(','))
            {
                string trimmed = component.Trim();
                if (trimmed.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                {
                    domainComponents.Add(trimmed[3..]);
                }
            }

            string domainDnsName = string.Join('.', domainComponents);
            return (server, domainDnsName);
        }

        private static bool ConnectShare(string uncPath, string username, string? password)
        {
            var resource = new NETRESOURCE
            {
                dwType = ResourceTypeDisk,
                lpRemoteName = uncPath
            };

            int result = WNetAddConnection2(ref resource, password ?? string.Empty, username, 0);

            // ERROR_ALREADY_ASSIGNED / ERROR_SESSION_CREDENTIAL_CONFLICT: aynı sunucuya
            // zaten (aynı kimlikle) bağlıysa hata sayılmaz, mevcut bağlantı kullanılır.
            if (result != 0 && result != ErrorAlreadyAssigned)
            {
                throw new IOException($"SYSVOL paylaşımına bağlanılamadı ({uncPath}). Windows hata kodu: {result}");
            }

            return result == 0;
        }

        private static void DisconnectShare(string uncPath)
        {
            // force:true - bağlı dosya tanıtıcısı kalmış olsa bile bağlantıyı kapat.
            // Bu adımın atlanması, aynı sunucuya farklı kimlik bilgileriyle yapılan
            // sonraki bağlantı denemelerinin "1219 - birden fazla kimlik" hatasıyla
            // başarısız olmasına yol açar.
            WNetCancelConnection2(uncPath, 0, true);
        }

        private const int ResourceTypeDisk = 0x00000001;
        private const int ErrorAlreadyAssigned = 85;

        [StructLayout(LayoutKind.Sequential)]
        private struct NETRESOURCE
        {
            public int dwScope;
            public int dwType;
            public int dwDisplayType;
            public int dwUsage;
            public string? lpLocalName;
            public string? lpRemoteName;
            public string? lpComment;
            public string? lpProvider;
        }

        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        private static extern int WNetAddConnection2(ref NETRESOURCE netResource, string password, string username, int flags);

        [DllImport("mpr.dll", CharSet = CharSet.Unicode)]
        private static extern int WNetCancelConnection2(string name, int flags, bool force);
    }
}
