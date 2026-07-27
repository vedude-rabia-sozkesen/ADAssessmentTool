using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Reflection;
using ADAssessment.Core; // Az önce oluşturduğumuz veri modeline erişim sağladık (Loose Coupling)

namespace ADAssessment.Infrastructure.Ldap
{
    /// <summary>
    /// Active Directory'den salt-okunur (read-only) olarak kullanıcı hesabı verilerini
    /// çeken altyapı sınıfı. Bellek dostu ve sayfalı (paginated) mimari kullanır.
    /// </summary> // 👈 BURASI DÜZELTİLDİ
    public sealed class LdapDataExtractor
    {
        // 4000+ kullanıcılı sistemlerde RAM patlamasını önlemek için sayfa boyutu sınırı
        private const int DefaultPageSize = 500;

        // Ağ trafiğini ve RAM allocation'ı minimize etmek için sadece analizde kullanılacak öznitelikler çekilir
        private static readonly string[] UserProperties =
        {
            "sAMAccountName",
            "distinguishedName",
            "displayName",
            "userAccountControl",
            "pwdLastSet",
            "lastLogonTimestamp",
            "adminCount",
            "memberOf",
            "servicePrincipalName" //kerberoasting
        };

        private readonly string _ldapPath;

        public LdapDataExtractor(string ldapPath)
        {
            if (string.IsNullOrWhiteSpace(ldapPath))
            {
                throw new ArgumentException("LDAP path boş olamaz.", nameof(ldapPath));
            }
            _ldapPath = ldapPath;
        }

        /// AD üzerindeki kullanıcı nesnelerini çeker ve Core katmanındaki modele haritalar (Map eder).
        public IReadOnlyList<AdUserAccount> GetActiveUsers()
        {
            var results = new List<AdUserAccount>();

            // using var yapısı: İşlem bittiği an bellekten (RAM) anında temizlenir (Anti-Memory Leak)
            using var rootEntry = new DirectoryEntry(_ldapPath)
            {
                AuthenticationType = AuthenticationTypes.Secure | AuthenticationTypes.Sealing
            };

            using var searcher = new DirectorySearcher(rootEntry)
            {
                Filter = "(&(objectCategory=person)(objectClass=user))",
                PageSize = DefaultPageSize,
                SearchScope = SearchScope.Subtree,
                CacheResults = false,             // Sonuçları RAM'de önbelleğe almayarak sunucu yükünü hafifletir
                ReferralChasing = ReferralChasingOption.None
            };

            foreach (var propertyName in UserProperties)
            {
                searcher.PropertiesToLoad.Add(propertyName);
            }

            using SearchResultCollection searchResults = searcher.FindAll();

            foreach (SearchResult result in searchResults)
            {
                results.Add(MapToUserAccount(result));
            }

            return results;
        }

        private static AdUserAccount MapToUserAccount(SearchResult result)
        {
            //servicePrincipalName çoklu değer (multi-valued) içeren bir alandır, listeye çeviriyoruz
            var spnList = new List<string>();
            if (result.Properties.Contains("servicePrincipalName"))
            {
                foreach (object spn in result.Properties["servicePrincipalName"])
                {
                    if (spn != null) spnList.Add(spn.ToString()!);
                }
            }
            return new AdUserAccount
            {
                SamAccountName = GetString(result, "sAMAccountName"),
                DistinguishedName = GetString(result, "distinguishedName"),
                DisplayName = GetString(result, "displayName"),
                UserAccountControl = GetInt(result, "userAccountControl"),
                PasswordLastSet = GetFileTimeAsDateTime(result, "pwdLastSet"),
                LastLogonTimestamp = GetFileTimeAsDateTime(result, "lastLogonTimestamp"),
                IsAdminCountSet = GetInt(result, "adminCount") == 1,
                MemberOfCount = result.Properties.Contains("memberOf") ? result.Properties["memberOf"].Count : 0, // 👈 BURAYA VİRGÜL EKLENDİ
                ServicePrincipalNames = spnList
            };
        }

        private static string GetString(SearchResult result, string propertyName)
        {
            if (result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0)
            {
                return result.Properties[propertyName][0]?.ToString() ?? string.Empty;
            }
            return string.Empty;
        }

        private static int GetInt(SearchResult result, string propertyName)
        {
            if (result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0)
            {
                return Convert.ToInt32(result.Properties[propertyName][0]);
            }
            return 0;
        }

        private static DateTime? GetFileTimeAsDateTime(SearchResult result, string propertyName)
        {
            if (!result.Properties.Contains(propertyName) || result.Properties[propertyName].Count == 0)
            {
                return null;
            }

            object rawValue = result.Properties[propertyName][0];
            long fileTime;

            if (rawValue is long directValue)
            {
                fileTime = directValue;
            }
            else
            {
                try
                {
                    // Active Directory'nin Integer8 (LargeInteger) COM nesnesini çözmek için Reflection kullanımı
                    Type comType = rawValue.GetType();
                    int highPart = (int)comType.InvokeMember("HighPart", BindingFlags.GetProperty, null, rawValue, null)!;
                    int lowPart = (int)comType.InvokeMember("LowPart", BindingFlags.GetProperty, null, rawValue, null)!;
                    fileTime = ((long)highPart << 32) + (uint)lowPart;
                }
                catch
                {
                    return null;
                }
            }

            if (fileTime <= 0) return null;

            try
            {
                return DateTime.FromFileTimeUtc(fileTime);
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }
    }
}