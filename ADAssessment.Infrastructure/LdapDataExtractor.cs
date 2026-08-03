using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Reflection;
using System.Security;
using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Ldap
{
    /// <summary>
    /// Active Directory'den salt-okunur (read-only) olarak kullanıcı hesabı verilerini
    /// çeken altyapı sınıfı. Zero Trust LDAPS (Port 636), gMSA ve şifreli kimlik doğrulama destekler.
    /// </summary>
    public sealed class LdapDataExtractor
    {
        private const int DefaultPageSize = 500;

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
            "servicePrincipalName"
        };

        private readonly LdapConnectionOptions _options;

        /// <summary>
        /// Konfigürasyon nesnesi ile LDAPS ve gMSA uyumlu kurucu metod.
        /// </summary>
        public LdapDataExtractor(LdapConnectionOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
            if (string.IsNullOrWhiteSpace(options.LdapPath))
            {
                throw new ArgumentException("LDAP path boş olamaz.", nameof(options));
            }
            _options = options;
        }

        /// <summary>
        /// Geriye dönük uyumluluk sağlayan aşırı yüklenmiş kurucu metod.
        /// Lab/Test ortamlarında geriye dönük uyumluluk için AllowUnsecureFallback=true set eder.
        /// </summary>
        public LdapDataExtractor(string ldapPath, string? username = null, string? password = null, bool useLdaps = false)
            : this(new LdapConnectionOptions
            {
                LdapPath = ldapPath,
                Username = username,
                Password = password,
                UseLdaps = useLdaps || ldapPath.Contains(":636"),
                AllowUnsecureFallback = true
            })
        {
        }

        /// <summary>
        /// AD üzerindeki kullanıcı nesnelerini çeker ve Core katmanındaki modele haritalar.
        /// </summary>
        public IReadOnlyList<AdUserAccount> GetActiveUsers()
        {
            string formattedPath = _options.GetFormattedLdapPath();

            // Zero Trust Güvenlik Denetimi:
            // Eğer LDAPS kullanılmıyorsa ve Unsecure Fallback kapalıysa bağlantıyı reddet!
            if (!_options.UseLdaps && !_options.AllowUnsecureFallback && !formattedPath.Contains(":636"))
            {
                throw new SecurityException(
                    "ZERO TRUST UYARISI: Şifresiz LDAP (Port 389) üzerinden bağlantı reddedildi. " +
                    "Bağlantıyı LDAPS (Port 636) olarak yapılandırın veya test ortamı için AllowUnsecureFallback=true yapın.");
            }

            try
            {
                return QueryDirectory(formattedPath, _options.UseLdaps || formattedPath.Contains(":636"));
            }
            catch (Exception ex) when (_options.AllowUnsecureFallback && (_options.UseLdaps || formattedPath.Contains(":636")))
            {
                Console.WriteLine($"[*] [LDAPS UYARISI] Port 636 (SSL) bağlantısı kurulamadı ({ex.Message}). Fallback: Kerberos Sealing (Port 389) deneniyor...");

                string fallbackPath = _options.LdapPath;
                if (fallbackPath.StartsWith("LDAPS://", StringComparison.OrdinalIgnoreCase))
                {
                    fallbackPath = "LDAP://" + fallbackPath.Substring(8);
                }
                fallbackPath = fallbackPath.Replace(":636", "");

                return QueryDirectory(fallbackPath, useLdaps: false);
            }
        }

        private IReadOnlyList<AdUserAccount> QueryDirectory(string path, bool useLdaps)
        {
            var results = new List<AdUserAccount>();
            var authType = AuthenticationTypes.Secure;
            if (useLdaps)
            {
                authType |= AuthenticationTypes.SecureSocketsLayer;
            }
            else
            {
                authType |= AuthenticationTypes.Sealing; // Kerberos Sealing
            }

            using var rootEntry = string.IsNullOrEmpty(_options.Username)
                ? new DirectoryEntry(path) { AuthenticationType = authType }
                : new DirectoryEntry(path, _options.Username, _options.Password, authType);

            using var searcher = new DirectorySearcher(rootEntry)
            {
                Filter = "(&(objectCategory=person)(objectClass=user))",
                PageSize = _options.PageSize > 0 ? _options.PageSize : DefaultPageSize,
                SearchScope = SearchScope.Subtree,
                CacheResults = false,
                ReferralChasing = ReferralChasingOption.All
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
                MemberOfCount = result.Properties.Contains("memberOf") ? result.Properties["memberOf"].Count : 0,
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