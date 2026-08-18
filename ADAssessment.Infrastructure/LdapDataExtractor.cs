using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Reflection;
using System.Security;
using System.Security.AccessControl;
using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Ldap
{
    /// <summary>
    /// Active Directory'den salt-okunur (read-only) olarak kullanıcı hesabı verilerini
    /// çeken altyapı sınıfı. Zero Trust LDAPS (Port 636), gMSA ve şifreli kimlik doğrulama destekler.
    /// </summary>
    public sealed class LdapDataExtractor : ILdapDataExtractor
    {
        private const int DefaultPageSize = 500;

        // AD-DS'in "User-Change-Password" kontrol erişim hakkının well-known GUID'i.
        // Bkz. MS-ADTS 5.1.3.2.1 - "Cannot change password" ayarı bu hakkın Everyone/SELF
        // için Deny edilmesiyle uygulanır, userAccountControl bitiyle DEĞİL.
        private static readonly Guid ChangePasswordRightGuid = new("ab721a53-1e2f-11d0-9819-00aa0040529b");
        private const string EveryoneSid = "S-1-1-0";
        private const string SelfSid = "S-1-5-10";

        private const string UserFilter = "(&(objectCategory=person)(objectClass=user))";
        private const string ComputerFilter = "(objectCategory=computer)";

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
            "servicePrincipalName",
            "nTSecurityDescriptor"
        };

        private static readonly string[] ComputerProperties =
        {
            "sAMAccountName",
            "distinguishedName",
            "operatingSystem",
            "userAccountControl",
            "pwdLastSet",
            "lastLogonTimestamp"
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
        /// Zero Trust ilkesi gereği AllowUnsecureFallback varsayılan olarak false'tur;
        /// lab/test ortamı için Port 389 düşüşü gerekiyorsa LdapConnectionOptions tabanlı
        /// kurucu metod ile açıkça true set edilmelidir.
        /// </summary>
        public LdapDataExtractor(string ldapPath, string? username = null, string? password = null, bool useLdaps = false)
            : this(new LdapConnectionOptions
            {
                LdapPath = ldapPath,
                Username = username,
                Password = password,
                UseLdaps = useLdaps || ldapPath.Contains(":636"),
                AllowUnsecureFallback = false
            })
        {
        }

        /// <summary>
        /// AD üzerindeki kullanıcı nesnelerini çeker ve Core katmanındaki modele haritalar.
        /// </summary>
        public IReadOnlyList<AdUserAccount> GetActiveUsers()
        {
            return ExecuteWithLdapsFallback(
                (path, useLdaps) => Query(path, useLdaps, UserFilter, UserProperties, MapToUserAccount, includeDacl: true));
        }

        /// <summary>
        /// AD üzerindeki bilgisayar (computer) nesnelerini çeker ve Core katmanındaki modele
        /// haritalar. Kullanıcı sorgusuyla aynı bağlantı/Zero Trust/fallback mantığını
        /// (ExecuteWithLdapsFallback) paylaşır - sadece filtre, öznitelik listesi ve
        /// haritalama fonksiyonu farklıdır.
        /// </summary>
        public IReadOnlyList<AdComputerAccount> GetComputerAccounts()
        {
            return ExecuteWithLdapsFallback(
                (path, useLdaps) => Query(path, useLdaps, ComputerFilter, ComputerProperties, MapToComputerAccount, includeDacl: false));
        }

        /// <summary>
        /// Zero Trust LDAPS denetimini ve (lab/test ortamları için) şifresiz LDAP'a düşüş
        /// mantığını, sorgulanan nesne tipinden (kullanıcı/bilgisayar) bağımsız olarak tek
        /// bir yerde uygular - iki ayrı sorgu yolunun bu güvenlik mantığında birbirinden
        /// sapmasını (biri düzeltilip diğerinin unutulmasını) engeller.
        /// </summary>
        private IReadOnlyList<T> ExecuteWithLdapsFallback<T>(Func<string, bool, IReadOnlyList<T>> queryFunc)
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
                return queryFunc(formattedPath, _options.UseLdaps || formattedPath.Contains(":636"));
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

                return queryFunc(fallbackPath, false);
            }
        }

        private IReadOnlyList<T> Query<T>(string path, bool useLdaps, string filter, string[] properties, Func<SearchResult, T> mapper, bool includeDacl)
        {
            var results = new List<T>();
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
                Filter = filter,
                PageSize = _options.PageSize > 0 ? _options.PageSize : DefaultPageSize,
                SearchScope = SearchScope.Subtree,
                CacheResults = false,
                // Referral takibi kapalı: bir saldırgan/rogue DC'nin referral yanıtıyla sorguyu
                // kendi kontrolündeki bir sunucuya yönlendirmesi (referral injection) riskini
                // ortadan kaldırır. Araç tek domain'i taradığından referral'a ihtiyaç yoktur.
                ReferralChasing = ReferralChasingOption.None
            };

            if (includeDacl)
            {
                // "Cannot change password" ayarını ACL üzerinden tespit edebilmek için DACL'i
                // de aynı paged search içinde (ekstra bağlantı gerektirmeden) çekiyoruz.
                // Bilgisayar sorgusunda bu bilgiye ihtiyaç yok, gereksiz yere istenmiyor.
                searcher.SecurityMasks = SecurityMasks.Dacl;
            }

            foreach (var propertyName in properties)
            {
                searcher.PropertiesToLoad.Add(propertyName);
            }

            using SearchResultCollection searchResults = searcher.FindAll();

            foreach (SearchResult result in searchResults)
            {
                results.Add(mapper(result));
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
                ServicePrincipalNames = spnList,
                IsCannotChangePassword = IsCannotChangePasswordViaAcl(result)
            };
        }

        private static AdComputerAccount MapToComputerAccount(SearchResult result)
        {
            return new AdComputerAccount
            {
                SamAccountName = GetString(result, "sAMAccountName"),
                DistinguishedName = GetString(result, "distinguishedName"),
                OperatingSystem = GetString(result, "operatingSystem"),
                UserAccountControl = GetInt(result, "userAccountControl"),
                PasswordLastSet = GetFileTimeAsDateTime(result, "pwdLastSet"),
                LastLogonTimestamp = GetFileTimeAsDateTime(result, "lastLogonTimestamp")
            };
        }

        /// <summary>
        /// "Kullanıcı parolasını değiştiremez" kısıtlamasının gerçek uygulanma şekli olan
        /// ACL kontrolü. Nesnenin DACL'inde Everyone veya NT AUTHORITY\SELF için
        /// "Change Password" özel hakkının Deny edildiği bir ACE var mı diye bakar.
        /// ACL okunamazsa (yetki/parse hatası) güvenli tarafta kalınır: kısıtlama yok varsayılır.
        /// </summary>
        private static bool IsCannotChangePasswordViaAcl(SearchResult result)
        {
            if (!result.Properties.Contains("ntsecuritydescriptor") || result.Properties["ntsecuritydescriptor"].Count == 0)
            {
                return false;
            }

            try
            {
                var sdBytes = (byte[])result.Properties["ntsecuritydescriptor"][0];
                var rawSecurityDescriptor = new RawSecurityDescriptor(sdBytes, 0);
                RawAcl? dacl = rawSecurityDescriptor.DiscretionaryAcl;
                if (dacl == null) return false;

                foreach (GenericAce ace in dacl)
                {
                    if (ace is not ObjectAce objectAce) continue;
                    if (objectAce.AceType != AceType.AccessDeniedObject) continue;
                    if ((objectAce.ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) == 0) continue;
                    if (objectAce.ObjectAceType != ChangePasswordRightGuid) continue;

                    string sid = objectAce.SecurityIdentifier.Value;
                    if (sid == SelfSid || sid == EveryoneSid)
                    {
                        return true;
                    }
                }
            }
            catch
            {
                return false;
            }

            return false;
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