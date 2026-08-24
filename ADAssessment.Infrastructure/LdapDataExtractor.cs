using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Reflection;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
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

        // DS-Replication-Get-Changes / DS-Replication-Get-Changes-All - MS-ADTS'te tanımlı,
        // "DCSync" saldırısının temelini oluşturan iki kontrol erişim hakkının well-known GUID'i.
        private static readonly Guid GetChangesRightGuid = new("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2");
        private static readonly Guid GetChangesAllRightGuid = new("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2");

        // DCSync haklarına varsayılan/beklenen şekilde sahip olan sabit (well-known) asıl
        // güvenlik prensipleri - domain'e göre değişmeyenler burada, domain'e özgü Domain
        // Admins (RID 512), Enterprise Admins (RID 519), Domain Controllers (RID 516) ve
        // Enterprise Read-only Domain Controllers (RID 498) ise domain SID'i öğrenildikten
        // sonra ayrıca eklenir. Canlı lab testinde RID 516/498'in unutulması gerçek bir
        // yanlış pozitife (false positive) yol açmıştı - normal DC'ler ve RODC'ler
        // varsayılan olarak bu hakların bir kısmına/tamamına sahiptir.
        private const string BuiltinAdministratorsSid = "S-1-5-32-544";
        private const string EnterpriseDomainControllersSid = "S-1-5-9";
        private const string LocalSystemSid = "S-1-5-18";

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
            "nTSecurityDescriptor",
            "sIDHistory",
            "msDS-SupportedEncryptionTypes"
        };

        private static readonly string[] ComputerProperties =
        {
            "sAMAccountName",
            "distinguishedName",
            "operatingSystem",
            "userAccountControl",
            "pwdLastSet",
            "lastLogonTimestamp",
            "msDS-AllowedToActOnBehalfOfOtherIdentity",
            "msDS-AllowedToDelegateTo",
            "ms-Mcs-AdmPwdExpirationTime",
            "msLAPS-PasswordExpirationTime"
        };

        private readonly LdapConnectionOptions _options;

        // Bu LdapDataExtractor örneğinin (DI'da AddScoped - yani tek bir tarama isteği
        // boyunca yaşar) LDAPS'in bu istekte çalışıp çalışmadığına dair öğrendiği bilgiyi
        // önbelleğe alır: null = henüz denenmedi, true = bu taramada zaten başarısız oldu
        // (tekrar deneme, doğrudan Port 389'a git), false = çalışıyor. Her yeni tarama
        // (yeni bir HTTP isteği = yeni bir örnek) LDAPS'i en az bir kez yeniden dener -
        // sadece AYNI tarama içindeki 6+ ayrı sorgunun (kullanıcılar, bilgisayarlar,
        // DCSync, functional level, forest özellikleri, trust'lar) HER BİRİNİN kendi
        // başarısız LDAPS denemesini beklemesi önlenir.
        private bool? _ldapsUnavailableThisScan;

        /// <summary>
        /// Konfigürasyon nesnesi ile LDAPS ve gMSA uyumlu kurucu metod. LdapPath boş
        /// olsa bile (ör. AD henüz dashboard'dan yapılandırılmamışsa) burada HATA
        /// FIRLATILMAZ - bilerek. WebAPI'de bu sınıf DI tarafından controller'ın kendi
        /// kurucu metodunda (constructor injection) inşa edilir; bu, controller'ın Execute
        /// eylem gövdesindeki try/catch'e HİÇ girmeden çalışır - burada fırlatılan bir hata
        /// kullanıcıya çirkin/yakalanmamış bir 500 sayfası olarak yansırdı (gerçekten
        /// yaşanmış bir regresyon). Bunun yerine boş/geçersiz ayar, ilk gerçek LDAP
        /// sorgusunda (GetActiveUsers vb.) doğal olarak başarısız olur - o noktada zaten
        /// her çağıran kendi try/catch'iyle bu hatayı temiz bir mesaja çeviriyor.
        /// </summary>
        public LdapDataExtractor(LdapConnectionOptions options)
        {
            ArgumentNullException.ThrowIfNull(options);
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
        /// Bağlantı ayarlarının (LDAP Path, kullanıcı adı, parola) gerçekten çalışıp
        /// çalışmadığını, GERÇEK bir veri sorgusu (kullanıcı/bilgisayar listesi vb.) hiç
        /// çekmeden doğrular - domain kökünü Base scope'ta, tek bir öznitelik isteyerek
        /// okur. AD Bağlantı Ayarları formunun "doğrulama ile bağlan" akışında
        /// (AdConnectionController/LdapConnectionTester) kullanılır. Kullanıcı/bilgisayar
        /// sorgularıyla AYNI ExecuteWithLdapsFallback mekanizmasını (Zero Trust denetimi +
        /// LDAPS/389 fallback) paylaştığından, testin sonucu gerçek bir taramanın
        /// yaşayacağı bağlantı davranışının birebir sadık bir provası olur.
        /// </summary>
        public bool TestConnection()
        {
            var results = ExecuteWithLdapsFallback<bool>((path, useLdaps) => QueryTestConnection(path, useLdaps));
            return results.Count > 0 && results[0];
        }

        private IReadOnlyList<bool> QueryTestConnection(string path, bool useLdaps)
        {
            var authType = AuthenticationTypes.Secure;
            authType |= useLdaps ? AuthenticationTypes.SecureSocketsLayer : AuthenticationTypes.Sealing;

            using var rootEntry = string.IsNullOrEmpty(_options.Username)
                ? new DirectoryEntry(path) { AuthenticationType = authType }
                : new DirectoryEntry(path, _options.Username, _options.Password, authType);

            using var searcher = new DirectorySearcher(rootEntry)
            {
                Filter = "(objectClass=*)",
                SearchScope = SearchScope.Base,
                ReferralChasing = ReferralChasingOption.None
            };
            searcher.PropertiesToLoad.Add("distinguishedName");

            SearchResult? result = searcher.FindOne();
            return new List<bool> { result != null };
        }

        /// <summary>
        /// Domain'in kök nesnesinin DACL'inde, DCSync haklarına (bkz. GetChangesRightGuid/
        /// GetChangesAllRightGuid) sahip, varsayılan olmayan asıl güvenlik prensiplerini
        /// tespit eder. Kullanıcı/bilgisayar sorgularından farklı olarak tek bir nesne
        /// (domain kökü) okunur, bu yüzden ExecuteWithLdapsFallback'in liste döndüren
        /// imzasına, tek elemanlı bir liste olarak uyarlanır.
        /// </summary>
        public DcSyncRightsSettings GetDcSyncRights()
        {
            var results = ExecuteWithLdapsFallback<DcSyncRightsSettings>(
                (path, useLdaps) => QueryDcSyncRights(path, useLdaps));

            return results.Count > 0 ? results[0] : new DcSyncRightsSettings();
        }

        private IReadOnlyList<DcSyncRightsSettings> QueryDcSyncRights(string path, bool useLdaps)
        {
            var authType = AuthenticationTypes.Secure;
            authType |= useLdaps ? AuthenticationTypes.SecureSocketsLayer : AuthenticationTypes.Sealing;

            using var rootEntry = string.IsNullOrEmpty(_options.Username)
                ? new DirectoryEntry(path) { AuthenticationType = authType }
                : new DirectoryEntry(path, _options.Username, _options.Password, authType);

            using var searcher = new DirectorySearcher(rootEntry)
            {
                Filter = "(objectClass=*)",
                SearchScope = SearchScope.Base,
                ReferralChasing = ReferralChasingOption.None,
                // Domain kökünün kendi DACL'ini (kimin replikasyon hakkı olduğunu) ve
                // objectSid'ini (domain'e özgü Domain Admins/Enterprise Admins SID'lerini
                // hesaplayabilmek için) okuyoruz.
                SecurityMasks = SecurityMasks.Dacl
            };
            searcher.PropertiesToLoad.Add("nTSecurityDescriptor");
            searcher.PropertiesToLoad.Add("objectSid");
            searcher.PropertiesToLoad.Add("distinguishedName");

            SearchResult? result = searcher.FindOne();
            if (result == null)
            {
                return Array.Empty<DcSyncRightsSettings>();
            }

            string domainDn = GetString(result, "distinguishedName");
            var unexpectedPrincipals = new List<string>();

            bool hasDacl = result.Properties.Contains("ntsecuritydescriptor") && result.Properties["ntsecuritydescriptor"].Count > 0;
            bool hasSid = result.Properties.Contains("objectSid") && result.Properties["objectSid"].Count > 0;

            if (hasDacl && hasSid)
            {
                string domainSidValue = new SecurityIdentifier((byte[])result.Properties["objectSid"][0], 0).Value;

                try
                {
                    var sdBytes = (byte[])result.Properties["ntsecuritydescriptor"][0];
                    var rawSecurityDescriptor = new RawSecurityDescriptor(sdBytes, 0);
                    RawAcl? dacl = rawSecurityDescriptor.DiscretionaryAcl;

                    if (dacl != null)
                    {
                        var foundSids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                        foreach (GenericAce ace in dacl)
                        {
                            if (ace is not ObjectAce objectAce) continue;
                            if (objectAce.AceType != AceType.AccessAllowedObject) continue;
                            if ((objectAce.ObjectAceFlags & ObjectAceFlags.ObjectAceTypePresent) == 0) continue;
                            if (objectAce.ObjectAceType != GetChangesRightGuid && objectAce.ObjectAceType != GetChangesAllRightGuid) continue;

                            string sidValue = objectAce.SecurityIdentifier.Value;
                            if (IsExpectedDcSyncPrincipal(sidValue, domainSidValue)) continue;

                            foundSids.Add(sidValue);
                        }

                        foreach (string sidValue in foundSids)
                        {
                            unexpectedPrincipals.Add(ResolvePrincipalName(sidValue));
                        }
                    }
                }
                catch
                {
                    // ACL ayrıştırılamazsa güvenli tarafta kalınır: hiçbir beklenmeyen
                    // prensip raporlanmaz (boş sonuç), tüm sorgu başarısız olmaz.
                }
            }

            return new List<DcSyncRightsSettings>
            {
                new DcSyncRightsSettings
                {
                    DomainDistinguishedName = domainDn,
                    UnexpectedPrincipals = unexpectedPrincipals
                }
            };
        }

        /// <summary>
        /// Domain kök nesnesinin msDS-Behavior-Version özniteliğini (Domain Fonksiyonel
        /// Seviyesi) okur. DCSync sorgusuyla (GetDcSyncRights) aynı nesneyi (domain kökü)
        /// hedefler ama farklı bir özniteliği okuduğundan ve tamamen bağımsız bir bulguya
        /// (eskimiş fonksiyonel seviye vs. beklenmeyen replikasyon hakkı) hizmet ettiğinden
        /// ayrı bir metod olarak tutulur - tek bir nesnenin tekrar okunması (küçük, Base-scope
        /// bir sorgu) ihmal edilebilir bir maliyettir.
        /// </summary>
        public DomainFunctionalLevelSettings GetDomainFunctionalLevel()
        {
            var results = ExecuteWithLdapsFallback<DomainFunctionalLevelSettings>(
                (path, useLdaps) => QueryDomainFunctionalLevel(path, useLdaps));

            return results.Count > 0 ? results[0] : new DomainFunctionalLevelSettings();
        }

        private IReadOnlyList<DomainFunctionalLevelSettings> QueryDomainFunctionalLevel(string path, bool useLdaps)
        {
            var authType = AuthenticationTypes.Secure;
            authType |= useLdaps ? AuthenticationTypes.SecureSocketsLayer : AuthenticationTypes.Sealing;

            using var rootEntry = string.IsNullOrEmpty(_options.Username)
                ? new DirectoryEntry(path) { AuthenticationType = authType }
                : new DirectoryEntry(path, _options.Username, _options.Password, authType);

            using var searcher = new DirectorySearcher(rootEntry)
            {
                Filter = "(objectClass=*)",
                SearchScope = SearchScope.Base,
                ReferralChasing = ReferralChasingOption.None
            };
            searcher.PropertiesToLoad.Add("msDS-Behavior-Version");
            searcher.PropertiesToLoad.Add("distinguishedName");

            SearchResult? result = searcher.FindOne();
            if (result == null)
            {
                return Array.Empty<DomainFunctionalLevelSettings>();
            }

            // GetInt (diğer sorgularda kullanılan paylaşımlı yardımcı) öznitelik eksikse 0
            // döner - burada bu YANLIŞ olur, çünkü ham msDS-Behavior-Version değeri 0 zaten
            // geçerli/gerçek bir seviyeyi (Windows2000Domain) ifade eder. Öznitelik gerçekten
            // eksikse (beklenmez ama savunmacı olmak gerekir) -1 (Informational, "veri yok")
            // ile karıştırılmaması için burada özel olarak ayrıştırılır.
            bool hasLevel = result.Properties.Contains("msDS-Behavior-Version") && result.Properties["msDS-Behavior-Version"].Count > 0;
            int functionalLevel = hasLevel ? Convert.ToInt32(result.Properties["msDS-Behavior-Version"][0]) : -1;

            return new List<DomainFunctionalLevelSettings>
            {
                new DomainFunctionalLevelSettings
                {
                    DomainDistinguishedName = GetString(result, "distinguishedName"),
                    FunctionalLevel = functionalLevel
                }
            };
        }

        /// <summary>
        /// Forest seviyesindeki AD Recycle Bin (Silinen Öğeler Kutusu) özelliğinin etkin olup
        /// olmadığını okur. Kullanıcı/bilgisayar/domain kökü sorgularının hiçbirinden farklı
        /// olarak, önce RootDSE'den (dizinin kendi kök meta verisi - her DC'nin yayınladığı,
        /// bağlanmadan önce "forest'ın Configuration bölümü nerede" gibi temel yapılandırma
        /// bilgilerini taşıyan özel bir nesne) Configuration Naming Context'in tam yolunu
        /// öğrenip, ardından o yol altındaki bilinen "Recycle Bin Feature" nesnesini okumak
        /// gerekir - iki adımlı bir sorgu.
        /// </summary>
        public ForestOptionalFeatureSettings GetForestOptionalFeatures()
        {
            var results = ExecuteWithLdapsFallback<ForestOptionalFeatureSettings>(
                (path, useLdaps) => QueryForestOptionalFeatures(path, useLdaps));

            return results.Count > 0 ? results[0] : new ForestOptionalFeatureSettings();
        }

        private IReadOnlyList<ForestOptionalFeatureSettings> QueryForestOptionalFeatures(string path, bool useLdaps)
        {
            var authType = AuthenticationTypes.Secure;
            authType |= useLdaps ? AuthenticationTypes.SecureSocketsLayer : AuthenticationTypes.Sealing;

            string rootDsePath = BuildPathWithDn(path, "RootDSE");
            using var rootDseEntry = string.IsNullOrEmpty(_options.Username)
                ? new DirectoryEntry(rootDsePath) { AuthenticationType = authType }
                : new DirectoryEntry(rootDsePath, _options.Username, _options.Password, authType);

            string? configurationNc = rootDseEntry.Properties.Contains("configurationNamingContext")
                ? rootDseEntry.Properties["configurationNamingContext"][0]?.ToString()
                : null;

            if (string.IsNullOrEmpty(configurationNc))
            {
                return Array.Empty<ForestOptionalFeatureSettings>();
            }

            // Recycle Bin Feature nesnesinin DN'i sabit/well-known bir konumdadır - her
            // forest'ta aynı göreli yolda bulunur, sadece Configuration NC'nin kendisi
            // (forest'a özgü) baştan öğrenilmesi gerekir.
            string featureDn = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services," + configurationNc;
            string featurePath = BuildPathWithDn(path, featureDn);

            using var featureEntry = string.IsNullOrEmpty(_options.Username)
                ? new DirectoryEntry(featurePath) { AuthenticationType = authType }
                : new DirectoryEntry(featurePath, _options.Username, _options.Password, authType);

            using var searcher = new DirectorySearcher(featureEntry)
            {
                Filter = "(objectClass=*)",
                SearchScope = SearchScope.Base,
                ReferralChasing = ReferralChasingOption.None
            };
            searcher.PropertiesToLoad.Add("msDS-EnabledFeatureBL");

            SearchResult? result;
            try
            {
                result = searcher.FindOne();
            }
            catch (System.Runtime.InteropServices.COMException)
            {
                // Feature nesnesi hiç yok - forest'ta Recycle Bin hiçbir zaman
                // etkinleştirilmemiş demektir. Bu, "veri okunamadı" değil, güvenilir/kesin
                // bir "devre dışı" sonucudur.
                return new List<ForestOptionalFeatureSettings> { new ForestOptionalFeatureSettings { IsRecycleBinEnabled = false } };
            }

            if (result == null)
            {
                return new List<ForestOptionalFeatureSettings> { new ForestOptionalFeatureSettings { IsRecycleBinEnabled = false } };
            }

            bool isEnabled = result.Properties.Contains("msDS-EnabledFeatureBL") && result.Properties["msDS-EnabledFeatureBL"].Count > 0;

            return new List<ForestOptionalFeatureSettings> { new ForestOptionalFeatureSettings { IsRecycleBinEnabled = isEnabled } };
        }

        /// <summary>
        /// Zaten şema+host+port içeren tam bir LDAP yolunu (ör. "LDAP://192.0.2.1:636/
        /// DC=contoso,DC=local") alıp, sonundaki DN kısmını verilen yeni DN ile değiştirir (ör.
        /// "RootDSE" veya farklı bir konteynerin DN'i). ExtractBaseDn'in (LdapProtocolSecurityChecker)
        /// tersi işlemi yapar - public/saf/I-O'suz olduğundan doğrudan birim testiyle
        /// doğrulanabilir.
        /// </summary>
        public static string BuildPathWithDn(string formattedLdapPath, string dn)
        {
            int schemeEnd = formattedLdapPath.IndexOf("://", StringComparison.OrdinalIgnoreCase);
            if (schemeEnd < 0) return formattedLdapPath;

            int hostStart = schemeEnd + 3;
            int slashIndex = formattedLdapPath.IndexOf('/', hostStart);
            string hostPrefix = slashIndex < 0 ? formattedLdapPath : formattedLdapPath.Substring(0, slashIndex);

            return hostPrefix + "/" + dn;
        }

        /// <summary>
        /// Bu domain'in kurduğu güven ilişkilerini (trust) okur. AD'de her trust, domain
        /// kökünün altındaki sabit "CN=System" konteynerinde bir "trustedDomain" nesnesi
        /// olarak saklanır - kullanıcı/bilgisayar sorgularının aksine (tüm alt ağacı tarayan
        /// Subtree scope), burada System konteynerinin doğrudan altına (OneLevel) bakmak
        /// yeterlidir çünkü trustedDomain nesneleri iç içe (nested) bulunmaz.
        /// </summary>
        public IReadOnlyList<AdTrustRelationship> GetTrustRelationships()
        {
            return ExecuteWithLdapsFallback<AdTrustRelationship>(
                (path, useLdaps) => QueryTrustRelationships(path, useLdaps));
        }

        private IReadOnlyList<AdTrustRelationship> QueryTrustRelationships(string path, bool useLdaps)
        {
            string baseDn = LdapProtocolSecurityChecker.ExtractBaseDn(path);
            if (string.IsNullOrEmpty(baseDn))
            {
                return Array.Empty<AdTrustRelationship>();
            }

            string systemContainerPath = BuildPathWithDn(path, "CN=System," + baseDn);

            var authType = AuthenticationTypes.Secure;
            authType |= useLdaps ? AuthenticationTypes.SecureSocketsLayer : AuthenticationTypes.Sealing;

            using var systemEntry = string.IsNullOrEmpty(_options.Username)
                ? new DirectoryEntry(systemContainerPath) { AuthenticationType = authType }
                : new DirectoryEntry(systemContainerPath, _options.Username, _options.Password, authType);

            using var searcher = new DirectorySearcher(systemEntry)
            {
                Filter = "(objectClass=trustedDomain)",
                SearchScope = SearchScope.OneLevel,
                ReferralChasing = ReferralChasingOption.None
            };
            searcher.PropertiesToLoad.Add("trustPartner");
            searcher.PropertiesToLoad.Add("trustDirection");
            searcher.PropertiesToLoad.Add("trustType");
            searcher.PropertiesToLoad.Add("trustAttributes");

            var results = new List<AdTrustRelationship>();

            using SearchResultCollection searchResults = searcher.FindAll();
            foreach (SearchResult result in searchResults)
            {
                results.Add(new AdTrustRelationship
                {
                    TrustPartner = GetString(result, "trustPartner"),
                    TrustDirection = GetInt(result, "trustDirection"),
                    TrustType = GetInt(result, "trustType"),
                    TrustAttributes = GetInt(result, "trustAttributes")
                });
            }

            return results;
        }

        // Domain'e özgü (domain SID + RID) beklenen DCSync sahipleri: 512=Domain Admins,
        // 519=Enterprise Admins (yalnızca forest root'ta anlamlı), 516=Domain Controllers
        // (normal DC'ler arası replikasyon için varsayılan), 498=Enterprise Read-only
        // Domain Controllers (RODC'lerin filtrelenmiş replikasyonu için varsayılan).
        private static readonly string[] ExpectedDcSyncRids = { "512", "519", "516", "498" };

        /// <summary>
        /// Bir SID'in, DCSync haklarına varsayılan/beklenen şekilde sahip olan bir asıl
        /// güvenlik prensibine ait olup olmadığını kontrol eder. Public: saf/I-O'suz bir
        /// yardımcı fonksiyon olduğundan doğrudan birim testiyle doğrulanabilir - bu, canlı
        /// lab testinde Domain Controllers (RID 516) ve Enterprise Read-only Domain
        /// Controllers (RID 498) gruplarının unutulup yanlış pozitif üretmesiyle bulunan
        /// gerçek bir hatanın regresyon testidir.
        /// </summary>
        public static bool IsExpectedDcSyncPrincipal(string sidValue, string domainSidValue)
        {
            if (string.Equals(sidValue, BuiltinAdministratorsSid, StringComparison.OrdinalIgnoreCase)) return true;
            if (string.Equals(sidValue, EnterpriseDomainControllersSid, StringComparison.OrdinalIgnoreCase)) return true;
            if (string.Equals(sidValue, LocalSystemSid, StringComparison.OrdinalIgnoreCase)) return true;

            foreach (string rid in ExpectedDcSyncRids)
            {
                if (string.Equals(sidValue, domainSidValue + "-" + rid, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Ham SID'i, mümkünse okunabilir bir isme ("DOMAIN\isim") çözümler - bir güvenlik
        /// analistine "S-1-5-21-...-1234" göstermek yerine kimin gerçekten sorumlu olduğunu
        /// göstermek için. Çözümlenemezse (örn. yetim/silinmiş SID) ham SID'e geri döner.
        /// </summary>
        private static string ResolvePrincipalName(string sidValue)
        {
            try
            {
                var sid = new SecurityIdentifier(sidValue);
                return sid.Translate(typeof(NTAccount)).Value;
            }
            catch
            {
                return sidValue;
            }
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

            bool wantsLdaps = _options.UseLdaps || formattedPath.Contains(":636");

            // Bu taramada LDAPS'in zaten çalışmadığı öğrenildiyse, garanti başarısız
            // olacak bir denemeyi tekrar bekletmek yerine doğrudan bilinen çalışan
            // (Port 389) yola gidilir. AllowUnsecureFallback zaten yukarıdaki Zero Trust
            // denetiminden geçtiği için burada tekrar kontrol edilmesine gerek yok -
            // bu dal SADECE daha önce gerçekten başarılı bir fallback yaşandıysa girilir.
            if (wantsLdaps && _ldapsUnavailableThisScan == true)
            {
                return queryFunc(BuildFallbackPath(), false);
            }

            try
            {
                var result = queryFunc(formattedPath, wantsLdaps);
                if (wantsLdaps)
                {
                    _ldapsUnavailableThisScan = false;
                }
                return result;
            }
            catch (Exception ex) when (_options.AllowUnsecureFallback && wantsLdaps)
            {
                Console.WriteLine($"[*] [LDAPS UYARISI] Port 636 (SSL) bağlantısı kurulamadı ({ex.Message}). Fallback: Kerberos Sealing (Port 389) deneniyor...");
                _ldapsUnavailableThisScan = true;

                return queryFunc(BuildFallbackPath(), false);
            }
        }

        private string BuildFallbackPath()
        {
            string fallbackPath = _options.LdapPath;
            if (fallbackPath.StartsWith("LDAPS://", StringComparison.OrdinalIgnoreCase))
            {
                fallbackPath = "LDAP://" + fallbackPath.Substring(8);
            }
            return fallbackPath.Replace(":636", "");
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
                IsCannotChangePassword = IsCannotChangePasswordViaAcl(result),
                HasSidHistory = result.Properties.Contains("sIDHistory") && result.Properties["sIDHistory"].Count > 0,
                SupportedEncryptionTypes = GetInt(result, "msDS-SupportedEncryptionTypes")
            };
        }

        private static AdComputerAccount MapToComputerAccount(SearchResult result)
        {
            var delegateToList = new List<string>();
            if (result.Properties.Contains("msDS-AllowedToDelegateTo"))
            {
                foreach (object spn in result.Properties["msDS-AllowedToDelegateTo"])
                {
                    if (spn != null) delegateToList.Add(spn.ToString()!);
                }
            }

            return new AdComputerAccount
            {
                SamAccountName = GetString(result, "sAMAccountName"),
                DistinguishedName = GetString(result, "distinguishedName"),
                OperatingSystem = GetString(result, "operatingSystem"),
                UserAccountControl = GetInt(result, "userAccountControl"),
                PasswordLastSet = GetFileTimeAsDateTime(result, "pwdLastSet"),
                LastLogonTimestamp = GetFileTimeAsDateTime(result, "lastLogonTimestamp"),
                ResourceBasedConstrainedDelegationPrincipals = ParseRbcdPrincipals(result),
                AllowedToDelegateTo = delegateToList,
                HasLapsManagedPassword = HasAnyValue(result, "ms-Mcs-AdmPwdExpirationTime") || HasAnyValue(result, "msLAPS-PasswordExpirationTime")
            };
        }

        private static bool HasAnyValue(SearchResult result, string propertyName)
        {
            return result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0;
        }

        /// <summary>
        /// msDS-AllowedToActOnBehalfOfOtherIdentity özniteliğini (RBCD - Resource-Based
        /// Constrained Delegation) ayrıştırır. Bu öznitelik, nesnenin KENDİ ACL'i değil, ham
        /// bir güvenlik tanımlayıcısı (security descriptor) TAŞIYAN bir öznitelik DEĞERİDİR -
        /// bu yüzden SecurityMasks.Dacl (nesnenin kendi nTSecurityDescriptor'ı için gereken
        /// bayrak) gerektirmez, normal bir öznitelik gibi PropertiesToLoad'a eklenmesi yeterli.
        /// ACE'ler burada ObjectAce (AD-008/AD-023'teki gibi belirli bir kontrol erişim hakkı
        /// GUID'ine bağlı) değil, düz CommonAce'dir - RBCD basitçe "bu SID'ler kimlik
        /// doğrulayabilir" der, belirli bir hakka bağlı değildir.
        /// </summary>
        private static IReadOnlyList<string> ParseRbcdPrincipals(SearchResult result)
        {
            if (!result.Properties.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity") || result.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Count == 0)
            {
                return Array.Empty<string>();
            }

            try
            {
                var sdBytes = (byte[])result.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"][0];
                var rawSecurityDescriptor = new RawSecurityDescriptor(sdBytes, 0);
                RawAcl? dacl = rawSecurityDescriptor.DiscretionaryAcl;
                if (dacl == null) return Array.Empty<string>();

                var principals = new List<string>();
                foreach (GenericAce ace in dacl)
                {
                    if (ace is not CommonAce commonAce) continue;
                    if (commonAce.AceType != AceType.AccessAllowed) continue;
                    principals.Add(ResolvePrincipalName(commonAce.SecurityIdentifier.Value));
                }
                return principals;
            }
            catch
            {
                // ACL ayrıştırılamazsa güvenli tarafta kalınır: hiçbir RBCD prensibi
                // raporlanmaz (AD-008/AD-023'teki aynı savunmacı yaklaşım).
                return Array.Empty<string>();
            }
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