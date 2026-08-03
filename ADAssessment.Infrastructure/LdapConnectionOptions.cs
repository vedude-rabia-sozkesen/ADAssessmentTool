using System;

namespace ADAssessment.Infrastructure.Ldap
{
    /// <summary>
    /// Active Directory (LDAP/LDAPS) bağlantı ve kimlik doğrulama seçeneklerini
    /// kapsülleyen konfigürasyon nesnesi. Zero Trust ve gMSA standartlarına uygundur.
    /// </summary>
    public sealed class LdapConnectionOptions
    {
        /// <summary>
        /// Bağlanılacak LDAP/LDAPS adresi. (Örn: "LDAP://192.168.92.100/DC=lab,DC=local")
        /// </summary>
        public string LdapPath { get; set; } = string.Empty;

        /// <summary>
        /// Servis hesabı kullanıcı adı (Domain\Username). 
        /// gMSA veya Integrated Windows Auth kullanılıyorsa null/boş bırakılabilir.
        /// </summary>
        public string? Username { get; set; }

        /// <summary>
        /// Servis hesabı parolası. 
        /// gMSA kullanılıyorsa null kalabilir, explicit hesaptaysa şifreli bellekten beslenir.
        /// </summary>
        public string? Password { get; set; }

        /// <summary>
        /// SSL/TLS şifreli bağlantı (Port 636 - LDAPS) zorunlu kılınsın mı? Default: true (Zero Trust)
        /// </summary>
        public bool UseLdaps { get; set; } = true;

        /// <summary>
        /// SSL/TLS sertifikası bulunmayan test/lab ortamları için Port 389 düşüşüne izin verilsin mi? Default: false (Zero Trust)
        /// </summary>
        public bool AllowUnsecureFallback { get; set; } = false;

        /// <summary>
        /// Sayfalı arama (Paged Search) sayfa boyutu. Default: 500
        /// </summary>
        public int PageSize { get; set; } = 500;

        /// <summary>
        /// Zero Trust ilkelerine uygun olarak bağlantı adresini LDAPS (Port 636) formatına otomatik dönüştürür.
        /// </summary>
        public string GetFormattedLdapPath()
        {
            if (string.IsNullOrWhiteSpace(LdapPath)) return string.Empty;

            if (UseLdaps)
            {
                string formatted = LdapPath;

                // "LDAP://" ise "LDAPS://" olarak değiştir
                if (formatted.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                {
                    formatted = "LDAPS://" + formatted.Substring(7);
                }
                else if (!formatted.StartsWith("LDAPS://", StringComparison.OrdinalIgnoreCase))
                {
                    formatted = "LDAPS://" + formatted;
                }

                // Port numarası açıkça belirtilmemişse otomatik olarak :636 ekle
                // Örn: LDAPS://192.168.92.100/DC=lab,DC=local -> LDAPS://192.168.92.100:636/DC=lab,DC=local
                int slashIndex = formatted.IndexOf('/', 8); // "LDAPS://" sonrasındaki ilk '/'
                if (slashIndex > 8)
                {
                    string hostPart = formatted.Substring(8, slashIndex - 8);
                    if (!hostPart.Contains(':'))
                    {
                        formatted = formatted.Substring(0, slashIndex) + ":636" + formatted.Substring(slashIndex);
                    }
                }

                return formatted;
            }

            return LdapPath;
        }
    }
}
