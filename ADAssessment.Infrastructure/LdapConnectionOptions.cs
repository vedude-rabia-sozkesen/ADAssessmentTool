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
        /// Zero Trust ilkelerine uygun olarak bağlantı adresini LDAPS (Port 636) için
        /// hazırlar. ÖNEMLİ: ADSI'nin (System.DirectoryServices'in temelindeki Windows
        /// dizin servisi arayüzü) LDAP sağlayıcısı SADECE "LDAP://" şemasını tanır -
        /// "LDAPS://" geçerli bir ADSI yolu DEĞİLDİR ve E_ADS_BAD_PATHNAME (0x80005000)
        /// hatasıyla reddedilir. SSL/TLS, şema ile değil AuthenticationTypes.SecureSocketsLayer
        /// bayrağıyla (bkz. LdapDataExtractor.QueryDirectory) etkinleştirilir; bu metodun
        /// tek işi şemayı "LDAP://" olarak normalize edip port 636'yı eklemektir.
        /// </summary>
        public string GetFormattedLdapPath()
        {
            if (string.IsNullOrWhiteSpace(LdapPath)) return string.Empty;

            if (UseLdaps)
            {
                string formatted = LdapPath;

                // Yanlışlıkla "LDAPS://" girilmişse (geçersiz bir ADSI şeması) "LDAP://"'a normalize et.
                if (formatted.StartsWith("LDAPS://", StringComparison.OrdinalIgnoreCase))
                {
                    formatted = "LDAP://" + formatted.Substring(8);
                }
                else if (!formatted.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                {
                    formatted = "LDAP://" + formatted;
                }

                // Port numarası açıkça belirtilmemişse otomatik olarak :636 ekle
                // Örn: LDAP://192.168.92.100/DC=lab,DC=local -> LDAP://192.168.92.100:636/DC=lab,DC=local
                int slashIndex = formatted.IndexOf('/', 7); // "LDAP://" sonrasındaki ilk '/'
                if (slashIndex > 7)
                {
                    string hostPart = formatted.Substring(7, slashIndex - 7);
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
