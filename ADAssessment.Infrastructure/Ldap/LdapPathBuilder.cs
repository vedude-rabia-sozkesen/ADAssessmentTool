using System;

namespace ADAssessment.Infrastructure.Ldap
{
    /// <summary>
    /// Kullanıcının "DC İsmi" (FQDN) ve IP adresi gibi, LDAP path söz dizimini (LDAP://,
    /// DC=... vb.) bilmesini gerektirmeyen ayrı alanlardan geçerli bir LDAP bağlantı yolu
    /// inşa eden saf/I-O'suz yardımcı sınıf - AdConnectionController'ın dashboard formunu
    /// "tek bir path kutusu" yerine "iki ayrı, anlaşılır kutucuk" olarak sunabilmesi için.
    /// </summary>
    public static class LdapPathBuilder
    {
        /// <summary>
        /// "DC01.lab.local" gibi tam nitelikli (FQDN) bir DC sunucu adından, ilk etiketi
        /// (sunucunun kendi adı, "DC01") atıp kalan domain kısmını ("lab.local") standart
        /// LDAP DN formatına ("DC=lab,DC=local") çevirir. Alt domain'leri de doğru işler
        /// (ör. "DC01.child.contoso.com" -> "DC=child,DC=contoso,DC=com"). FQDN olmayan
        /// (hiç nokta içermeyen, ör. sadece "DC01") bir isimden domain adı güvenilir şekilde
        /// çıkarılamayacağından null döner.
        /// </summary>
        public static string? TryBuildDomainDn(string dcHostname)
        {
            if (string.IsNullOrWhiteSpace(dcHostname))
            {
                return null;
            }

            int firstDot = dcHostname.IndexOf('.');
            if (firstDot < 0 || firstDot == dcHostname.Length - 1)
            {
                return null;
            }

            string domainSuffix = dcHostname.Substring(firstDot + 1);
            string[] labels = domainSuffix.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length == 0)
            {
                return null;
            }

            return "DC=" + string.Join(",DC=", labels);
        }

        /// <summary>IP adresi ve önceden hesaplanmış domain DN'inden tam LDAP yolunu üretir.</summary>
        public static string BuildLdapPath(string ipAddress, string domainDn)
        {
            return $"LDAP://{ipAddress}/{domainDn}";
        }
    }
}
