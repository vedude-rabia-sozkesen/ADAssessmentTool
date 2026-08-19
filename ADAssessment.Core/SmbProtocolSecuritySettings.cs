namespace ADAssessment.Core
{
    /// <summary>
    /// Domain Controller'ın SMB (Server Message Block - Windows dosya/paylaşım paylaşım
    /// protokolü) seviyesindeki güvenlik davranışını temsil eder. LdapProtocolSecuritySettings
    /// gibi, bu veri de bir dosyadan/LDAP özniteliğinden değil, gerçek bir bağlantı
    /// denemesiyle (bkz. ISmbProtocolSecurityChecker) gözlemlenir.
    /// </summary>
    public sealed class SmbProtocolSecuritySettings
    {
        public string DomainController { get; init; } = string.Empty;

        /// DC, kimlik doğrulaması yapılmamış (boş kullanıcı adı + boş şifre - "null
        /// session") bir bağlantının IPC$ (Inter-Process Communication - ağ üzerinden
        /// süreçler arası iletişim için ayrılmış özel SMB paylaşımı) paylaşımına
        /// bağlanmasına izin veriyor mu? İzin veriyorsa, hiçbir kimlik bilgisi olmayan
        /// bir saldırgan bile SAM/LSA politika sorguları üzerinden kullanıcı ve grup
        /// listesini çıkarabilir.
        public bool IsAnonymousAccessAllowed { get; init; }
    }
}
