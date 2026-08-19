using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Domain'in kendi kök nesnesinin (naming context) DACL'inde, DS-Replication-Get-Changes
    /// ve DS-Replication-Get-Changes-All (bir Domain Controller'ın yaptığı gibi tüm dizin
    /// değişikliklerini - parola hash'leri dahil - çekebilme hakkı, "DCSync" saldırısının
    /// temelini oluşturur) haklarına sahip, varsayılan/beklenen olmayan asıl güvenlik
    /// prensiplerini (principal) temsil eder.
    /// </summary>
    public sealed class DcSyncRightsSettings
    {
        public string DomainDistinguishedName { get; init; } = string.Empty;

        /// Domain Admins, Enterprise Admins, BUILTIN\Administrators, Enterprise Domain
        /// Controllers ve SYSTEM dışında, DCSync haklarına sahip her asıl güvenlik prensibi
        /// (kullanıcı adı çözümlenebiliyorsa "DOMAIN\isim", çözümlenemiyorsa ham SID).
        public IReadOnlyList<string> UnexpectedPrincipals { get; init; } = System.Array.Empty<string>();
    }
}
