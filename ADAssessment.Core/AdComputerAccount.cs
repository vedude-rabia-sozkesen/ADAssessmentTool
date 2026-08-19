using System;

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory'den çekilen bilgisayar (computer) nesnesi verilerini Core
    /// katmanında temsil eden, değiştirilemez (init-only) veri modelidir. AdUserAccount'tan
    /// ayrı tutulur çünkü computer nesneleri farklı bir LDAP objectClass'a (computer) sahiptir
    /// ve kullanıcı hesaplarında olmayan alanlar (işletim sistemi) taşır.
    /// </summary>
    public sealed class AdComputerAccount
    {
        public string SamAccountName { get; init; } = string.Empty;
        public string DistinguishedName { get; init; } = string.Empty;

        /// Bilgisayarın kendi bildirdiği işletim sistemi adı (örn. "Windows Server 2019 Standard").
        /// AD tarafından doğrulanmaz - bilgisayarın kendisi tarafından yazılan bir öz-bildirimdir,
        /// ama gerçek dünyada eskimiş/desteklenmeyen işletim sistemlerini tespit etmek için
        /// endüstri standardı (PingCastle, Purple Knight vb. de aynı yaklaşımı kullanır) budur.
        public string OperatingSystem { get; init; } = string.Empty;

        public int UserAccountControl { get; init; }
        public DateTime? PasswordLastSet { get; init; }
        public DateTime? LastLogonTimestamp { get; init; }

        /// UserAccountControl bit 2 (0x2) = ACCOUNTDISABLE bayrağını kontrol eder.
        public bool IsEnabled => (UserAccountControl & 0x2) == 0;

        /// UserAccountControl bit 19 (0x80000) = TRUSTED_FOR_DELEGATION bayrağını kontrol eder.
        /// AdUserAccount'taki karşılığıyla aynı bit - UAC bayrakları nesne tipinden (kullanıcı/
        /// bilgisayar) bağımsızdır.
        public bool IsUnconstrainedDelegation => (UserAccountControl & 0x80000) != 0;

        /// UserAccountControl bit 13 (0x2000) = SERVER_TRUST_ACCOUNT bayrağını kontrol eder.
        /// Bu bit sadece Domain Controller bilgisayar hesaplarında set edilir; bir DC'nin
        /// sınırsız delegasyona sahip olması tasarım gereği beklenen/normal bir durumdur
        /// (DC'ler arası bazı Kerberos işlemleri bunu gerektirir) - bu yüzden delegasyon
        /// kuralında DC'leri elemek (false positive önlemek) için kullanılır.
        public bool IsDomainController => (UserAccountControl & 0x2000) != 0;
    }
}
