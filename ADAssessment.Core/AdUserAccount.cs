using System;

namespace ADAssessment.Core
{
    /// <summary>
    /// Active Directory'den çekilen kullanıcı hesabı verilerini Core katmanında 
    /// temsil eden, değiştirilemez (init-only) veri modelidir.
    /// Kuralların (Rules) analiz edebilmesi için burada konumlandırılmıştır.
    /// </summary>
    public sealed class AdUserAccount
    {
        public string SamAccountName { get; init; } = string.Empty;
        public string DistinguishedName { get; init; } = string.Empty;
        public string DisplayName { get; init; } = string.Empty;

        /// Kullanıcının aktif dizindeki bayrak tabanlı durum kodu (UAC).
        /// Parola süresi, kilitlenme durumu veya hesabın aktifliği bu bitlerden hesaplanır.
        public int UserAccountControl { get; init; }
        public DateTime? PasswordLastSet { get; init; }
        public DateTime? LastLogonTimestamp { get; init; }

        /// adminCount = 1 olma durumu. Domain Admin gibi kritik gruplara 
        /// dahil edilmiş hesapları (Protected Accounts) tespit etmek için kullanılır.
        public bool IsAdminCountSet { get; init; }

        /// Kullanıcının üye olduğu grup sayısı.

        public int MemberOfCount { get; init; }

        /// UserAccountControl bit 2 (0x2) = ACCOUNTDISABLE bayrağını kontrol eder.s
        /// Hesap aktifse true, devre dışı bırakılmışsa false döner.
        public bool IsEnabled => (UserAccountControl & 0x2) == 0;

        /// Hesaba tanımlanmış olan Service Principal Name (SPN) listesi.
        /// Kerberoasting analizinin ana odak noktasıdır.
        public IReadOnlyList<string> ServicePrincipalNames { get; init; } = System.Array.Empty<string>();

        /// UserAccountControl bit 22 (0x400000) = DONT_REQUIRE_PREAUTH bayrağını kontrol eder.
        /// Kerberos ön kimlik doğrulaması kapalıysa true döner (AS-REP Roasting Zafiyeti).
        public bool IsPreauthNotRequired => (UserAccountControl & 0x400000) != 0;
    }
}