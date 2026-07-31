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

        /// UserAccountControl bit 16 (0x10000) = DONT_EXPIRE_PASSWORD bayrağını kontrol eder.
        public bool IsPasswordNeverExpires => (UserAccountControl & 0x10000) != 0;

        /// UserAccountControl bit 5 (0x20) = PASSWD_NOTREQD bayrağını kontrol eder.
        public bool IsPasswordNotRequired => (UserAccountControl & 0x20) != 0;

        /// UserAccountControl bit 19 (0x80000) = TRUSTED_FOR_DELEGATION bayrağını kontrol eder.
        public bool IsUnconstrainedDelegation => (UserAccountControl & 0x80000) != 0;

        /// UserAccountControl bit 6 (0x40) = PASSWD_CANT_CHG bayrağını kontrol eder.
        public bool IsCannotChangePassword => (UserAccountControl & 0x40) != 0;

        /// UserAccountControl bit 7 (0x80) = ENCRYPTED_TEXT_PASSWORD_ALLOWED bayrağını kontrol eder.
        public bool IsReversibleEncryptionAllowed => (UserAccountControl & 0x80) != 0;

        /// UserAccountControl bit 21 (0x200000) = USE_DES_KEY_ONLY bayrağını kontrol eder.
        public bool IsDesEncryptionAllowed => (UserAccountControl & 0x200000) != 0;
    }
}