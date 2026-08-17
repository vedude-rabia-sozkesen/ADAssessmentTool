namespace ADAssessment.Core
{
    /// <summary>
    /// Bir Group Policy Object'in (GPO) SYSVOL üzerindeki GptTmpl.inf dosyasından
    /// okunan, domain/OU genelinde geçerli güvenlik politikası ayarlarını temsil eder.
    /// AdUserAccount'un aksine kullanıcı bazlı değil, politika bazlıdır - tek bir
    /// GPO, o GPO'nun bağlı olduğu tüm hesapları aynı anda etkiler.
    /// </summary>
    public sealed class GroupPolicySecuritySettings
    {
        public string GpoName { get; init; } = string.Empty;
        public string GpoGuid { get; init; } = string.Empty;

        /// GptTmpl.inf: [System Access] MinimumPasswordLength
        public int MinimumPasswordLength { get; init; }

        /// GptTmpl.inf: [System Access] PasswordComplexity (0/1)
        public bool PasswordComplexityEnabled { get; init; }

        /// GptTmpl.inf: [System Access] MaximumPasswordAge (gün). 0 = süresiz.
        public int MaximumPasswordAgeDays { get; init; }

        /// GptTmpl.inf: [System Access] LockoutBadCount. 0 = kilitleme yok (sınırsız deneme).
        public int LockoutThreshold { get; init; }

        /// GptTmpl.inf: [System Access] LockoutDuration (dakika).
        public int LockoutDurationMinutes { get; init; }

        /// GptTmpl.inf: [System Access] ClearTextPassword (0/1) - reversible encryption.
        public bool ReversibleEncryptionEnabled { get; init; }
    }
}
