using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// Bir güvenlik kuralı çalıştırıldıktan sonra üretilen analiz çıktısını temsil eder.
    /// Bellek performansını korumak ve veri tutarlılığını sağlamak için 'init-only' (immutable) özellikler barındırır.
    public class RuleResult
    {
        public string RuleId { get; init; } = string.Empty;

        /// Analiz sonucunda hedef sistemde bir zafiyet veya risk tespit edilip edilmediği bilgisi.
        /// true: Risk var, false: Sistem güvenli.

        public bool IsVulnerable { get; init; }

        public string RiskLevel { get; init; } = string.Empty;

        /// Zafiyetten etkilenen Active Directory nesnelerinin listesi (Örn: sAMAccountName veya DN listesi).
        /// Bellek dostu olması ve dışarıdan manipüle edilememesi için IReadOnlyList (Read-Only) olarak tasarlanmıştır.
        /// GC (Garbage Collector) yükünü azaltmak için varsayılan olarak boş dizi atanır.
        public IReadOnlyList<string> AffectedObjects { get; init; } = System.Array.Empty<string>();

        /// Tespit edilen zafiyetin sistem yöneticileri (SysAdmin) tarafından nasıl düzeltileceğine dair 
        /// adım adım uygulanabilir çözüm ve sıkılaştırma (hardening) önerisi.
        public string Remediation { get; init; } = string.Empty;
    }
}