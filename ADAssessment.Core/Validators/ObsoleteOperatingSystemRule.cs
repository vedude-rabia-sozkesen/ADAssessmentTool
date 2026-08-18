using System;
using System.Collections.Generic;
using System.Linq;

namespace ADAssessment.Core
{
    /// <summary>
    /// Microsoft tarafından güvenlik güncellemesi desteği tamamen sona ermiş (üretici desteği
    /// bitmiş) işletim sistemi çalıştıran bilgisayar hesaplarını tespit eder. Bu makineler,
    /// yeni keşfedilen zafiyetler için hiçbir zaman yama almayacağından kalıcı bir giriş
    /// noktası (saldırı yüzeyi) oluşturur.
    ///
    /// Liste kasıtlı olarak muhafazakar tutulmuştur - sadece yıllardır ve tartışmasız şekilde
    /// desteği bitmiş sürümleri içerir (Windows 10/Server 2016+ gibi sınırda/edisyona bağlı
    /// (örn. LTSC) durumlarda yanlış pozitif riskini almamak için dahil edilmemiştir). Bu liste,
    /// yeni sürümler desteği bittikçe periyodik olarak gözden geçirilmelidir.
    /// </summary>
    public sealed class ObsoleteOperatingSystemRule : IComputerComplianceRule
    {
        public string RuleId => "AD-017";

        public string Name => "Desteği Sona Ermiş İşletim Sistemi";

        public string Description => "Domain'e üye bazı bilgisayarlar, Microsoft tarafından güvenlik güncellemesi desteği tamamen sona ermiş bir işletim sistemi çalıştırıyor. Bu makineler yeni zafiyetler için asla yama almayacağından, domain içinde kalıcı bir saldırı yüzeyi oluşturur.";

        public string FrameworkMapping => "CIS Controls v8 - 4.1 / MITRE ATT&CK T1210 (Exploitation of Remote Services)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.8 (Management of Technical Vulnerabilities)";

        public string Remediation => "1. Etkilenen makineleri mümkün olan en kısa sürede desteklenen bir işletim sistemi sürümüne yükseltin.\n" +
                                     "2. Yükseltme mümkün değilse, makineyi ağ segmentasyonuyla izole edin.\n" +
                                     "3. Artık fiziksel/sanal olarak var olmayan makinelerin hesaplarını domain'den kaldırın.";

        // Contains ile eşleştirilir - örn. "Windows Server 2008 R2" da "Windows Server 2008"
        // arayışıyla eşleşir, bu istenen davranıştır (R2 sürümü de aynı şekilde desteksiz).
        private static readonly string[] ObsoleteOsMarkers =
        {
            "Windows 2000",
            "Windows XP",
            "Windows Vista",
            "Windows 7",
            "Windows 8",
            "Windows NT",
            "Windows Server 2000",
            "Windows Server 2003",
            "Windows Server 2008",
            "Windows Server 2012"
        };

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not IEnumerable<AdComputerAccount> computerList)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            var vulnerableComputers = new List<string>();

            foreach (var computer in computerList)
            {
                if (!computer.IsEnabled || string.IsNullOrWhiteSpace(computer.OperatingSystem))
                {
                    continue;
                }

                bool isObsolete = ObsoleteOsMarkers.Any(marker =>
                    computer.OperatingSystem.Contains(marker, StringComparison.OrdinalIgnoreCase));

                if (isObsolete)
                {
                    vulnerableComputers.Add($"{computer.SamAccountName} ({computer.OperatingSystem})");
                }
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableComputers.Count > 0,
                RiskLevel = vulnerableComputers.Count > 0 ? "High" : "Low",
                AffectedObjects = vulnerableComputers,
                Remediation = this.Remediation
            };
        }
    }
}
