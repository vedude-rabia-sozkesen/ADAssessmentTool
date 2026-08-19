using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Forest dışı (external) veya forest'lar arası (forest trust) güven ilişkilerinde SID
    /// filtering'in (karantina) devre dışı olduğu durumları tespit eder. SID filtering
    /// kapalıyken, güvenilen (trusted) tarafta bulunan (ve o tarafın tamamen kendi kontrolü
    /// dışında olabileceği) bir saldırgan, kendi hesabının sIDHistory'sine BU domain'in
    /// örn. Domain Admins SID'ini enjekte ederek trust sınırını aşıp doğrudan Domain Admin
    /// yetkisiyle buraya erişebilir - MITRE'nin "SID-History Injection" olarak kataloğladığı
    /// tekniğin, tek bir domain içi değil TRUST ÜZERİNDEN yapılan versiyonu. Aynı forest
    /// içindeki parent/child trust'lar (TRUST_ATTRIBUTE_WITHIN_FOREST) bilerek dışlanır -
    /// bu tür trust'larda SID History'nin forest içinde dolaşması tasarım gereği beklenir.
    /// </summary>
    public sealed class SidFilteringDisabledRule : ITrustComplianceRule
    {
        public string RuleId => "AD-032";

        public string Name => "Güven İlişkilerinde SID Filtering Devre Dışı";

        public string Description => "Forest dışı veya forest'lar arası bir güven ilişkisinde SID filtering (karantina) etkin değil. Güvenilen tarafta bulunan bir saldırgan, sIDHistory enjeksiyonuyla bu domain'de doğrudan yüksek yetkili bir hesap (ör. Domain Admins) gibi davranabilir.";

        public string FrameworkMapping => "MITRE ATT&CK T1134.005 (Access Token Manipulation: SID-History Injection)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.2 (Privileged Access Rights)";

        public string Remediation => "1. Etkilenen her trust için netdom trust /domain:<bu domain> /EnableSIDHistory:no komutuyla SID filtering'i etkinleştirin.\n" +
                                     "2. Etkinleştirmeden önce, karşı taraftan meşru şekilde SID History kullanan (gerçek bir domain göçü sürecinde olan) bir uygulama/senaryo olup olmadığını doğrulayın - etkinleştirme bu tür senaryoları kesintiye uğratabilir.\n" +
                                     "3. Mümkünse, güvenilen tarafın güvenlik duruşunu (patch seviyesi, yönetim pratikleri) da ayrıca değerlendirin - trust, en zayıf tarafın güvenlik seviyesini bu domain'e taşıyabilir.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not IEnumerable<AdTrustRelationship> trustList)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            var vulnerableTrusts = new List<string>();

            foreach (var trust in trustList)
            {
                if (trust.IsWithinForest) continue;
                if (trust.IsSidFilteringEnabled) continue;

                vulnerableTrusts.Add(trust.TrustPartner);
            }

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableTrusts.Count > 0,
                RiskLevel = vulnerableTrusts.Count > 0 ? "High" : "Low",
                AffectedObjects = vulnerableTrusts,
                Remediation = this.Remediation
            };
        }
    }
}
