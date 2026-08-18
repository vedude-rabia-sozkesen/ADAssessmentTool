using System.Collections.Generic;
using System.Xml.Serialization;

namespace ADAssessment.WebAPI.Models
{
    /// <summary>
    /// /api/assessment/scan yanıtının SIEM entegrasyonuna uygun, kararlı sözleşmesi.
    /// JSON ve XML'in ikisi de aynı bu tipten üretilir (content negotiation - istemcinin
    /// Accept header'ına göre otomatik seçim) - iki formatın birbirinden sapmaması,
    /// tek bir kaynaktan üretilmesiyle garanti edilir. RuleResult (Core) yerine burada
    /// ayrı bir DTO kullanılmasının sebebi: RuleResult.AffectedObjects IReadOnlyList
    /// tipinde ve XmlSerializer arayüz (interface) tipli üyeleri serileştiremiyor.
    /// </summary>
    [XmlRoot("ScanResult")]
    public class ScanResultResponse
    {
        public string Status { get; set; } = string.Empty;
        public int ScannedUserCount { get; set; }
        public int ScannedComputerCount { get; set; }
        public int TotalRulesExecuted { get; set; }
        public int VulnerableRulesCount { get; set; }

        [XmlArray("Results")]
        [XmlArrayItem("Rule")]
        public List<RuleResultDto> Results { get; set; } = new();
    }

    public class RuleResultDto
    {
        public string RuleId { get; set; } = string.Empty;
        public bool IsVulnerable { get; set; }
        public string RiskLevel { get; set; } = string.Empty;
        public string FrameworkMapping { get; set; } = string.Empty;
        public string Iso27001Mapping { get; set; } = string.Empty;

        [XmlArray("AffectedObjects")]
        [XmlArrayItem("Object")]
        public List<string> AffectedObjects { get; set; } = new();

        public string Remediation { get; set; } = string.Empty;
    }
}
