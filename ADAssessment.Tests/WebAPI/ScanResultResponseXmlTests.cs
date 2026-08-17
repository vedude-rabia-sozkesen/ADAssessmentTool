using System.Collections.Generic;
using System.IO;
using System.Xml.Serialization;
using ADAssessment.WebAPI.Models;
using Xunit;

namespace ADAssessment.Tests.WebAPI
{
    /// <summary>
    /// SIEM (Security Information and Event Management) entegrasyonu için ScanResultResponse'un
    /// gerçekten XML'e serileştirilebildiğini doğrular. XmlSerializer arayüz (interface) veya
    /// "object" tipli üyeleri serileştiremediğinden (bkz. RuleResult.AffectedObjects: IReadOnlyList,
    /// JsonRuleDefinition.Value: object), bu test bir regresyonu (örn. DTO'ya böyle bir tip
    /// eklenmesi) derleme zamanında değil ama en azından test zamanında yakalar.
    /// </summary>
    public class ScanResultResponseXmlTests
    {
        [Fact]
        public void ScanResultResponse_SerializesToXml_WithoutThrowing()
        {
            var response = new ScanResultResponse
            {
                Status = "Success",
                ScannedUserCount = 42,
                TotalRulesExecuted = 15,
                VulnerableRulesCount = 2,
                Results = new List<RuleResultDto>
                {
                    new RuleResultDto
                    {
                        RuleId = "AD-001",
                        IsVulnerable = true,
                        RiskLevel = "High",
                        AffectedObjects = new List<string> { "svc-web", "svc-sql" },
                        Remediation = "Rotate SPN credentials."
                    }
                }
            };

            var serializer = new XmlSerializer(typeof(ScanResultResponse));
            using var writer = new StringWriter();

            serializer.Serialize(writer, response);
            string xml = writer.ToString();

            Assert.Contains("<ScanResult", xml);
            Assert.Contains("AD-001", xml);
            Assert.Contains("svc-web", xml);
        }
    }
}
