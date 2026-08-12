using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Logging;

namespace ADAssessment.Tests.Infrastructure
{
    public class AuditLoggerTests : IDisposable
    {
        private readonly string _tempLogFile;

        public AuditLoggerTests()
        {
            _tempLogFile = Path.Combine(Path.GetTempPath(), "ADAssessmentTests_Audit_" + Guid.NewGuid() + ".log");
        }

        public void Dispose()
        {
            if (File.Exists(_tempLogFile))
            {
                File.Delete(_tempLogFile);
            }
        }

        private static List<RuleResult> SampleResults() => new()
        {
            new RuleResult { RuleId = "AD-001", IsVulnerable = true, RiskLevel = "High", AffectedObjects = new[] { "svc_sql" } },
            new RuleResult { RuleId = "AD-002", IsVulnerable = false, RiskLevel = "Low" }
        };

        [Fact]
        public void LogAssessment_SingleCall_WritesEntryToFile()
        {
            var logger = new AuditLogger(_tempLogFile);

            logger.LogAssessment("tester", 17, SampleResults());

            string content = File.ReadAllText(_tempLogFile);
            Assert.Contains("AUDIT_EVENT", content);
            Assert.Contains("Initiator: tester", content);
            Assert.Contains("AD-001", content);
        }

        [Fact]
        public async Task LogAssessment_ConcurrentCalls_DoNotCorruptOrLoseEntries()
        {
            // Az önce eklenen 'lock' düzeltmesinin regresyon testi: eşzamanlı
            // WebAPI istekleri aynı log dosyasına yazdığında satırların
            // birbirine karışmadığını/kaybolmadığını doğrular.
            var logger = new AuditLogger(_tempLogFile);
            const int concurrentWrites = 20;

            var tasks = Enumerable.Range(0, concurrentWrites)
                .Select(i => Task.Run(() => logger.LogAssessment($"tester-{i}", i, SampleResults())))
                .ToArray();

            await Task.WhenAll(tasks);

            string[] lines = File.ReadAllLines(_tempLogFile);
            int auditEventLines = lines.Count(l => l.Contains("AUDIT_EVENT"));

            Assert.Equal(concurrentWrites, auditEventLines);
        }
    }
}
