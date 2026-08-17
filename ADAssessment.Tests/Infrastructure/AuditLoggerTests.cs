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

        [Fact]
        public async Task LogAssessment_ConcurrentCalls_ProduceAnUnbrokenHashChain()
        {
            // "Önceki hash'i oku, yenisini hesapla, yaz" işleminin eşzamanlı çağrılarda
            // da atomik kaldığını (yarış durumu / zincirde çatallanma olmadığını) doğrular.
            var logger = new AuditLogger(_tempLogFile);
            const int concurrentWrites = 15;

            var tasks = Enumerable.Range(0, concurrentWrites)
                .Select(i => Task.Run(() => logger.LogAssessment($"tester-{i}", i, SampleResults())))
                .ToArray();

            await Task.WhenAll(tasks);

            AuditLogIntegrityResult result = logger.VerifyIntegrity();

            Assert.True(result.IsValid, result.FailureReason);
            Assert.Equal(concurrentWrites, result.VerifiedEntryCount);
        }

        [Fact]
        public void VerifyIntegrity_MissingFile_ReturnsValidWithZeroEntries()
        {
            var logger = new AuditLogger(_tempLogFile);

            AuditLogIntegrityResult result = logger.VerifyIntegrity();

            Assert.True(result.IsValid);
            Assert.Equal(0, result.VerifiedEntryCount);
        }

        [Fact]
        public void VerifyIntegrity_UntamperedMultiEntryLog_IsValid()
        {
            var logger = new AuditLogger(_tempLogFile);
            logger.LogAssessment("tester1", 10, SampleResults());
            logger.LogAssessment("tester2", 20, SampleResults());
            logger.LogAssessment("tester3", 30, SampleResults());

            AuditLogIntegrityResult result = logger.VerifyIntegrity();

            Assert.True(result.IsValid, result.FailureReason);
            Assert.Equal(3, result.VerifiedEntryCount);
        }

        [Fact]
        public void VerifyIntegrity_TamperedMiddleEntry_DetectsBreak()
        {
            // Az önce eklenen hash-chain düzeltmesinin asıl regresyon testi: bir saldırganın
            // (veya herhangi birinin) log dosyasındaki bir satırı sonradan değiştirmesi
            // durumunda bunun tespit edildiğini kanıtlar.
            var logger = new AuditLogger(_tempLogFile);
            logger.LogAssessment("tester1", 10, SampleResults());
            logger.LogAssessment("tester2", 20, SampleResults());
            logger.LogAssessment("tester3", 30, SampleResults());

            string content = File.ReadAllText(_tempLogFile);
            string tampered = content.Replace("Initiator: tester2", "Initiator: tester2-HACKED");
            File.WriteAllText(_tempLogFile, tampered);

            AuditLogIntegrityResult result = logger.VerifyIntegrity();

            Assert.False(result.IsValid);
            Assert.NotNull(result.FailureReason);
        }

        [Fact]
        public void VerifyIntegrity_DeletedMiddleEntry_DetectsBreak()
        {
            var logger = new AuditLogger(_tempLogFile);
            logger.LogAssessment("tester1", 10, SampleResults());
            logger.LogAssessment("tester2", 20, SampleResults());
            logger.LogAssessment("tester3", 30, SampleResults());

            // "tester2" bloğunu (başlık + detay + [CHAIN] satırı) tamamen dosyadan çıkar.
            string content = File.ReadAllText(_tempLogFile);
            int blockStart = content.IndexOf("Initiator: tester2", StringComparison.Ordinal);
            int blockLineStart = content.LastIndexOf('\n', blockStart) + 1;
            int blockEnd = content.IndexOf("\n\n", blockStart, StringComparison.Ordinal) + 2;
            string withoutBlock = content.Remove(blockLineStart, blockEnd - blockLineStart);
            File.WriteAllText(_tempLogFile, withoutBlock);

            AuditLogIntegrityResult result = logger.VerifyIntegrity();

            Assert.False(result.IsValid);
        }
    }
}
