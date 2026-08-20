using System;
using System.Collections.Generic;
using System.IO;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Persistence;
using Microsoft.Data.Sqlite;
using Xunit;

namespace ADAssessment.Tests.Infrastructure
{
    public class ScanHistoryRepositoryTests : IDisposable
    {
        private readonly string _tempDbPath;

        public ScanHistoryRepositoryTests()
        {
            _tempDbPath = Path.Combine(Path.GetTempPath(), "ADAssessmentTests_History_" + Guid.NewGuid() + ".db");
        }

        public void Dispose()
        {
            // Microsoft.Data.Sqlite varsayılan olarak bağlantı havuzlaması (connection
            // pooling) yapar - "using var connection" bağlantıyı C# tarafında Dispose
            // etse bile, alttaki native SQLite handle'ı havuzda açık tutulur. Dosyayı
            // silmeden önce havuzu temizlemek gerekir, aksi halde "process cannot access
            // the file" hatası alınır (gerçek bir kaynak sızıntısı değil, sadece test
            // temizliğinin havuzu hesaba katmaması).
            SqliteConnection.ClearAllPools();

            if (File.Exists(_tempDbPath))
            {
                File.Delete(_tempDbPath);
            }
        }

        private static List<ScanRuleFinding> SampleFindings() => new()
        {
            new ScanRuleFinding("AD-001", true, "High", "MITRE T1558.003", "ISO/IEC 27001:2022 - A.8.24", new[] { "svc_test" }, "Test remediation"),
            new ScanRuleFinding("AD-002", false, "Low", "MITRE T1558.004", "ISO/IEC 27001:2022 - A.8.5", Array.Empty<string>(), "N/A")
        };

        [Fact]
        public void Constructor_CreatesDatabaseFileAndFolder()
        {
            var repository = new ScanHistoryRepository(_tempDbPath);

            Assert.True(File.Exists(_tempDbPath));
            Assert.Equal(_tempDbPath, repository.DatabasePath);
        }

        [Fact]
        public void SaveScan_ThenGetScanById_RoundTripsAllFields()
        {
            var repository = new ScanHistoryRepository(_tempDbPath);
            var timestamp = new DateTime(2026, 8, 19, 10, 30, 0, DateTimeKind.Utc);

            int id = repository.SaveScan(timestamp, "burak", 18, 2, 33, 5, 72, "C", SampleFindings());

            var detail = repository.GetScanById(id);

            Assert.NotNull(detail);
            Assert.Equal("burak", detail!.Summary.Initiator);
            Assert.Equal(18, detail.Summary.ScannedUserCount);
            Assert.Equal(2, detail.Summary.ScannedComputerCount);
            Assert.Equal(72, detail.Summary.SecurityScore);
            Assert.Equal("C", detail.Summary.SecurityGrade);
            Assert.Equal(2, detail.Findings.Count);

            var firstFinding = detail.Findings[0];
            Assert.Equal("AD-001", firstFinding.RuleId);
            Assert.True(firstFinding.IsVulnerable);
            Assert.Equal("High", firstFinding.RiskLevel);
            Assert.Single(firstFinding.AffectedObjects);
            Assert.Equal("svc_test", firstFinding.AffectedObjects[0]);
        }

        [Fact]
        public void GetScanById_NonExistentId_ReturnsNull()
        {
            var repository = new ScanHistoryRepository(_tempDbPath);

            var detail = repository.GetScanById(999);

            Assert.Null(detail);
        }

        [Fact]
        public void GetRecentScans_ReturnsNewestFirst()
        {
            var repository = new ScanHistoryRepository(_tempDbPath);
            repository.SaveScan(new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc), "user1", 1, 0, 1, 0, 100, "A", SampleFindings());
            repository.SaveScan(new DateTime(2026, 8, 19, 0, 0, 0, DateTimeKind.Utc), "user2", 1, 0, 1, 0, 90, "A", SampleFindings());

            var scans = repository.GetRecentScans(limit: 10, offset: 0);

            Assert.Equal(2, scans.Count);
            Assert.Equal("user2", scans[0].Initiator);
            Assert.Equal("user1", scans[1].Initiator);
        }

        [Fact]
        public void SearchScans_FiltersByInitiator()
        {
            var repository = new ScanHistoryRepository(_tempDbPath);
            repository.SaveScan(DateTime.UtcNow, "alice", 1, 0, 1, 0, 100, "A", SampleFindings());
            repository.SaveScan(DateTime.UtcNow, "bob", 1, 0, 1, 0, 100, "A", SampleFindings());

            var results = repository.SearchScans(null, null, "alice");

            Assert.Single(results);
            Assert.Equal("alice", results[0].Initiator);
        }

        [Fact]
        public void SearchScans_FiltersByDateRange()
        {
            var repository = new ScanHistoryRepository(_tempDbPath);
            repository.SaveScan(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), "old_scan", 1, 0, 1, 0, 100, "A", SampleFindings());
            repository.SaveScan(new DateTime(2026, 8, 19, 0, 0, 0, DateTimeKind.Utc), "recent_scan", 1, 0, 1, 0, 100, "A", SampleFindings());

            var results = repository.SearchScans(new DateTime(2026, 6, 1, 0, 0, 0, DateTimeKind.Utc), null, null);

            Assert.Single(results);
            Assert.Equal("recent_scan", results[0].Initiator);
        }
    }
}
