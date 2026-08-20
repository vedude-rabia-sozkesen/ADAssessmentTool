using System;
using System.Collections.Generic;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Persistence;

namespace ADAssessment.Tests.WebAPI.Fakes
{
    /// <summary>
    /// IScanHistoryRepository'nin test projesindeki sahte implementasyonu - gerçek bir
    /// SQLite dosyasına dokunmadan AssessmentController'ın SaveScan'i çağırdığını
    /// doğrulamak için son çağrının parametrelerini saklar.
    /// </summary>
    internal sealed class FakeScanHistoryRepository : IScanHistoryRepository
    {
        public bool WasCalled { get; private set; }
        public string? LastInitiator { get; private set; }
        public int LastVulnerableRulesCount { get; private set; }
        public IReadOnlyList<ScanRuleFinding>? LastFindings { get; private set; }

        public int SaveScan(DateTime timestampUtc, string initiator, int scannedUserCount, int scannedComputerCount, int totalRulesExecuted, int vulnerableRulesCount, int securityScore, string securityGrade, IEnumerable<ScanRuleFinding> findings)
        {
            WasCalled = true;
            LastInitiator = initiator;
            LastVulnerableRulesCount = vulnerableRulesCount;
            LastFindings = new List<ScanRuleFinding>(findings);
            return 1;
        }

        public IReadOnlyList<ScanHistorySummary> GetRecentScans(int limit, int offset) => Array.Empty<ScanHistorySummary>();

        public ScanHistoryDetail? GetScanById(int id) => null;

        public IReadOnlyList<ScanHistorySummary> SearchScans(DateTime? fromUtc, DateTime? toUtc, string? initiator) => Array.Empty<ScanHistorySummary>();
    }

    /// <summary>
    /// SaveScan çağrıldığında her zaman hata fırlatan sahte implementasyon -
    /// AssessmentController'daki tarama geçmişi kaydı izolasyonunu (try/catch) test
    /// etmek için gerekli.
    /// </summary>
    internal sealed class ThrowingFakeScanHistoryRepository : IScanHistoryRepository
    {
        public int SaveScan(DateTime timestampUtc, string initiator, int scannedUserCount, int scannedComputerCount, int totalRulesExecuted, int vulnerableRulesCount, int securityScore, string securityGrade, IEnumerable<ScanRuleFinding> findings)
        {
            throw new InvalidOperationException("scan history save failed (test)");
        }

        public IReadOnlyList<ScanHistorySummary> GetRecentScans(int limit, int offset) => Array.Empty<ScanHistorySummary>();

        public ScanHistoryDetail? GetScanById(int id) => null;

        public IReadOnlyList<ScanHistorySummary> SearchScans(DateTime? fromUtc, DateTime? toUtc, string? initiator) => Array.Empty<ScanHistorySummary>();
    }
}
