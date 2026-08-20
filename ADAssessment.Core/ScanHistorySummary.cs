using System;

namespace ADAssessment.Core
{
    /// <summary>
    /// Geçmiş bir taramanın liste görünümü için hafif özeti (tam bulgu detayını taşımaz -
    /// bkz. ScanHistoryDetail). Geçmiş listesi/arama sonuçları bu tiple döner.
    /// </summary>
    public sealed record ScanHistorySummary(
        int Id,
        DateTime TimestampUtc,
        string Initiator,
        int ScannedUserCount,
        int ScannedComputerCount,
        int TotalRulesExecuted,
        int VulnerableRulesCount,
        int SecurityScore,
        string SecurityGrade);
}
