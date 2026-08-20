using System;
using System.Collections.Generic;
using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Persistence
{
    /// <summary>
    /// Tamamlanmış taramaların kalıcı (aranabilir) geçmişini saklayan/sorgulayan depo.
    /// Denetim izi (IAuditLogger, hash-zincirli, kurcalanamaz) ile aynı işi yapmaz - o
    /// "bu tarama gerçekten oldu, değiştirilmedi" kanıtı için var; bu depo "geçmiş
    /// taramalara sonradan bakabilme/arayabilme" için var. İkisi birlikte, tek biri değil.
    /// </summary>
    public interface IScanHistoryRepository
    {
        /// <summary>
        /// Tamamlanmış bir taramayı kalıcı olarak kaydeder. Döndürülen değer, o taramanın
        /// veritabanındaki kimliği (ScanRuns.Id) - GetScanById ile tekrar çekilebilir.
        /// </summary>
        int SaveScan(
            DateTime timestampUtc,
            string initiator,
            int scannedUserCount,
            int scannedComputerCount,
            int totalRulesExecuted,
            int vulnerableRulesCount,
            int securityScore,
            string securityGrade,
            IEnumerable<ScanRuleFinding> findings);

        IReadOnlyList<ScanHistorySummary> GetRecentScans(int limit, int offset);

        ScanHistoryDetail? GetScanById(int id);

        IReadOnlyList<ScanHistorySummary> SearchScans(DateTime? fromUtc, DateTime? toUtc, string? initiator);
    }
}
