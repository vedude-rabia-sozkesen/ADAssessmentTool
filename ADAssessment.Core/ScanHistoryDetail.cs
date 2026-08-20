using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Geçmiş bir taramanın tam detayı - özet bilgiler (Summary) + o taramadaki her kuralın
    /// tam sonucu (Findings). Bir geçmiş taramanın tam raporunu yeniden oluşturmak için yeterli.
    /// </summary>
    public sealed record ScanHistoryDetail(
        ScanHistorySummary Summary,
        IReadOnlyList<ScanRuleFinding> Findings);
}
