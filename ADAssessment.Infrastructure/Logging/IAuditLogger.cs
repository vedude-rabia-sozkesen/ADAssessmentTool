using System;
using System.Collections.Generic;
using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Logging
{
    /// <summary>
    /// Güvenlik taramalarını, tetikleyen kullanıcıyı ve bulunan zafiyetleri 
    /// denetim izine (Audit Log) kaydeden arayüz. Zero Trust uyumludur.
    /// </summary>
    public interface IAuditLogger
    {
        /// <summary>
        /// Tarama işlemini ve sonuçlarını denetim günlüğüne yazar.
        /// </summary>
        void LogAssessment(string initiator, int scannedUserCount, IEnumerable<RuleResult> results);
    }
}
