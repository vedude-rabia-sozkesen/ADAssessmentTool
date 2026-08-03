using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Logging
{
    /// <summary>
    /// Güvenlik taramalarını zaman damgası (Timestamp), kimliği ve bulunan zafiyetlerle
    /// güvenli log dosyasına yazan Audit Logger uygulaması.
    /// </summary>
    public sealed class AuditLogger : IAuditLogger
    {
        private readonly string _logFilePath;

        public AuditLogger(string? logFilePath = null)
        {
            _logFilePath = logFilePath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "audit_events.log");
        }

        public void LogAssessment(string initiator, int scannedUserCount, IEnumerable<RuleResult> results)
        {
            var ruleList = results.ToList();
            int vulnerableCount = ruleList.Count(r => r.IsVulnerable);
            string timestamp = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss UTC");

            string logEntry = $"[{timestamp}] AUDIT_EVENT | Initiator: {initiator} | ScannedUsers: {scannedUserCount} | TotalRules: {ruleList.Count} | VulnerableRules: {vulnerableCount}\n";

            foreach (var rule in ruleList.Where(r => r.IsVulnerable))
            {
                logEntry += $"   -> [VULNERABILITY] RuleId: {rule.RuleId} | Risk: {rule.RiskLevel} | AffectedCount: {rule.AffectedObjects.Count}\n";
            }

            try
            {
                File.AppendAllText(_logFilePath, logEntry + "\n");
                Console.WriteLine($"[*] [AUDIT] Tarama kaydı denetim günlüğüne işlendi: {_logFilePath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] [AUDIT HATA] Denetim izi yazılamadı: {ex.Message}");
            }
        }
    }
}
