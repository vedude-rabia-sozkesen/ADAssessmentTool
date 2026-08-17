using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Logging
{
    /// <summary>
    /// Güvenlik taramalarını zaman damgası (Timestamp), kimliği ve bulunan zafiyetlerle
    /// güvenli log dosyasına yazan Audit Logger uygulaması. OWASP A09 (Security Logging &amp;
    /// Monitoring Failures) gereği, her kayıt bir önceki kaydın SHA-256 hash'ini içerecek
    /// şekilde zincirlenir (hash-chain) - dosya üzerinde sonradan yapılan bir değişiklik
    /// (satır silme/düzenleme) zinciri kırar ve <see cref="VerifyIntegrity"/> ile tespit edilebilir.
    /// </summary>
    public sealed class AuditLogger : IAuditLogger
    {
        private const string GenesisHash = "GENESIS";
        private static readonly Regex ChainLinePattern = new(
            @"\[CHAIN\] PrevHash: (?<prev>\S+) \| EntryHash: (?<entry>\S+)",
            RegexOptions.Compiled);

        private readonly string _logFilePath;
        private readonly object _syncRoot = new();

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
                // Eşzamanlı (concurrent) WebAPI istekleri aynı log dosyasına yazabileceğinden
                // hem satırların karışmasını/kaybolmasını önlemek hem de "önceki hash'i oku,
                // yeni hash'i hesapla, yaz" işleminin bölünmez (atomic) kalmasını sağlamak için
                // tamamı aynı kilit altında yapılır.
                lock (_syncRoot)
                {
                    string previousHash = ReadLastEntryHash();
                    string entryHash = ComputeEntryHash(previousHash, logEntry);
                    string chainedEntry = logEntry + $"   [CHAIN] PrevHash: {previousHash} | EntryHash: {entryHash}\n";

                    File.AppendAllText(_logFilePath, chainedEntry + "\n");
                }
                Console.WriteLine($"[*] [AUDIT] Tarama kaydı denetim günlüğüne işlendi: {_logFilePath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] [AUDIT HATA] Denetim izi yazılamadı: {ex.Message}");
            }
        }

        /// <summary>
        /// Log dosyasındaki hash zincirinin baştan sona kırılmadığını doğrular. Bir saldırgan
        /// (veya herhangi biri) dosyadaki bir kaydı silse, değiştirse veya araya yeni bir kayıt
        /// eklese, zincirdeki ilgili noktadan itibaren doğrulama başarısız olur.
        /// </summary>
        public AuditLogIntegrityResult VerifyIntegrity()
        {
            if (!File.Exists(_logFilePath))
            {
                return new AuditLogIntegrityResult(true, 0, null);
            }

            List<string> blocks;
            lock (_syncRoot)
            {
                blocks = SplitIntoBlocks(File.ReadAllText(_logFilePath));
            }

            string expectedPrevHash = GenesisHash;
            int blockIndex = 0;

            foreach (string block in blocks)
            {
                blockIndex++;
                string[] lines = block.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                string? chainLine = lines.LastOrDefault(l => l.Contains("[CHAIN]"));

                if (chainLine == null)
                {
                    return new AuditLogIntegrityResult(false, blockIndex, $"Kayıt {blockIndex}: [CHAIN] satırı bulunamadı.");
                }

                Match match = ChainLinePattern.Match(chainLine);
                if (!match.Success)
                {
                    return new AuditLogIntegrityResult(false, blockIndex, $"Kayıt {blockIndex}: [CHAIN] satırı ayrıştırılamadı.");
                }

                string declaredPrevHash = match.Groups["prev"].Value;
                string declaredEntryHash = match.Groups["entry"].Value;

                if (!string.Equals(declaredPrevHash, expectedPrevHash, StringComparison.Ordinal))
                {
                    return new AuditLogIntegrityResult(false, blockIndex,
                        $"Kayıt {blockIndex}: zincir kopuk (beklenen önceki hash: {expectedPrevHash}, dosyada bulunan: {declaredPrevHash}). Kayıtlar arasına ekleme/çıkarma yapılmış olabilir.");
                }

                string contentWithoutChainLine = string.Join("\n", lines.Where(l => l != chainLine)) + "\n";
                string recomputedHash = ComputeEntryHash(declaredPrevHash, contentWithoutChainLine);

                if (!string.Equals(recomputedHash, declaredEntryHash, StringComparison.Ordinal))
                {
                    return new AuditLogIntegrityResult(false, blockIndex,
                        $"Kayıt {blockIndex}: içerik hash'i uyuşmuyor - bu kayıt yazıldıktan sonra değiştirilmiş olabilir.");
                }

                expectedPrevHash = declaredEntryHash;
            }

            return new AuditLogIntegrityResult(true, blockIndex, null);
        }

        private string ReadLastEntryHash()
        {
            if (!File.Exists(_logFilePath))
            {
                return GenesisHash;
            }

            foreach (string line in File.ReadLines(_logFilePath).Reverse())
            {
                Match match = ChainLinePattern.Match(line);
                if (match.Success)
                {
                    return match.Groups["entry"].Value;
                }
            }

            return GenesisHash;
        }

        private static string ComputeEntryHash(string previousHash, string entryContent)
        {
            byte[] inputBytes = Encoding.UTF8.GetBytes(previousHash + "\n" + entryContent);
            byte[] hashBytes = SHA256.HashData(inputBytes);
            return Convert.ToHexString(hashBytes);
        }

        /// <summary>
        /// Ham log dosyası içeriğini, her biri bir "AUDIT_EVENT" başlık satırıyla başlayan
        /// kayıt bloklarına ayırır.
        /// </summary>
        private static List<string> SplitIntoBlocks(string fileContent)
        {
            var blocks = new List<string>();
            var currentBlockLines = new List<string>();

            foreach (string rawLine in fileContent.Split('\n'))
            {
                string line = rawLine.TrimEnd('\r');

                if (line.Contains("AUDIT_EVENT") && currentBlockLines.Count > 0)
                {
                    blocks.Add(string.Join("\n", currentBlockLines) + "\n");
                    currentBlockLines.Clear();
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                currentBlockLines.Add(line);
            }

            if (currentBlockLines.Count > 0)
            {
                blocks.Add(string.Join("\n", currentBlockLines) + "\n");
            }

            return blocks;
        }
    }

    /// <summary>
    /// AuditLogger.VerifyIntegrity() sonucunu taşıyan basit veri nesnesi.
    /// </summary>
    public sealed record AuditLogIntegrityResult(bool IsValid, int VerifiedEntryCount, string? FailureReason);
}
