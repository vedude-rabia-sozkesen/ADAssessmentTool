using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text.Json;
using ADAssessment.Core;
using Microsoft.Data.Sqlite;

namespace ADAssessment.Infrastructure.Persistence
{
    /// <summary>
    /// IScanHistoryRepository'nin yerel, sunucusuz SQLite tabanlı implementasyonu.
    /// Zero Trust: veritabanı dosyası tamamen yerel diskte durur, hiçbir ağ bağlantısı
    /// açmaz. EF Core gibi bir ORM yerine bilerek ham/parametreli SQL kullanılır - proje
    /// zaten System.DirectoryServices'i doğrudan (sarmalayıcı kütüphane olmadan) kullanma
    /// felsefesindeydi, burada da aynı minimal-bağımlılık yaklaşımı sürdürülür.
    /// </summary>
    public sealed class ScanHistoryRepository : IScanHistoryRepository
    {
        private readonly string _connectionString;

        /// <summary>Bu depo örneğinin okuduğu/yazdığı gerçek dosya yolu (testlerde doğrulamak için).</summary>
        public string DatabasePath { get; }

        public ScanHistoryRepository(string? databasePath = null)
        {
            DatabasePath = databasePath ?? ResolveDefaultDatabasePath();

            string? directory = Path.GetDirectoryName(DatabasePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            _connectionString = new SqliteConnectionStringBuilder { DataSource = DatabasePath }.ToString();
            EnsureSchema();
        }

        /// <summary>
        /// JsonRuleRepository.ResolveDefaultRulesFolder ile birebir aynı desen: makine-geneli
        /// %ProgramData% konumu (WebAPI ve ConsoleApp hangisinden çalıştırılırsa çalıştırılsın
        /// aynı geçmişi görsün diye), AD_ASSESSMENT_DB_PATH env var'ı ile geçersiz kılınabilir.
        /// </summary>
        private static string ResolveDefaultDatabasePath()
        {
            string? envOverride = Environment.GetEnvironmentVariable("AD_ASSESSMENT_DB_PATH");
            if (!string.IsNullOrWhiteSpace(envOverride))
            {
                return envOverride;
            }

            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(programData, "ADAssessmentTool", "scan_history.db");
        }

        private void EnsureSchema()
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                CREATE TABLE IF NOT EXISTS ScanRuns (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    TimestampUtc TEXT NOT NULL,
                    Initiator TEXT NOT NULL,
                    ScannedUserCount INTEGER NOT NULL,
                    ScannedComputerCount INTEGER NOT NULL,
                    TotalRulesExecuted INTEGER NOT NULL,
                    VulnerableRulesCount INTEGER NOT NULL,
                    SecurityScore INTEGER NOT NULL,
                    SecurityGrade TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ScanRuleResults (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ScanRunId INTEGER NOT NULL REFERENCES ScanRuns(Id),
                    RuleId TEXT NOT NULL,
                    IsVulnerable INTEGER NOT NULL,
                    RiskLevel TEXT NOT NULL,
                    FrameworkMapping TEXT NOT NULL,
                    Iso27001Mapping TEXT NOT NULL,
                    AffectedObjectsJson TEXT NOT NULL,
                    Remediation TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS IX_ScanRuleResults_ScanRunId ON ScanRuleResults(ScanRunId);
                CREATE INDEX IF NOT EXISTS IX_ScanRuns_TimestampUtc ON ScanRuns(TimestampUtc);
            ";
            command.ExecuteNonQuery();
        }

        public int SaveScan(
            DateTime timestampUtc,
            string initiator,
            int scannedUserCount,
            int scannedComputerCount,
            int totalRulesExecuted,
            int vulnerableRulesCount,
            int securityScore,
            string securityGrade,
            IEnumerable<ScanRuleFinding> findings)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var transaction = connection.BeginTransaction();

            long scanRunId;
            using (var insertRun = connection.CreateCommand())
            {
                insertRun.Transaction = transaction;
                insertRun.CommandText = @"
                    INSERT INTO ScanRuns (TimestampUtc, Initiator, ScannedUserCount, ScannedComputerCount, TotalRulesExecuted, VulnerableRulesCount, SecurityScore, SecurityGrade)
                    VALUES ($timestamp, $initiator, $users, $computers, $totalRules, $vulnerable, $score, $grade);
                    SELECT last_insert_rowid();";
                insertRun.Parameters.AddWithValue("$timestamp", timestampUtc.ToString("o", CultureInfo.InvariantCulture));
                insertRun.Parameters.AddWithValue("$initiator", initiator);
                insertRun.Parameters.AddWithValue("$users", scannedUserCount);
                insertRun.Parameters.AddWithValue("$computers", scannedComputerCount);
                insertRun.Parameters.AddWithValue("$totalRules", totalRulesExecuted);
                insertRun.Parameters.AddWithValue("$vulnerable", vulnerableRulesCount);
                insertRun.Parameters.AddWithValue("$score", securityScore);
                insertRun.Parameters.AddWithValue("$grade", securityGrade);
                scanRunId = (long)insertRun.ExecuteScalar()!;
            }

            using (var insertResult = connection.CreateCommand())
            {
                insertResult.Transaction = transaction;
                insertResult.CommandText = @"
                    INSERT INTO ScanRuleResults (ScanRunId, RuleId, IsVulnerable, RiskLevel, FrameworkMapping, Iso27001Mapping, AffectedObjectsJson, Remediation)
                    VALUES ($scanRunId, $ruleId, $isVulnerable, $riskLevel, $framework, $iso, $affected, $remediation);";
                var pScanRunId = insertResult.Parameters.Add("$scanRunId", SqliteType.Integer);
                var pRuleId = insertResult.Parameters.Add("$ruleId", SqliteType.Text);
                var pIsVulnerable = insertResult.Parameters.Add("$isVulnerable", SqliteType.Integer);
                var pRiskLevel = insertResult.Parameters.Add("$riskLevel", SqliteType.Text);
                var pFramework = insertResult.Parameters.Add("$framework", SqliteType.Text);
                var pIso = insertResult.Parameters.Add("$iso", SqliteType.Text);
                var pAffected = insertResult.Parameters.Add("$affected", SqliteType.Text);
                var pRemediation = insertResult.Parameters.Add("$remediation", SqliteType.Text);

                foreach (var finding in findings)
                {
                    pScanRunId.Value = scanRunId;
                    pRuleId.Value = finding.RuleId;
                    pIsVulnerable.Value = finding.IsVulnerable ? 1 : 0;
                    pRiskLevel.Value = finding.RiskLevel;
                    pFramework.Value = finding.FrameworkMapping;
                    pIso.Value = finding.Iso27001Mapping;
                    pAffected.Value = JsonSerializer.Serialize(finding.AffectedObjects);
                    pRemediation.Value = finding.Remediation;
                    insertResult.ExecuteNonQuery();
                }
            }

            transaction.Commit();
            return (int)scanRunId;
        }

        public IReadOnlyList<ScanHistorySummary> GetRecentScans(int limit, int offset)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = @"
                SELECT Id, TimestampUtc, Initiator, ScannedUserCount, ScannedComputerCount, TotalRulesExecuted, VulnerableRulesCount, SecurityScore, SecurityGrade
                FROM ScanRuns
                ORDER BY TimestampUtc DESC
                LIMIT $limit OFFSET $offset;";
            command.Parameters.AddWithValue("$limit", limit);
            command.Parameters.AddWithValue("$offset", offset);

            var results = new List<ScanHistorySummary>();
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                results.Add(ReadSummary(reader));
            }
            return results;
        }

        public ScanHistoryDetail? GetScanById(int id)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            ScanHistorySummary? summary = null;
            using (var command = connection.CreateCommand())
            {
                command.CommandText = @"
                    SELECT Id, TimestampUtc, Initiator, ScannedUserCount, ScannedComputerCount, TotalRulesExecuted, VulnerableRulesCount, SecurityScore, SecurityGrade
                    FROM ScanRuns WHERE Id = $id;";
                command.Parameters.AddWithValue("$id", id);
                using var reader = command.ExecuteReader();
                if (reader.Read())
                {
                    summary = ReadSummary(reader);
                }
            }

            if (summary == null)
            {
                return null;
            }

            var findings = new List<ScanRuleFinding>();
            using (var command = connection.CreateCommand())
            {
                command.CommandText = @"
                    SELECT RuleId, IsVulnerable, RiskLevel, FrameworkMapping, Iso27001Mapping, AffectedObjectsJson, Remediation
                    FROM ScanRuleResults WHERE ScanRunId = $id;";
                command.Parameters.AddWithValue("$id", id);
                using var reader = command.ExecuteReader();
                while (reader.Read())
                {
                    var affected = JsonSerializer.Deserialize<List<string>>(reader.GetString(5)) ?? new List<string>();
                    findings.Add(new ScanRuleFinding(
                        reader.GetString(0),
                        reader.GetInt32(1) != 0,
                        reader.GetString(2),
                        reader.GetString(3),
                        reader.GetString(4),
                        affected,
                        reader.GetString(6)));
                }
            }

            return new ScanHistoryDetail(summary, findings);
        }

        public IReadOnlyList<ScanHistorySummary> SearchScans(DateTime? fromUtc, DateTime? toUtc, string? initiator)
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();
            using var command = connection.CreateCommand();

            // Koşul metinleri SABİT/literal string'lerdir (kullanıcı girdisinden gelmez) -
            // sadece hangi WHERE parçalarının dahil edileceğini belirler. Gerçek değerler
            // (fromUtc/toUtc/initiator) her zaman parametre olarak ($from, $to, $initiator)
            // geçilir - bu yüzden SQL injection riski taşımaz.
            var conditions = new List<string>();
            if (fromUtc.HasValue)
            {
                conditions.Add("TimestampUtc >= $from");
                command.Parameters.AddWithValue("$from", fromUtc.Value.ToString("o", CultureInfo.InvariantCulture));
            }
            if (toUtc.HasValue)
            {
                conditions.Add("TimestampUtc <= $to");
                command.Parameters.AddWithValue("$to", toUtc.Value.ToString("o", CultureInfo.InvariantCulture));
            }
            if (!string.IsNullOrWhiteSpace(initiator))
            {
                conditions.Add("Initiator = $initiator");
                command.Parameters.AddWithValue("$initiator", initiator);
            }

            string whereClause = conditions.Count > 0 ? "WHERE " + string.Join(" AND ", conditions) : string.Empty;
            command.CommandText = $@"
                SELECT Id, TimestampUtc, Initiator, ScannedUserCount, ScannedComputerCount, TotalRulesExecuted, VulnerableRulesCount, SecurityScore, SecurityGrade
                FROM ScanRuns
                {whereClause}
                ORDER BY TimestampUtc DESC;";

            var results = new List<ScanHistorySummary>();
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                results.Add(ReadSummary(reader));
            }
            return results;
        }

        private static ScanHistorySummary ReadSummary(SqliteDataReader reader)
        {
            return new ScanHistorySummary(
                reader.GetInt32(0),
                DateTime.Parse(reader.GetString(1), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
                reader.GetString(2),
                reader.GetInt32(3),
                reader.GetInt32(4),
                reader.GetInt32(5),
                reader.GetInt32(6),
                reader.GetInt32(7),
                reader.GetString(8));
        }
    }
}
