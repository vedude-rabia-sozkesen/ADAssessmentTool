using System;
using System.Collections.Generic;
using System.Linq;

namespace ADAssessment.Core
{
    /// <summary>
    /// Yönetici raporu deliverable'ının ("yüksek seviye güvenlik skorları") gerektirdiği,
    /// tek bir taramanın tüm bulgularını 0-100 arası tek bir güvenlik skoruna indirgeyen
    /// saf (I/O'suz, test edilebilir) hesaplama. RuleEvaluator'ın kural bazlı mantığından
    /// bağımsız - girdisi zaten üretilmiş RuleResult listesi.
    /// </summary>
    public static class SecurityScoreCalculator
    {
        private const int StartingScore = 100;

        // Risk seviyesine göre ceza puanı - "High" bir Kerberoasting zafiyeti, bir
        // "Low" seviyeli bulgudan çok daha fazla puan kaybettirmeli. "Informational"
        // (veri sağlanamadı) hiç puan kaybettirmez - kontrol edilememek, güvensiz
        // olmak demek değildir.
        private static readonly Dictionary<string, int> PenaltyByRiskLevel = new(StringComparer.OrdinalIgnoreCase)
        {
            ["High"] = 8,
            ["Medium"] = 4,
            ["Low"] = 2
        };

        public static SecurityScoreResult Calculate(IReadOnlyList<RuleResult> results)
        {
            int penalty = results
                .Where(r => r.IsVulnerable)
                .Sum(r => PenaltyByRiskLevel.TryGetValue(r.RiskLevel, out int p) ? p : 1);

            int score = Math.Max(0, Math.Min(StartingScore, StartingScore - penalty));

            string grade = score switch
            {
                >= 90 => "A",
                >= 75 => "B",
                >= 60 => "C",
                >= 40 => "D",
                _ => "F"
            };

            int highCount = results.Count(r => r.IsVulnerable && string.Equals(r.RiskLevel, "High", StringComparison.OrdinalIgnoreCase));
            int mediumCount = results.Count(r => r.IsVulnerable && string.Equals(r.RiskLevel, "Medium", StringComparison.OrdinalIgnoreCase));
            int lowCount = results.Count(r => r.IsVulnerable && string.Equals(r.RiskLevel, "Low", StringComparison.OrdinalIgnoreCase));

            return new SecurityScoreResult(score, grade, highCount, mediumCount, lowCount);
        }
    }

    public sealed record SecurityScoreResult(int Score, string Grade, int HighCount, int MediumCount, int LowCount);
}
