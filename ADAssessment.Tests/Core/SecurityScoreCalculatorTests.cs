using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core
{
    public class SecurityScoreCalculatorTests
    {
        [Fact]
        public void Calculate_NoVulnerabilities_ReturnsPerfectScoreAndGradeA()
        {
            var results = new List<RuleResult>
            {
                new RuleResult { RuleId = "AD-001", IsVulnerable = false, RiskLevel = "High" },
                new RuleResult { RuleId = "AD-002", IsVulnerable = false, RiskLevel = "Medium" }
            };

            var score = SecurityScoreCalculator.Calculate(results);

            Assert.Equal(100, score.Score);
            Assert.Equal("A", score.Grade);
            Assert.Equal(0, score.HighCount);
        }

        [Fact]
        public void Calculate_InformationalFindings_DoNotAffectScore()
        {
            var results = new List<RuleResult>
            {
                new RuleResult { RuleId = "AD-013", IsVulnerable = false, RiskLevel = "Informational" }
            };

            var score = SecurityScoreCalculator.Calculate(results);

            Assert.Equal(100, score.Score);
        }

        [Fact]
        public void Calculate_HighRiskVulnerability_PenalizesMoreThanLow()
        {
            var highOnly = new List<RuleResult> { new RuleResult { RuleId = "AD-001", IsVulnerable = true, RiskLevel = "High" } };
            var lowOnly = new List<RuleResult> { new RuleResult { RuleId = "AD-001", IsVulnerable = true, RiskLevel = "Low" } };

            var highScore = SecurityScoreCalculator.Calculate(highOnly);
            var lowScore = SecurityScoreCalculator.Calculate(lowOnly);

            Assert.True(highScore.Score < lowScore.Score);
        }

        [Fact]
        public void Calculate_ManyHighRiskVulnerabilities_ScoreFloorsAtZero_NotNegative()
        {
            var results = new List<RuleResult>();
            for (int i = 0; i < 20; i++)
            {
                results.Add(new RuleResult { RuleId = $"AD-{i:000}", IsVulnerable = true, RiskLevel = "High" });
            }

            var score = SecurityScoreCalculator.Calculate(results);

            Assert.Equal(0, score.Score);
            Assert.Equal("F", score.Grade);
        }

        [Fact]
        public void Calculate_CountsByRiskLevel_MatchInput()
        {
            var results = new List<RuleResult>
            {
                new RuleResult { RuleId = "AD-001", IsVulnerable = true, RiskLevel = "High" },
                new RuleResult { RuleId = "AD-002", IsVulnerable = true, RiskLevel = "High" },
                new RuleResult { RuleId = "AD-003", IsVulnerable = true, RiskLevel = "Medium" },
                new RuleResult { RuleId = "AD-004", IsVulnerable = true, RiskLevel = "Low" },
                new RuleResult { RuleId = "AD-005", IsVulnerable = false, RiskLevel = "High" }
            };

            var score = SecurityScoreCalculator.Calculate(results);

            Assert.Equal(2, score.HighCount);
            Assert.Equal(1, score.MediumCount);
            Assert.Equal(1, score.LowCount);
        }
    }
}
