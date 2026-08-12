using System.Collections.Generic;
using ADAssessment.Core;

namespace ADAssessment.Tests.Core
{
    public class DynamicComplianceRuleTests
    {
        private static JsonRuleDefinition MakeDefinition() => new JsonRuleDefinition
        {
            RuleId = "AD-011",
            Name = "Password Not Required",
            RiskLevel = "High",
            Remediation = "Fix it.",
            TargetProperty = "UserAccountControl",
            Operator = "BitwiseAND",
            Value = 32,
            Condition = "NotEqualZero"
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new DynamicComplianceRule(MakeDefinition());

            var result = rule.Execute("not a user list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_MatchingUser_ReportsVulnerableWithRuleRiskLevel()
        {
            var rule = new DynamicComplianceRule(MakeDefinition());
            var users = new List<AdUserAccount>
            {
                new AdUserAccount { SamAccountName = "nopass", UserAccountControl = 0x0200 | 0x20 }
            };

            var result = rule.Execute(users);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
            Assert.Contains(result.AffectedObjects, a => a.Contains("nopass"));
        }

        [Fact]
        public void Execute_NoMatchingUsers_ReportsLowRiskNotVulnerable()
        {
            var rule = new DynamicComplianceRule(MakeDefinition());
            var users = new List<AdUserAccount>
            {
                new AdUserAccount { SamAccountName = "normal", UserAccountControl = 0x0200 }
            };

            var result = rule.Execute(users);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Low", result.RiskLevel);
            Assert.Empty(result.AffectedObjects);
        }

        [Fact]
        public void Execute_PrivilegedAffectedAccount_IsTaggedCritical()
        {
            var rule = new DynamicComplianceRule(MakeDefinition());
            var users = new List<AdUserAccount>
            {
                new AdUserAccount { SamAccountName = "admin1", UserAccountControl = 0x0200 | 0x20, IsAdminCountSet = true }
            };

            var result = rule.Execute(users);

            Assert.Contains(result.AffectedObjects, a => a.Contains("[KRİTİK YETKİLİ]") && a.Contains("admin1"));
        }
    }
}
