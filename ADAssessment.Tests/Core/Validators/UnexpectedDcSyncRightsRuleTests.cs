using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class UnexpectedDcSyncRightsRuleTests
    {
        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new UnexpectedDcSyncRightsRule();

            var result = rule.Execute("not a settings object");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_UnexpectedPrincipalPresent_ReportsVulnerable()
        {
            var rule = new UnexpectedDcSyncRightsRule();
            var settings = new DcSyncRightsSettings
            {
                DomainDistinguishedName = "DC=lab,DC=local",
                UnexpectedPrincipals = new List<string> { "LAB\\svc-backup" }
            };

            var result = rule.Execute(settings);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
            Assert.Contains("LAB\\svc-backup", result.AffectedObjects);
        }

        [Fact]
        public void Execute_NoUnexpectedPrincipals_NotVulnerable()
        {
            var rule = new UnexpectedDcSyncRightsRule();
            var settings = new DcSyncRightsSettings
            {
                DomainDistinguishedName = "DC=lab,DC=local",
                UnexpectedPrincipals = System.Array.Empty<string>()
            };

            var result = rule.Execute(settings);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Low", result.RiskLevel);
        }
    }
}
