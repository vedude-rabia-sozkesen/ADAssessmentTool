using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class UnexpectedResourceBasedConstrainedDelegationRuleTests
    {
        private static AdComputerAccount Computer(string name, IReadOnlyList<string> rbcdPrincipals) => new()
        {
            SamAccountName = name,
            UserAccountControl = ValidatorTestHelpers.Enabled,
            ResourceBasedConstrainedDelegationPrincipals = rbcdPrincipals
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new UnexpectedResourceBasedConstrainedDelegationRule();

            var result = rule.Execute("not a computer list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_ComputerWithRbcdPrincipal_ReportsVulnerable()
        {
            var rule = new UnexpectedResourceBasedConstrainedDelegationRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("FILESERVER01$", new[] { "LAB\\test_svc" })
            };

            var result = rule.Execute(computers);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
            Assert.Contains("FILESERVER01$", result.AffectedObjects[0]);
            Assert.Contains("test_svc", result.AffectedObjects[0]);
        }

        [Fact]
        public void Execute_ComputerWithoutRbcd_NotVulnerable()
        {
            var rule = new UnexpectedResourceBasedConstrainedDelegationRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("NORMAL-PC$", System.Array.Empty<string>())
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }
    }
}
