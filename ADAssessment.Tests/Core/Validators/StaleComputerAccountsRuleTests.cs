using System;
using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class StaleComputerAccountsRuleTests
    {
        private static AdComputerAccount Computer(string name, int uac, DateTime? lastLogon) => new()
        {
            SamAccountName = name,
            UserAccountControl = uac,
            LastLogonTimestamp = lastLogon
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new StaleComputerAccountsRule();

            var result = rule.Execute("not a computer list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_EnabledComputerWithOldLastLogon_ReportsVulnerable()
        {
            var rule = new StaleComputerAccountsRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("OLD-PC$", ValidatorTestHelpers.Enabled, DateTime.UtcNow.AddDays(-200))
            };

            var result = rule.Execute(computers);

            Assert.True(result.IsVulnerable);
            Assert.Contains("OLD-PC$", result.AffectedObjects[0]);
        }

        [Fact]
        public void Execute_EnabledComputerNeverLoggedOn_ReportsVulnerable()
        {
            var rule = new StaleComputerAccountsRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("NEVER-PC$", ValidatorTestHelpers.Enabled, null)
            };

            var result = rule.Execute(computers);

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_RecentlyActiveComputer_NotVulnerable()
        {
            var rule = new StaleComputerAccountsRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("ACTIVE-PC$", ValidatorTestHelpers.Enabled, DateTime.UtcNow.AddDays(-5))
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledStaleComputer_NotVulnerable()
        {
            var rule = new StaleComputerAccountsRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("DISABLED-PC$", ValidatorTestHelpers.Disabled, DateTime.UtcNow.AddDays(-500))
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }
    }
}
