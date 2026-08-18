using System;
using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class StaleComputerPasswordRuleTests
    {
        private static AdComputerAccount Computer(string name, int uac, DateTime? passwordLastSet) => new()
        {
            SamAccountName = name,
            UserAccountControl = uac,
            PasswordLastSet = passwordLastSet
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new StaleComputerPasswordRule();

            var result = rule.Execute("not a computer list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_EnabledComputerWithStalePassword_ReportsVulnerable()
        {
            var rule = new StaleComputerPasswordRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("STALE-PW$", ValidatorTestHelpers.Enabled, DateTime.UtcNow.AddDays(-120))
            };

            var result = rule.Execute(computers);

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledComputerWithRecentPassword_NotVulnerable()
        {
            var rule = new StaleComputerPasswordRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("FRESH-PW$", ValidatorTestHelpers.Enabled, DateTime.UtcNow.AddDays(-10))
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledComputerWithStalePassword_NotVulnerable()
        {
            var rule = new StaleComputerPasswordRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("DISABLED-PW$", ValidatorTestHelpers.Disabled, DateTime.UtcNow.AddDays(-400))
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }
    }
}
