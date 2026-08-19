using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class SidHistoryPresentRuleTests
    {
        private static AdUserAccount User(string name, bool hasSidHistory) => new()
        {
            SamAccountName = name,
            UserAccountControl = ValidatorTestHelpers.Enabled,
            HasSidHistory = hasSidHistory
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new SidHistoryPresentRule();

            var result = rule.Execute("not a user list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_UserWithSidHistory_ReportsVulnerable()
        {
            var rule = new SidHistoryPresentRule();
            var users = new List<AdUserAccount> { User("migrated_user", hasSidHistory: true) };

            var result = rule.Execute(users);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
            Assert.Contains("migrated_user", result.AffectedObjects[0]);
        }

        [Fact]
        public void Execute_UserWithoutSidHistory_NotVulnerable()
        {
            var rule = new SidHistoryPresentRule();
            var users = new List<AdUserAccount> { User("normal_user", hasSidHistory: false) };

            var result = rule.Execute(users);

            Assert.False(result.IsVulnerable);
        }
    }
}
