using System;
using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class KrbtgtPasswordAgeRuleTests
    {
        private static AdUserAccount User(string samAccountName, DateTime? passwordLastSet) => new()
        {
            SamAccountName = samAccountName,
            UserAccountControl = ValidatorTestHelpers.Enabled,
            PasswordLastSet = passwordLastSet
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new KrbtgtPasswordAgeRule();

            var result = rule.Execute("not a user list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_NoKrbtgtInList_ReturnsInformationalNonVulnerable()
        {
            var rule = new KrbtgtPasswordAgeRule();
            var users = new List<AdUserAccount> { User("jdoe", DateTime.UtcNow) };

            var result = rule.Execute(users);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_KrbtgtPasswordOlderThan180Days_ReportsVulnerable()
        {
            var rule = new KrbtgtPasswordAgeRule();
            var users = new List<AdUserAccount> { User("krbtgt", DateTime.UtcNow.AddDays(-400)) };

            var result = rule.Execute(users);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
        }

        [Fact]
        public void Execute_KrbtgtNeverSetPassword_ReportsVulnerable()
        {
            var rule = new KrbtgtPasswordAgeRule();
            var users = new List<AdUserAccount> { User("KRBTGT", null) };

            var result = rule.Execute(users);

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_KrbtgtPasswordRecentlyRotated_NotVulnerable()
        {
            var rule = new KrbtgtPasswordAgeRule();
            var users = new List<AdUserAccount> { User("krbtgt", DateTime.UtcNow.AddDays(-10)) };

            var result = rule.Execute(users);

            Assert.False(result.IsVulnerable);
        }
    }
}
