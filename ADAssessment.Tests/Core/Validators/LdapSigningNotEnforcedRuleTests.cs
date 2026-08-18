using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class LdapSigningNotEnforcedRuleTests
    {
        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new LdapSigningNotEnforcedRule();

            var result = rule.Execute("not a settings object");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_SigningNotEnforced_ReportsVulnerable()
        {
            var rule = new LdapSigningNotEnforcedRule();
            var settings = new LdapProtocolSecuritySettings { DomainController = "DC01.lab.local", IsSigningEnforced = false };

            var result = rule.Execute(settings);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
            Assert.Contains("DC01.lab.local", result.AffectedObjects);
        }

        [Fact]
        public void Execute_SigningEnforced_NotVulnerable()
        {
            var rule = new LdapSigningNotEnforcedRule();
            var settings = new LdapProtocolSecuritySettings { DomainController = "DC01.lab.local", IsSigningEnforced = true };

            var result = rule.Execute(settings);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Low", result.RiskLevel);
        }
    }
}
