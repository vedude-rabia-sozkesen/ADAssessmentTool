using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class LdapChannelBindingNotEnforcedRuleTests
    {
        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new LdapChannelBindingNotEnforcedRule();

            var result = rule.Execute("not a settings object");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_ChannelBindingNotEnforced_ReportsVulnerable()
        {
            var rule = new LdapChannelBindingNotEnforcedRule();
            var settings = new LdapProtocolSecuritySettings { DomainController = "DC01.lab.local", IsChannelBindingEnforced = false };

            var result = rule.Execute(settings);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
            Assert.Contains("DC01.lab.local", result.AffectedObjects);
        }

        [Fact]
        public void Execute_ChannelBindingEnforced_NotVulnerable()
        {
            var rule = new LdapChannelBindingNotEnforcedRule();
            var settings = new LdapProtocolSecuritySettings { DomainController = "DC01.lab.local", IsChannelBindingEnforced = true };

            var result = rule.Execute(settings);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Low", result.RiskLevel);
        }
    }
}
