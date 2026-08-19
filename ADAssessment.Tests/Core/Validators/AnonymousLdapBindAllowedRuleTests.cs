using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class AnonymousLdapBindAllowedRuleTests
    {
        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new AnonymousLdapBindAllowedRule();

            var result = rule.Execute("not a settings object");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_AnonymousBindAllowed_ReportsVulnerable()
        {
            var rule = new AnonymousLdapBindAllowedRule();
            var settings = new LdapProtocolSecuritySettings { DomainController = "DC01.lab.local", IsAnonymousBindAllowed = true };

            var result = rule.Execute(settings);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
            Assert.Contains("DC01.lab.local", result.AffectedObjects);
        }

        [Fact]
        public void Execute_AnonymousBindNotAllowed_NotVulnerable()
        {
            var rule = new AnonymousLdapBindAllowedRule();
            var settings = new LdapProtocolSecuritySettings { DomainController = "DC01.lab.local", IsAnonymousBindAllowed = false };

            var result = rule.Execute(settings);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Low", result.RiskLevel);
        }
    }
}
