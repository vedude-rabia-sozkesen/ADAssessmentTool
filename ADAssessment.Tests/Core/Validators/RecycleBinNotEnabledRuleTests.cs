using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class RecycleBinNotEnabledRuleTests
    {
        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new RecycleBinNotEnabledRule();

            var result = rule.Execute("not forest settings");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_UnknownState_ReturnsInformationalNonVulnerable()
        {
            var rule = new RecycleBinNotEnabledRule();
            var settings = new ForestOptionalFeatureSettings { IsRecycleBinEnabled = null };

            var result = rule.Execute(settings);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_RecycleBinDisabled_ReportsVulnerable()
        {
            var rule = new RecycleBinNotEnabledRule();
            var settings = new ForestOptionalFeatureSettings { IsRecycleBinEnabled = false };

            var result = rule.Execute(settings);

            Assert.True(result.IsVulnerable);
            Assert.Equal("Medium", result.RiskLevel);
        }

        [Fact]
        public void Execute_RecycleBinEnabled_NotVulnerable()
        {
            var rule = new RecycleBinNotEnabledRule();
            var settings = new ForestOptionalFeatureSettings { IsRecycleBinEnabled = true };

            var result = rule.Execute(settings);

            Assert.False(result.IsVulnerable);
        }
    }
}
