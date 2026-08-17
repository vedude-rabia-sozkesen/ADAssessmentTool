using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class ReversiblePasswordEncryptionPolicyRuleTests
    {
        private readonly ReversiblePasswordEncryptionPolicyRule _rule = new();

        [Fact]
        public void Execute_ReversibleEncryptionEnabled_IsVulnerable()
        {
            var policy = new GroupPolicySecuritySettings { GpoName = "Default Domain Policy", ReversibleEncryptionEnabled = true };

            var result = _rule.Execute(new[] { policy });

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
            Assert.Contains("Default Domain Policy", result.AffectedObjects);
        }

        [Fact]
        public void Execute_ReversibleEncryptionDisabled_IsNotVulnerable()
        {
            var policy = new GroupPolicySecuritySettings { GpoName = "Default Domain Policy", ReversibleEncryptionEnabled = false };

            var result = _rule.Execute(new[] { policy });

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_InvalidDirectoryData_ReturnsInformational()
        {
            var result = _rule.Execute(null!);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }
    }
}
