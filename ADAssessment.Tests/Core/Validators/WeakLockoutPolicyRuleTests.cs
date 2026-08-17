using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class WeakLockoutPolicyRuleTests
    {
        private readonly WeakLockoutPolicyRule _rule = new();

        [Fact]
        public void Execute_ZeroLockoutThreshold_IsVulnerable()
        {
            var policy = new GroupPolicySecuritySettings { GpoName = "Default Domain Policy", LockoutThreshold = 0 };

            var result = _rule.Execute(new[] { policy });

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
        }

        [Fact]
        public void Execute_NonZeroLockoutThreshold_IsNotVulnerable()
        {
            var policy = new GroupPolicySecuritySettings { GpoName = "Default Domain Policy", LockoutThreshold = 5 };

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
