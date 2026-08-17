using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class WeakPasswordPolicyRuleTests
    {
        private readonly WeakPasswordPolicyRule _rule = new();

        private static GroupPolicySecuritySettings StrongPolicy() => new()
        {
            GpoName = "Default Domain Policy",
            MinimumPasswordLength = 16,
            PasswordComplexityEnabled = true,
            MaximumPasswordAgeDays = 90
        };

        [Fact]
        public void Execute_ShortMinimumLength_IsVulnerable()
        {
            var weak = new GroupPolicySecuritySettings
            {
                GpoName = "Default Domain Policy",
                MinimumPasswordLength = 6,
                PasswordComplexityEnabled = true,
                MaximumPasswordAgeDays = 90
            };

            var result = _rule.Execute(new[] { weak });

            Assert.True(result.IsVulnerable);
            Assert.Contains(result.AffectedObjects, a => a.Contains("Default Domain Policy"));
        }

        [Fact]
        public void Execute_ComplexityDisabled_IsVulnerable()
        {
            var weak = new GroupPolicySecuritySettings
            {
                GpoName = "Default Domain Policy",
                MinimumPasswordLength = 16,
                PasswordComplexityEnabled = false,
                MaximumPasswordAgeDays = 90
            };

            var result = _rule.Execute(new[] { weak });

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_PasswordNeverExpires_IsVulnerable()
        {
            var weak = new GroupPolicySecuritySettings
            {
                GpoName = "Default Domain Policy",
                MinimumPasswordLength = 16,
                PasswordComplexityEnabled = true,
                MaximumPasswordAgeDays = 0
            };

            var result = _rule.Execute(new[] { weak });

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_StrongPolicy_IsNotVulnerable()
        {
            var result = _rule.Execute(new[] { StrongPolicy() });

            Assert.False(result.IsVulnerable);
            Assert.Equal("Low", result.RiskLevel);
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
