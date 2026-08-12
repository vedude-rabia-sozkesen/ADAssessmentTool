using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class UnconstrainedDelegationRuleTests
    {
        private readonly UnconstrainedDelegationRule _rule = new();
        private const int TrustedForDelegation = 0x80000;

        [Fact]
        public void Execute_EnabledUserWithUnconstrainedDelegation_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("svc_web", ValidatorTestHelpers.Enabled | TrustedForDelegation);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
        }

        [Fact]
        public void Execute_DisabledUserWithUnconstrainedDelegation_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("svc_web", ValidatorTestHelpers.Disabled | TrustedForDelegation);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserWithoutDelegation_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("jdoe", ValidatorTestHelpers.Enabled);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }
    }
}
