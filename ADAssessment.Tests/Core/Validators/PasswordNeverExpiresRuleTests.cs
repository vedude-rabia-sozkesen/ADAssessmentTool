using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class PasswordNeverExpiresRuleTests
    {
        private readonly PasswordNeverExpiresRule _rule = new();
        private const int DontExpirePassword = 0x10000;

        [Fact]
        public void Execute_EnabledUserWithNeverExpires_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("svc_app", ValidatorTestHelpers.Enabled | DontExpirePassword);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
            Assert.Equal("Medium", result.RiskLevel);
        }

        [Fact]
        public void Execute_DisabledUserWithNeverExpires_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("svc_app", ValidatorTestHelpers.Disabled | DontExpirePassword);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserWithExpiringPassword_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("jdoe", ValidatorTestHelpers.Enabled);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }
    }
}
