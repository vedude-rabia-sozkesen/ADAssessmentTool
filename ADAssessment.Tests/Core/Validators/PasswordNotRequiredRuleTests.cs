using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class PasswordNotRequiredRuleTests
    {
        private readonly PasswordNotRequiredRule _rule = new();
        private const int PasswdNotReqd = 0x20;

        [Fact]
        public void Execute_EnabledUserWithPasswordNotRequired_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("nopass", ValidatorTestHelpers.Enabled | PasswdNotReqd);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
        }

        [Fact]
        public void Execute_DisabledUserWithPasswordNotRequired_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("nopass", ValidatorTestHelpers.Disabled | PasswdNotReqd);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserRequiringPassword_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("jdoe", ValidatorTestHelpers.Enabled);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }
    }
}
