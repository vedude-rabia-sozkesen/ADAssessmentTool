using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class CannotChangePasswordRuleTests
    {
        private readonly CannotChangePasswordRule _rule = new();
        private const int PasswdCantChg = 0x40;

        [Fact]
        public void Execute_EnabledUserCannotChangePassword_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("svc_locked", ValidatorTestHelpers.Enabled | PasswdCantChg);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledUserCannotChangePassword_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("svc_locked", ValidatorTestHelpers.Disabled | PasswdCantChg);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserCanChangePassword_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("jdoe", ValidatorTestHelpers.Enabled);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }
    }
}
