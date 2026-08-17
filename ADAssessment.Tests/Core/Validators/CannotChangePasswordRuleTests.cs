using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class CannotChangePasswordRuleTests
    {
        private readonly CannotChangePasswordRule _rule = new();

        [Fact]
        public void Execute_EnabledUserCannotChangePassword_IsVulnerable()
        {
            // IsCannotChangePassword artık UAC bitinden değil, LdapDataExtractor'ın ACL
            // analizinden geliyor (bkz. LdapDataExtractor.IsCannotChangePasswordViaAcl) -
            // test seviyesinde bu doğrudan property olarak set ediliyor.
            var user = ValidatorTestHelpers.User("svc_locked", ValidatorTestHelpers.Enabled, isCannotChangePassword: true);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledUserCannotChangePassword_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("svc_locked", ValidatorTestHelpers.Disabled, isCannotChangePassword: true);

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
