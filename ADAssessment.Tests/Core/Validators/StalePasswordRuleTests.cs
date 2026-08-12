using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class StalePasswordRuleTests
    {
        private readonly StalePasswordRule _rule = new();

        [Fact]
        public void Execute_EnabledUserPasswordSet200DaysAgo_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("stalepass", ValidatorTestHelpers.Enabled, passwordLastSet: System.DateTime.UtcNow.AddDays(-200));

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserPasswordSetRecently_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("freshpass", ValidatorTestHelpers.Enabled, passwordLastSet: System.DateTime.UtcNow.AddDays(-1));

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserWithNoPasswordLastSetValue_IsNotVulnerable()
        {
            // PasswordLastSet null iken kural "stale" saymıyor (StaleUserAccountsRule'dan farklı davranış) -
            // mevcut kodun gerçek davranışını doğrulayan regresyon testi.
            var user = ValidatorTestHelpers.User("neverset", ValidatorTestHelpers.Enabled, passwordLastSet: null);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledUserWithStalePassword_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("disabledstale", ValidatorTestHelpers.Disabled, passwordLastSet: System.DateTime.UtcNow.AddDays(-200));

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }
    }
}
