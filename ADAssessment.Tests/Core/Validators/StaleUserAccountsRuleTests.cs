using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class StaleUserAccountsRuleTests
    {
        private readonly StaleUserAccountsRule _rule = new();

        [Fact]
        public void Execute_EnabledUserNeverLoggedOn_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("neverlogged", ValidatorTestHelpers.Enabled, lastLogonTimestamp: null);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserLoggedOn100DaysAgo_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("stale", ValidatorTestHelpers.Enabled, lastLogonTimestamp: System.DateTime.UtcNow.AddDays(-100));

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserLoggedOnYesterday_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("active", ValidatorTestHelpers.Enabled, lastLogonTimestamp: System.DateTime.UtcNow.AddDays(-1));

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledStaleUser_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("disabledstale", ValidatorTestHelpers.Disabled, lastLogonTimestamp: null);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }
    }
}
