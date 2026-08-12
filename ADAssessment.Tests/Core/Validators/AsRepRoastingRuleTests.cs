using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class AsRepRoastingRuleTests
    {
        private readonly AsRepRoastingRule _rule = new();
        private const int DontRequirePreauth = 0x400000;

        [Fact]
        public void Execute_EnabledUserWithNoPreauth_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("jdoe", ValidatorTestHelpers.Enabled | DontRequirePreauth);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledUserWithNoPreauth_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("jdoe", ValidatorTestHelpers.Disabled | DontRequirePreauth);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserWithPreauthRequired_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("jdoe", ValidatorTestHelpers.Enabled);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }
    }
}
