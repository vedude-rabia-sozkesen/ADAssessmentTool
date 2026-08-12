using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class DesEncryptionAllowedRuleTests
    {
        private readonly DesEncryptionAllowedRule _rule = new();
        private const int UseDesKeyOnly = 0x200000;

        [Fact]
        public void Execute_EnabledUserWithDesOnly_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("legacyhost", ValidatorTestHelpers.Enabled | UseDesKeyOnly);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
        }

        [Fact]
        public void Execute_DisabledUserWithDesOnly_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("legacyhost", ValidatorTestHelpers.Disabled | UseDesKeyOnly);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserWithoutDesOnly_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("jdoe", ValidatorTestHelpers.Enabled);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }
    }
}
