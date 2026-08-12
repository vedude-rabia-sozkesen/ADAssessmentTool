using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class ReversibleEncryptionRuleTests
    {
        private readonly ReversibleEncryptionRule _rule = new();
        private const int EncryptedTextPasswordAllowed = 0x80;

        [Fact]
        public void Execute_EnabledUserWithReversibleEncryption_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("legacyapp", ValidatorTestHelpers.Enabled | EncryptedTextPasswordAllowed);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
        }

        [Fact]
        public void Execute_DisabledUserWithReversibleEncryption_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("legacyapp", ValidatorTestHelpers.Disabled | EncryptedTextPasswordAllowed);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserWithoutReversibleEncryption_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("jdoe", ValidatorTestHelpers.Enabled);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }
    }
}
