using ADAssessment.Core;

namespace ADAssessment.Tests.Core
{
    public class RuleIdValidatorTests
    {
        [Theory]
        [InlineData("AD-011")]
        [InlineData("AD_012")]
        [InlineData("a")]
        [InlineData("Custom-Rule-99")]
        public void IsValid_AcceptsAlphanumericHyphenUnderscore(string ruleId)
        {
            Assert.True(RuleIdValidator.IsValid(ruleId));
        }

        [Theory]
        [InlineData("../../evil")]
        [InlineData("..\\..\\evil")]
        [InlineData("AD/011")]
        [InlineData("AD 011")]
        [InlineData("")]
        [InlineData(null)]
        [InlineData("   ")]
        public void IsValid_RejectsPathTraversalAndInvalidCharacters(string? ruleId)
        {
            Assert.False(RuleIdValidator.IsValid(ruleId));
        }

        [Fact]
        public void IsValid_RejectsIdsLongerThan64Characters()
        {
            string tooLong = new string('a', 65);

            Assert.False(RuleIdValidator.IsValid(tooLong));
        }

        [Fact]
        public void IsValid_Accepts64CharacterId()
        {
            string exactly64 = new string('a', 64);

            Assert.True(RuleIdValidator.IsValid(exactly64));
        }
    }
}
