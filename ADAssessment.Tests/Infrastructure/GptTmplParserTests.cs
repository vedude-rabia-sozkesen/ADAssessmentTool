using ADAssessment.Infrastructure.Sysvol;

namespace ADAssessment.Tests.Infrastructure
{
    public class GptTmplParserTests
    {
        private const string WeakPolicyContent = """
            [Unicode]
            Unicode=yes
            [System Access]
            MinimumPasswordAge = 1
            MaximumPasswordAge = 0
            MinimumPasswordLength = 6
            PasswordComplexity = 0
            PasswordHistorySize = 0
            LockoutBadCount = 0
            LockoutDuration = 30
            ClearTextPassword = 1
            [Version]
            signature="$CHICAGO$"
            Revision=1
            """;

        private const string StrongPolicyContent = """
            [System Access]
            MinimumPasswordAge = 1
            MaximumPasswordAge = 90
            MinimumPasswordLength = 16
            PasswordComplexity = 1
            PasswordHistorySize = 24
            LockoutBadCount = 5
            LockoutDuration = 30
            ClearTextPassword = 0
            """;

        [Fact]
        public void Parse_WeakPolicy_ExtractsAllFieldsCorrectly()
        {
            var result = GptTmplParser.Parse(WeakPolicyContent, "Default Domain Policy", "{GUID}");

            Assert.Equal("Default Domain Policy", result.GpoName);
            Assert.Equal("{GUID}", result.GpoGuid);
            Assert.Equal(6, result.MinimumPasswordLength);
            Assert.False(result.PasswordComplexityEnabled);
            Assert.Equal(0, result.MaximumPasswordAgeDays);
            Assert.Equal(0, result.LockoutThreshold);
            Assert.Equal(30, result.LockoutDurationMinutes);
            Assert.True(result.ReversibleEncryptionEnabled);
        }

        [Fact]
        public void Parse_StrongPolicy_ExtractsAllFieldsCorrectly()
        {
            var result = GptTmplParser.Parse(StrongPolicyContent, "Strong Policy", "{GUID2}");

            Assert.Equal(16, result.MinimumPasswordLength);
            Assert.True(result.PasswordComplexityEnabled);
            Assert.Equal(90, result.MaximumPasswordAgeDays);
            Assert.Equal(5, result.LockoutThreshold);
            Assert.False(result.ReversibleEncryptionEnabled);
        }

        [Fact]
        public void Parse_MissingSystemAccessSection_ReturnsAllZeroDefaults()
        {
            const string contentWithoutSystemAccess = """
                [Version]
                signature="$CHICAGO$"
                Revision=1
                """;

            var result = GptTmplParser.Parse(contentWithoutSystemAccess, "Empty GPO", "{GUID3}");

            Assert.Equal(0, result.MinimumPasswordLength);
            Assert.False(result.PasswordComplexityEnabled);
            Assert.False(result.ReversibleEncryptionEnabled);
        }

        [Fact]
        public void Parse_IgnoresValuesFromOtherSections()
        {
            // [Registry Values] içindeki "MinimumPasswordLength" benzeri bir anahtar
            // (kasıtlı çakışma) [System Access] bölümündeki değeri ezmemeli.
            const string content = """
                [Registry Values]
                MinimumPasswordLength = 999
                [System Access]
                MinimumPasswordLength = 14
                """;

            var result = GptTmplParser.Parse(content, "Test", "{GUID}");

            Assert.Equal(14, result.MinimumPasswordLength);
        }

        [Fact]
        public void Parse_EmptyContent_DoesNotThrow()
        {
            var exception = Record.Exception(() => GptTmplParser.Parse("", "Empty", "{GUID}"));

            Assert.Null(exception);
        }
    }
}
