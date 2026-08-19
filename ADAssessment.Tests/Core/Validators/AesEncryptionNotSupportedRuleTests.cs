using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class AesEncryptionNotSupportedRuleTests
    {
        private static AdUserAccount User(string name, int supportedEncryptionTypes) => new()
        {
            SamAccountName = name,
            UserAccountControl = ValidatorTestHelpers.Enabled,
            SupportedEncryptionTypes = supportedEncryptionTypes
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new AesEncryptionNotSupportedRule();

            var result = rule.Execute("not a user list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_RC4OnlyExplicitlySet_ReportsVulnerable()
        {
            var rule = new AesEncryptionNotSupportedRule();
            var users = new List<AdUserAccount> { User("svc_legacy", 0x4) }; // RC4-HMAC only

            var result = rule.Execute(users);

            Assert.True(result.IsVulnerable);
            Assert.Equal("Medium", result.RiskLevel);
        }

        [Fact]
        public void Execute_AttributeNotSet_NotVulnerable()
        {
            // 0 = öznitelik hiç set edilmemiş; bu son derece yaygın bir varsayılan durumdur
            // ve DC'nin kendi varsayılanına tabidir - gürültü üretmemesi için flag edilmemeli.
            var rule = new AesEncryptionNotSupportedRule();
            var users = new List<AdUserAccount> { User("normal_user", 0) };

            var result = rule.Execute(users);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_Aes256Supported_NotVulnerable()
        {
            var rule = new AesEncryptionNotSupportedRule();
            var users = new List<AdUserAccount> { User("modern_user", 0x18) }; // AES128 + AES256

            var result = rule.Execute(users);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_RC4AndAesBothSet_NotVulnerable()
        {
            // AES bitleri de dahil olduğu sürece (RC4 uyumluluk için birlikte set edilmiş
            // olsa bile) hesap AES kullanabilir - bu kuralın odağı SADECE AES'in yokluğu.
            var rule = new AesEncryptionNotSupportedRule();
            var users = new List<AdUserAccount> { User("mixed_user", 0x4 | 0x8) };

            var result = rule.Execute(users);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledUserRc4Only_NotVulnerable()
        {
            var rule = new AesEncryptionNotSupportedRule();
            var users = new List<AdUserAccount>
            {
                new AdUserAccount { SamAccountName = "disabled_svc", UserAccountControl = ValidatorTestHelpers.Disabled, SupportedEncryptionTypes = 0x4 }
            };

            var result = rule.Execute(users);

            Assert.False(result.IsVulnerable);
        }
    }
}
