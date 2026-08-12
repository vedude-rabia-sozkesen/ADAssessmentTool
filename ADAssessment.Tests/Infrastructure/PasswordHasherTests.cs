using ADAssessment.Infrastructure.Configuration;

namespace ADAssessment.Tests.Infrastructure
{
    public class PasswordHasherTests
    {
        [Fact]
        public void Hash_ThenVerify_WithCorrectPassword_ReturnsTrue()
        {
            string hash = PasswordHasher.Hash("CorrectHorseBatteryStaple!1");

            Assert.True(PasswordHasher.Verify("CorrectHorseBatteryStaple!1", hash));
        }

        [Fact]
        public void Verify_WithWrongPassword_ReturnsFalse()
        {
            string hash = PasswordHasher.Hash("CorrectHorseBatteryStaple!1");

            Assert.False(PasswordHasher.Verify("WrongPassword!1", hash));
        }

        [Fact]
        public void Hash_ProducesDifferentOutputForSamePassword_DueToRandomSalt()
        {
            string hash1 = PasswordHasher.Hash("SamePassword!1");
            string hash2 = PasswordHasher.Hash("SamePassword!1");

            Assert.NotEqual(hash1, hash2);
            Assert.True(PasswordHasher.Verify("SamePassword!1", hash1));
            Assert.True(PasswordHasher.Verify("SamePassword!1", hash2));
        }

        [Theory]
        [InlineData("not-a-valid-hash")]
        [InlineData("100000.onlytwoparts")]
        [InlineData("notanumber.c2FsdA==.aGFzaA==")]
        [InlineData("100000.not-base64!.aGFzaA==")]
        [InlineData("")]
        public void Verify_WithMalformedEncodedHash_ReturnsFalseWithoutThrowing(string malformed)
        {
            var exception = Record.Exception(() => PasswordHasher.Verify("anypassword", malformed));

            Assert.Null(exception);
            Assert.False(PasswordHasher.Verify("anypassword", malformed));
        }

        [Fact]
        public void Verify_WithEmptyPassword_ReturnsFalse()
        {
            string hash = PasswordHasher.Hash("realpassword");

            Assert.False(PasswordHasher.Verify("", hash));
        }
    }
}
