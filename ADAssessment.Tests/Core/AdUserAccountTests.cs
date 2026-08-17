using ADAssessment.Core;

namespace ADAssessment.Tests.Core
{
    public class AdUserAccountTests
    {
        private static AdUserAccount WithUac(int uac) => new AdUserAccount { UserAccountControl = uac };

        [Fact]
        public void IsEnabled_FalseWhenAccountDisableBitSet()
        {
            Assert.False(WithUac(0x0002).IsEnabled);
            Assert.True(WithUac(0x0200).IsEnabled);
        }

        [Fact]
        public void IsPreauthNotRequired_ChecksBit0x400000()
        {
            Assert.True(WithUac(0x400000).IsPreauthNotRequired);
            Assert.False(WithUac(0x000000).IsPreauthNotRequired);
        }

        [Fact]
        public void IsPasswordNeverExpires_ChecksBit0x10000()
        {
            Assert.True(WithUac(0x10000).IsPasswordNeverExpires);
            Assert.False(WithUac(0x000000).IsPasswordNeverExpires);
        }

        [Fact]
        public void IsPasswordNotRequired_ChecksBit0x20()
        {
            Assert.True(WithUac(0x20).IsPasswordNotRequired);
            Assert.False(WithUac(0x000000).IsPasswordNotRequired);
        }

        [Fact]
        public void IsUnconstrainedDelegation_ChecksBit0x80000()
        {
            Assert.True(WithUac(0x80000).IsUnconstrainedDelegation);
            Assert.False(WithUac(0x000000).IsUnconstrainedDelegation);
        }

        [Fact]
        public void IsCannotChangePassword_IsPlainSettableProperty_NotDerivedFromUac()
        {
            // Modern AD'de "cannot change password" UAC bitinden değil ACL'den geliyor
            // (bkz. LdapDataExtractor.IsCannotChangePasswordViaAcl) - bu yüzden burada
            // UserAccountControl'den tamamen bağımsız, init ile set edilen düz bir property.
            var user = new AdUserAccount { UserAccountControl = 0x40, IsCannotChangePassword = false };
            Assert.False(user.IsCannotChangePassword);

            var user2 = new AdUserAccount { UserAccountControl = 0, IsCannotChangePassword = true };
            Assert.True(user2.IsCannotChangePassword);
        }

        [Fact]
        public void IsReversibleEncryptionAllowed_ChecksBit0x80()
        {
            Assert.True(WithUac(0x80).IsReversibleEncryptionAllowed);
            Assert.False(WithUac(0x000000).IsReversibleEncryptionAllowed);
        }

        [Fact]
        public void IsDesEncryptionAllowed_ChecksBit0x200000()
        {
            Assert.True(WithUac(0x200000).IsDesEncryptionAllowed);
            Assert.False(WithUac(0x000000).IsDesEncryptionAllowed);
        }

        [Fact]
        public void MultipleFlagsCombined_AreDetectedIndependently()
        {
            var user = WithUac(0x0200 | 0x10000 | 0x400000); // enabled + never expires + no preauth

            Assert.True(user.IsEnabled);
            Assert.True(user.IsPasswordNeverExpires);
            Assert.True(user.IsPreauthNotRequired);
            Assert.False(user.IsPasswordNotRequired);
            Assert.False(user.IsUnconstrainedDelegation);
        }
    }
}
