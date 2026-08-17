using ADAssessment.Infrastructure.Ldap;
using Xunit;

namespace ADAssessment.Tests.Infrastructure
{
    /// <summary>
    /// GetFormattedLdapPath() ADSI'nin (System.DirectoryServices) yalnızca "LDAP://" şemasını
    /// tanıdığı, "LDAPS://" şemasının ise E_ADS_BAD_PATHNAME (0x80005000) ile reddedildiği
    /// gerçeğine dayanır. Bu testler, üretilen yolun her zaman "LDAP://" ile başlamasını ve
    /// asla "LDAPS://" içermemesini kilit altına alır (regresyon: bu metod önceden yanlışlıkla
    /// "LDAPS://" üretiyordu).
    /// </summary>
    public class LdapConnectionOptionsTests
    {
        [Fact]
        public void GetFormattedLdapPath_UseLdapsTrue_PlainLdapInput_ProducesLdapSchemeWithPort636()
        {
            var options = new LdapConnectionOptions
            {
                LdapPath = "LDAP://192.168.92.100/DC=lab,DC=local",
                UseLdaps = true
            };

            string result = options.GetFormattedLdapPath();

            Assert.Equal("LDAP://192.168.92.100:636/DC=lab,DC=local", result);
            Assert.DoesNotContain("LDAPS://", result);
        }

        [Fact]
        public void GetFormattedLdapPath_UseLdapsTrue_NoSchemeInInput_AddsLdapSchemeAndPort636()
        {
            var options = new LdapConnectionOptions
            {
                LdapPath = "192.168.92.100/DC=lab,DC=local",
                UseLdaps = true
            };

            string result = options.GetFormattedLdapPath();

            Assert.Equal("LDAP://192.168.92.100:636/DC=lab,DC=local", result);
        }

        [Fact]
        public void GetFormattedLdapPath_UseLdapsTrue_LdapsSchemeInInput_NormalizesToLdapScheme()
        {
            // Kullanıcı yanlışlıkla "LDAPS://" girse bile üretilen yol ADSI'nin
            // tanıdığı "LDAP://" şemasına normalize edilmelidir.
            var options = new LdapConnectionOptions
            {
                LdapPath = "LDAPS://192.168.92.100/DC=lab,DC=local",
                UseLdaps = true
            };

            string result = options.GetFormattedLdapPath();

            Assert.Equal("LDAP://192.168.92.100:636/DC=lab,DC=local", result);
            Assert.DoesNotContain("LDAPS://", result);
        }

        [Fact]
        public void GetFormattedLdapPath_UseLdapsTrue_PortAlreadySpecified_DoesNotDuplicatePort()
        {
            var options = new LdapConnectionOptions
            {
                LdapPath = "LDAP://192.168.92.100:636/DC=lab,DC=local",
                UseLdaps = true
            };

            string result = options.GetFormattedLdapPath();

            Assert.Equal("LDAP://192.168.92.100:636/DC=lab,DC=local", result);
        }

        [Fact]
        public void GetFormattedLdapPath_UseLdapsFalse_ReturnsOriginalPathUnchanged()
        {
            var options = new LdapConnectionOptions
            {
                LdapPath = "LDAP://192.168.92.100/DC=lab,DC=local",
                UseLdaps = false
            };

            string result = options.GetFormattedLdapPath();

            Assert.Equal("LDAP://192.168.92.100/DC=lab,DC=local", result);
        }

        [Fact]
        public void GetFormattedLdapPath_EmptyPath_ReturnsEmptyString()
        {
            var options = new LdapConnectionOptions
            {
                LdapPath = string.Empty,
                UseLdaps = true
            };

            string result = options.GetFormattedLdapPath();

            Assert.Equal(string.Empty, result);
        }
    }
}
