using ADAssessment.Infrastructure.Ldap;
using Xunit;

namespace ADAssessment.Tests.Infrastructure
{
    public class LdapProtocolSecurityCheckerTests
    {
        [Theory]
        [InlineData("LDAP://192.168.92.100/DC=lab,DC=local", "DC=lab,DC=local")]
        [InlineData("LDAPS://192.168.92.100:636/DC=lab,DC=local", "DC=lab,DC=local")]
        [InlineData("LDAP://DC01.lab.local/DC=lab,DC=local", "DC=lab,DC=local")]
        [InlineData("LDAP://192.168.92.100", "")]
        public void ExtractBaseDn_ParsesDnCorrectly(string ldapPath, string expectedBaseDn)
        {
            string result = LdapProtocolSecurityChecker.ExtractBaseDn(ldapPath);

            Assert.Equal(expectedBaseDn, result);
        }
    }
}
