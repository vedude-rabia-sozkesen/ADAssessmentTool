using ADAssessment.Infrastructure.Ldap;
using Xunit;

namespace ADAssessment.Tests.Infrastructure
{
    /// <summary>
    /// LdapDataExtractor.BuildPathWithDn'in (AD-031'in forest özellik sorgusunda,
    /// RootDSE ve Configuration NC altındaki bilinen nesnelere bağlanmak için kullanılan
    /// saf/I-O'suz yardımcı fonksiyonu) regresyon testleri.
    /// </summary>
    public class LdapDataExtractorPathTests
    {
        [Theory]
        [InlineData("LDAP://192.168.92.100:636/DC=lab,DC=local", "RootDSE", "LDAP://192.168.92.100:636/RootDSE")]
        [InlineData("LDAP://192.168.92.100/DC=lab,DC=local", "RootDSE", "LDAP://192.168.92.100/RootDSE")]
        [InlineData("LDAP://DC01.lab.local:636/DC=lab,DC=local", "CN=Foo,DC=lab,DC=local", "LDAP://DC01.lab.local:636/CN=Foo,DC=lab,DC=local")]
        public void BuildPathWithDn_ReplacesDnPortionCorrectly(string formattedLdapPath, string dn, string expected)
        {
            string result = LdapDataExtractor.BuildPathWithDn(formattedLdapPath, dn);

            Assert.Equal(expected, result);
        }
    }
}
