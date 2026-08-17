using ADAssessment.Infrastructure.Sysvol;

namespace ADAssessment.Tests.Infrastructure
{
    public class SysvolDataExtractorTests
    {
        [Theory]
        [InlineData("LDAP://192.168.92.100/DC=lab,DC=local", "192.168.92.100", "lab.local")]
        [InlineData("LDAPS://192.168.92.100:636/DC=lab,DC=local", "192.168.92.100", "lab.local")]
        [InlineData("LDAP://dc01.contoso.com/DC=contoso,DC=com", "dc01.contoso.com", "contoso.com")]
        [InlineData("LDAP://192.168.1.1/DC=corp,DC=example,DC=org", "192.168.1.1", "corp.example.org")]
        public void ParseServerAndDomain_ExtractsCorrectServerAndDomainDnsName(string ldapPath, string expectedServer, string expectedDomain)
        {
            var (server, domain) = SysvolDataExtractor.ParseServerAndDomain(ldapPath);

            Assert.Equal(expectedServer, server);
            Assert.Equal(expectedDomain, domain);
        }
    }
}
