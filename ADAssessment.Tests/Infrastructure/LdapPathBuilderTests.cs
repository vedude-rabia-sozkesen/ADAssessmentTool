using ADAssessment.Infrastructure.Ldap;
using Xunit;

namespace ADAssessment.Tests.Infrastructure
{
    public class LdapPathBuilderTests
    {
        [Theory]
        [InlineData("DC01.contoso.local", "DC=contoso,DC=local")]
        [InlineData("DC02.child.contoso.local", "DC=child,DC=contoso,DC=local")]
        [InlineData("dc01.contoso.com", "DC=contoso,DC=com")]
        public void TryBuildDomainDn_FullyQualifiedHostname_StripsFirstLabel(string dcHostname, string expectedDn)
        {
            string? result = LdapPathBuilder.TryBuildDomainDn(dcHostname);

            Assert.Equal(expectedDn, result);
        }

        [Theory]
        [InlineData("DC01")]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("DC01.")]
        public void TryBuildDomainDn_NotFullyQualified_ReturnsNull(string dcHostname)
        {
            string? result = LdapPathBuilder.TryBuildDomainDn(dcHostname);

            Assert.Null(result);
        }

        [Fact]
        public void TryBuildDomainDn_NullInput_ReturnsNull()
        {
            string? result = LdapPathBuilder.TryBuildDomainDn(null!);

            Assert.Null(result);
        }

        [Fact]
        public void BuildLdapPath_CombinesIpAndDomainDn()
        {
            string result = LdapPathBuilder.BuildLdapPath("192.0.2.1", "DC=contoso,DC=local");

            Assert.Equal("LDAP://192.0.2.1/DC=contoso,DC=local", result);
        }
    }
}
