using ADAssessment.Infrastructure.Ldap;
using Xunit;

namespace ADAssessment.Tests.Infrastructure
{
    /// <summary>
    /// LdapDataExtractor.IsExpectedDcSyncPrincipal'ın (AD-023'ün DCSync hakları
    /// denetiminde kullanılan saf/testedilebilir yardımcı fonksiyonu) regresyon testleri.
    /// RID 516 (Domain Controllers) ve RID 498 (Enterprise Read-only Domain Controllers)
    /// vakaları, canlı lab testinde gerçekten yaşanmış bir yanlış pozitifin (false
    /// positive) düzeltmesidir - bu iki grup varsayılan olarak DCSync haklarına sahiptir.
    /// </summary>
    public class LdapDataExtractorDcSyncTests
    {
        private const string DomainSid = "S-1-5-21-1111111111-2222222222-3333333333";

        [Theory]
        [InlineData(DomainSid + "-512")]   // Domain Admins
        [InlineData(DomainSid + "-519")]   // Enterprise Admins
        [InlineData(DomainSid + "-516")]   // Domain Controllers
        [InlineData(DomainSid + "-498")]   // Enterprise Read-only Domain Controllers
        [InlineData("S-1-5-32-544")]       // BUILTIN\Administrators
        [InlineData("S-1-5-9")]            // Enterprise Domain Controllers
        [InlineData("S-1-5-18")]           // SYSTEM
        public void IsExpectedDcSyncPrincipal_KnownSafePrincipals_ReturnsTrue(string sidValue)
        {
            bool result = LdapDataExtractor.IsExpectedDcSyncPrincipal(sidValue, DomainSid);

            Assert.True(result);
        }

        [Theory]
        [InlineData(DomainSid + "-1105")]  // rastgele bir kullanıcı hesabı RID'i
        [InlineData(DomainSid + "-513")]   // Domain Users - DCSync hakkı beklenmez
        [InlineData("S-1-1-0")]            // Everyone
        public void IsExpectedDcSyncPrincipal_UnexpectedPrincipals_ReturnsFalse(string sidValue)
        {
            bool result = LdapDataExtractor.IsExpectedDcSyncPrincipal(sidValue, DomainSid);

            Assert.False(result);
        }
    }
}
