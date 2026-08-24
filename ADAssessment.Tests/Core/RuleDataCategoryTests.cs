using System.Linq;
using ADAssessment.Core;

namespace ADAssessment.Tests.Core
{
    public class RuleDataCategoryTests
    {
        [Theory]
        [InlineData(RuleDataCategory.User, typeof(AdUserAccount), true)]
        [InlineData(RuleDataCategory.Computer, typeof(AdComputerAccount), true)]
        [InlineData(RuleDataCategory.GroupPolicy, typeof(GroupPolicySecuritySettings), true)]
        [InlineData(RuleDataCategory.Trust, typeof(AdTrustRelationship), true)]
        [InlineData(RuleDataCategory.LdapProtocol, typeof(LdapProtocolSecuritySettings), false)]
        [InlineData(RuleDataCategory.SmbProtocol, typeof(SmbProtocolSecuritySettings), false)]
        [InlineData(RuleDataCategory.DcSync, typeof(DcSyncRightsSettings), false)]
        [InlineData(RuleDataCategory.DomainFunctionalLevel, typeof(DomainFunctionalLevelSettings), false)]
        [InlineData(RuleDataCategory.ForestOptionalFeature, typeof(ForestOptionalFeatureSettings), false)]
        public void GetClrType_And_IsListBased_MatchExpectedShapeForEveryCategory(string category, System.Type expectedType, bool expectedListBased)
        {
            Assert.Equal(expectedType, RuleDataCategory.GetClrType(category));
            Assert.Equal(expectedListBased, RuleDataCategory.IsListBased(category));
        }

        [Fact]
        public void Normalize_NullOrWhitespace_DefaultsToUser()
        {
            Assert.Equal(RuleDataCategory.User, RuleDataCategory.Normalize(null));
            Assert.Equal(RuleDataCategory.User, RuleDataCategory.Normalize(""));
            Assert.Equal(RuleDataCategory.User, RuleDataCategory.Normalize("   "));
        }

        [Theory]
        [InlineData(RuleDataCategory.User, true)]
        [InlineData(RuleDataCategory.Computer, true)]
        [InlineData("NotARealCategory", false)]
        public void IsValid_KnownAndUnknownCategories(string category, bool expected)
        {
            Assert.Equal(expected, RuleDataCategory.IsValid(category));
        }

        [Fact]
        public void GetPropertyNames_User_ContainsKnownUserAttributes()
        {
            var names = RuleDataCategory.GetPropertyNames(RuleDataCategory.User);

            Assert.Contains(nameof(AdUserAccount.SamAccountName), names);
            Assert.Contains(nameof(AdUserAccount.UserAccountControl), names);
            Assert.Contains(nameof(AdUserAccount.IsAdminCountSet), names);
        }

        [Fact]
        public void GetPropertyNames_Computer_ContainsKnownComputerAttributes()
        {
            var names = RuleDataCategory.GetPropertyNames(RuleDataCategory.Computer);

            Assert.Contains(nameof(AdComputerAccount.OperatingSystem), names);
            Assert.Contains(nameof(AdComputerAccount.HasLapsManagedPassword), names);
        }

        [Fact]
        public void GetPropertyNames_Trust_ContainsTrustAttributes()
        {
            var names = RuleDataCategory.GetPropertyNames(RuleDataCategory.Trust);

            Assert.Contains(nameof(AdTrustRelationship.TrustPartner), names);
            Assert.Contains(nameof(AdTrustRelationship.TrustAttributes), names);
            Assert.Contains(nameof(AdTrustRelationship.IsSidFilteringEnabled), names);
        }

        [Fact]
        public void GetPropertyNames_UnknownCategory_ReturnsEmptyList()
        {
            var names = RuleDataCategory.GetPropertyNames("NotARealCategory");

            Assert.Empty(names);
        }

        [Fact]
        public void GetIdentifierProperty_ListBasedCategories_ReturnExpectedIdentifiers()
        {
            Assert.Equal(nameof(AdUserAccount.SamAccountName), RuleDataCategory.GetIdentifierProperty(RuleDataCategory.User));
            Assert.Equal(nameof(AdComputerAccount.SamAccountName), RuleDataCategory.GetIdentifierProperty(RuleDataCategory.Computer));
            Assert.Equal(nameof(AdTrustRelationship.TrustPartner), RuleDataCategory.GetIdentifierProperty(RuleDataCategory.Trust));
        }

        [Fact]
        public void GetIdentifierProperty_SingleObjectCategories_ReturnNull()
        {
            Assert.Null(RuleDataCategory.GetIdentifierProperty(RuleDataCategory.LdapProtocol));
            Assert.Null(RuleDataCategory.GetIdentifierProperty(RuleDataCategory.DcSync));
        }

        [Fact]
        public void AllCategories_ContainsAllNineRegisteredCategories()
        {
            var all = RuleDataCategory.AllCategories;

            Assert.Equal(9, all.Count);
            Assert.Contains(RuleDataCategory.User, all);
            Assert.Contains(RuleDataCategory.Computer, all);
            Assert.Contains(RuleDataCategory.GroupPolicy, all);
            Assert.Contains(RuleDataCategory.LdapProtocol, all);
            Assert.Contains(RuleDataCategory.SmbProtocol, all);
            Assert.Contains(RuleDataCategory.DcSync, all);
            Assert.Contains(RuleDataCategory.DomainFunctionalLevel, all);
            Assert.Contains(RuleDataCategory.ForestOptionalFeature, all);
            Assert.Contains(RuleDataCategory.Trust, all);
        }

        [Fact]
        public void GetGroupLabel_UserAndComputer_AreDistinctFromAdSettingsGroup()
        {
            string userGroup = RuleDataCategory.GetGroupLabel(RuleDataCategory.User);
            string computerGroup = RuleDataCategory.GetGroupLabel(RuleDataCategory.Computer);
            string ldapGroup = RuleDataCategory.GetGroupLabel(RuleDataCategory.LdapProtocol);

            Assert.NotEqual(userGroup, computerGroup);
            Assert.NotEqual(userGroup, ldapGroup);
            // Yedi "AD Ayarları" alt kategorisi aynı grup etiketi altında toplanmalı ki
            // frontend'de tek bir <optgroup> olarak görünsünler.
            Assert.Equal(ldapGroup, RuleDataCategory.GetGroupLabel(RuleDataCategory.SmbProtocol));
            Assert.Equal(ldapGroup, RuleDataCategory.GetGroupLabel(RuleDataCategory.Trust));
        }
    }
}
