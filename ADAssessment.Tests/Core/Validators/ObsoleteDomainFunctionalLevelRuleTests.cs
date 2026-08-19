using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class ObsoleteDomainFunctionalLevelRuleTests
    {
        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new ObsoleteDomainFunctionalLevelRule();

            var result = rule.Execute("not domain functional level settings");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        /// <summary>
        /// FunctionalLevel = -1, veri hiç okunamadığını (özniteliğin bulunamadığını) temsil
        /// eder - bu "Windows 2000 seviyesi" (0) ile karıştırılmamalı, aksi halde veri
        /// eksikliği yanlışlıkla bir zafiyet olarak raporlanır.
        /// </summary>
        [Fact]
        public void Execute_UnknownFunctionalLevel_ReturnsInformationalNonVulnerable()
        {
            var rule = new ObsoleteDomainFunctionalLevelRule();
            var settings = new DomainFunctionalLevelSettings { FunctionalLevel = -1 };

            var result = rule.Execute(settings);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Theory]
        [InlineData(0)] // Windows2000Domain
        [InlineData(2)] // Windows2003Domain
        [InlineData(4)] // Windows2008R2Domain
        public void Execute_ObsoleteFunctionalLevel_ReportsVulnerable(int level)
        {
            var rule = new ObsoleteDomainFunctionalLevelRule();
            var settings = new DomainFunctionalLevelSettings { DomainDistinguishedName = "DC=lab,DC=local", FunctionalLevel = level };

            var result = rule.Execute(settings);

            Assert.True(result.IsVulnerable);
            Assert.Equal("Medium", result.RiskLevel);
        }

        [Theory]
        [InlineData(5)] // Windows2012Domain
        [InlineData(7)] // Windows2016Domain
        public void Execute_ModernFunctionalLevel_NotVulnerable(int level)
        {
            var rule = new ObsoleteDomainFunctionalLevelRule();
            var settings = new DomainFunctionalLevelSettings { DomainDistinguishedName = "DC=lab,DC=local", FunctionalLevel = level };

            var result = rule.Execute(settings);

            Assert.False(result.IsVulnerable);
        }
    }
}
