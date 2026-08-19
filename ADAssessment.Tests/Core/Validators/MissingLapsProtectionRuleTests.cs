using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class MissingLapsProtectionRuleTests
    {
        // SERVER_TRUST_ACCOUNT
        private const int DomainControllerBit = 0x2000;

        private static AdComputerAccount Computer(string name, int uac, bool hasLaps) => new()
        {
            SamAccountName = name,
            UserAccountControl = uac,
            HasLapsManagedPassword = hasLaps
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new MissingLapsProtectionRule();

            var result = rule.Execute("not a computer list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_EnabledNonDcComputerWithoutLaps_ReportsVulnerable()
        {
            var rule = new MissingLapsProtectionRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("WORKSTATION01$", ValidatorTestHelpers.Enabled, hasLaps: false)
            };

            var result = rule.Execute(computers);

            Assert.True(result.IsVulnerable);
            Assert.Equal("Medium", result.RiskLevel);
        }

        [Fact]
        public void Execute_ComputerWithLaps_NotVulnerable()
        {
            var rule = new MissingLapsProtectionRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("WORKSTATION02$", ValidatorTestHelpers.Enabled, hasLaps: true)
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }

        /// <summary>
        /// Regresyon testi: Domain Controller'lar LAPS'ın hedeflediği senaryonun dışındadır
        /// (farklı bir sertleştirme modeli uygulanır) - dışlanmazsa her taramada garanti
        /// "zafiyet" görünür.
        /// </summary>
        [Fact]
        public void Execute_DomainControllerWithoutLaps_NotVulnerable()
        {
            var rule = new MissingLapsProtectionRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("DC01$", ValidatorTestHelpers.Enabled | DomainControllerBit, hasLaps: false)
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledComputerWithoutLaps_NotVulnerable()
        {
            var rule = new MissingLapsProtectionRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("OLD-PC$", ValidatorTestHelpers.Disabled, hasLaps: false)
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }
    }
}
