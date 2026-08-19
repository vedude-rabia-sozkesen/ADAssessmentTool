using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class ComputerUnconstrainedDelegationRuleTests
    {
        // Delegasyon: 0x80000 (TRUSTED_FOR_DELEGATION), DC: 0x2000 (SERVER_TRUST_ACCOUNT).
        private const int UnconstrainedDelegationBit = 0x80000;
        private const int DomainControllerBit = 0x2000;

        private static AdComputerAccount Computer(string name, int uac) => new()
        {
            SamAccountName = name,
            UserAccountControl = uac
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new ComputerUnconstrainedDelegationRule();

            var result = rule.Execute("not a computer list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_EnabledNonDcComputerWithUnconstrainedDelegation_ReportsVulnerable()
        {
            var rule = new ComputerUnconstrainedDelegationRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("FILESERVER01$", ValidatorTestHelpers.Enabled | UnconstrainedDelegationBit)
            };

            var result = rule.Execute(computers);

            Assert.True(result.IsVulnerable);
            Assert.Contains("FILESERVER01$", result.AffectedObjects[0]);
        }

        /// <summary>
        /// Regresyon testi: Domain Controller'lar tasarım gereği (SERVER_TRUST_ACCOUNT bayrağı
        /// ile birlikte) sınırsız delegasyona sahiptir - bu bir zafiyet DEĞİL, normal/beklenen
        /// bir durumdur. Elenmezse her taramada garanti "zafiyet" görünür (yanlış pozitif).
        /// </summary>
        [Fact]
        public void Execute_DomainControllerWithUnconstrainedDelegation_NotVulnerable()
        {
            var rule = new ComputerUnconstrainedDelegationRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("DC01$", ValidatorTestHelpers.Enabled | UnconstrainedDelegationBit | DomainControllerBit)
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_NonDcComputerWithoutUnconstrainedDelegation_NotVulnerable()
        {
            var rule = new ComputerUnconstrainedDelegationRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("WORKSTATION01$", ValidatorTestHelpers.Enabled)
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledComputerWithUnconstrainedDelegation_NotVulnerable()
        {
            var rule = new ComputerUnconstrainedDelegationRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("OLD-SRV$", ValidatorTestHelpers.Disabled | UnconstrainedDelegationBit)
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }
    }
}
