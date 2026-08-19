using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class ProtocolTransitionDelegationRuleTests
    {
        // TRUSTED_TO_AUTH_FOR_DELEGATION
        private const int ProtocolTransitionBit = 0x1000000;

        private static AdComputerAccount Computer(string name, int uac, IReadOnlyList<string> delegateTo) => new()
        {
            SamAccountName = name,
            UserAccountControl = uac,
            AllowedToDelegateTo = delegateTo
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new ProtocolTransitionDelegationRule();

            var result = rule.Execute("not a computer list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_EnabledComputerWithProtocolTransitionAndDelegateTargets_ReportsVulnerable()
        {
            var rule = new ProtocolTransitionDelegationRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("APPSRV01$", ValidatorTestHelpers.Enabled | ProtocolTransitionBit, new[] { "cifs/fileserver01.lab.local" })
            };

            var result = rule.Execute(computers);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
        }

        [Fact]
        public void Execute_ProtocolTransitionBitWithoutDelegateTargets_NotVulnerable()
        {
            // UAC bayrağı tek başına (hedef SPN listesi boşken) gerçek bir delegasyon
            // yetkisi taşımaz - false positive üretmemesi gerekiyor.
            var rule = new ProtocolTransitionDelegationRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("APPSRV02$", ValidatorTestHelpers.Enabled | ProtocolTransitionBit, System.Array.Empty<string>())
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DelegateTargetsWithoutProtocolTransitionBit_NotVulnerable()
        {
            // Sadece msDS-AllowedToDelegateTo dolu ama protokol geçişi bayrağı yoksa, bu
            // standart (daha düşük riskli) kısıtlı delegasyondur - bu kuralın hedefi değil.
            var rule = new ProtocolTransitionDelegationRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("APPSRV03$", ValidatorTestHelpers.Enabled, new[] { "cifs/fileserver01.lab.local" })
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledComputer_NotVulnerable()
        {
            var rule = new ProtocolTransitionDelegationRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("OLD-APPSRV$", ValidatorTestHelpers.Disabled | ProtocolTransitionBit, new[] { "cifs/fileserver01.lab.local" })
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }
    }
}
