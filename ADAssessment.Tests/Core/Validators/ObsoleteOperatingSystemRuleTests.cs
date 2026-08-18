using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class ObsoleteOperatingSystemRuleTests
    {
        private static AdComputerAccount Computer(string name, int uac, string operatingSystem) => new()
        {
            SamAccountName = name,
            UserAccountControl = uac,
            OperatingSystem = operatingSystem
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new ObsoleteOperatingSystemRule();

            var result = rule.Execute("not a computer list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Theory]
        [InlineData("Windows Server 2008 R2 Standard")]
        [InlineData("Windows Server 2003")]
        [InlineData("Windows 7 Professional")]
        [InlineData("Windows XP Professional")]
        [InlineData("Windows Server 2012 R2 Standard")]
        public void Execute_EnabledComputerWithObsoleteOs_ReportsVulnerable(string operatingSystem)
        {
            var rule = new ObsoleteOperatingSystemRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("OLD-OS$", ValidatorTestHelpers.Enabled, operatingSystem)
            };

            var result = rule.Execute(computers);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
        }

        [Theory]
        [InlineData("Windows Server 2019 Standard")]
        [InlineData("Windows Server 2022 Datacenter")]
        [InlineData("Windows 11 Enterprise")]
        public void Execute_EnabledComputerWithSupportedOs_NotVulnerable(string operatingSystem)
        {
            var rule = new ObsoleteOperatingSystemRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("NEW-OS$", ValidatorTestHelpers.Enabled, operatingSystem)
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_DisabledComputerWithObsoleteOs_NotVulnerable()
        {
            var rule = new ObsoleteOperatingSystemRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("DISABLED-OLD$", ValidatorTestHelpers.Disabled, "Windows XP Professional")
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_MissingOperatingSystemValue_NotVulnerable()
        {
            var rule = new ObsoleteOperatingSystemRule();
            var computers = new List<AdComputerAccount>
            {
                Computer("NO-OS$", ValidatorTestHelpers.Enabled, string.Empty)
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
        }
    }
}
