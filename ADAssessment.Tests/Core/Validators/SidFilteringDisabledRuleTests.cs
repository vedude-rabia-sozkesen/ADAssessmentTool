using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core.Validators
{
    public class SidFilteringDisabledRuleTests
    {
        // TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (SID filtering)
        private const int SidFilteringBit = 0x4;

        // TRUST_ATTRIBUTE_WITHIN_FOREST
        private const int WithinForestBit = 0x20;

        private static AdTrustRelationship Trust(string partner, int trustAttributes) => new()
        {
            TrustPartner = partner,
            TrustAttributes = trustAttributes
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new SidFilteringDisabledRule();

            var result = rule.Execute("not a trust list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_ExternalTrustWithoutSidFiltering_ReportsVulnerable()
        {
            var rule = new SidFilteringDisabledRule();
            var trusts = new List<AdTrustRelationship> { Trust("partner.external.com", 0) };

            var result = rule.Execute(trusts);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
            Assert.Contains("partner.external.com", result.AffectedObjects[0]);
        }

        [Fact]
        public void Execute_ExternalTrustWithSidFiltering_NotVulnerable()
        {
            var rule = new SidFilteringDisabledRule();
            var trusts = new List<AdTrustRelationship> { Trust("secure-partner.com", SidFilteringBit) };

            var result = rule.Execute(trusts);

            Assert.False(result.IsVulnerable);
        }

        /// <summary>
        /// Regresyon testi: aynı forest içindeki parent/child trust'lar (TRUST_ATTRIBUTE_WITHIN_FOREST)
        /// SID filtering'e tabi değildir - bu tasarım gereğidir, her multi-domain forest'ta
        /// garanti "zafiyet" olarak görünmemesi gerekir.
        /// </summary>
        [Fact]
        public void Execute_WithinForestTrustWithoutSidFiltering_NotVulnerable()
        {
            var rule = new SidFilteringDisabledRule();
            var trusts = new List<AdTrustRelationship> { Trust("child.lab.local", WithinForestBit) };

            var result = rule.Execute(trusts);

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_NoTrusts_NotVulnerable()
        {
            var rule = new SidFilteringDisabledRule();
            var trusts = new List<AdTrustRelationship>();

            var result = rule.Execute(trusts);

            Assert.False(result.IsVulnerable);
        }
    }
}
