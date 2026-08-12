using System.Collections.Generic;
using ADAssessment.Core;

namespace ADAssessment.Tests.Core.Validators
{
    public class KerberoastingRuleTests
    {
        private readonly KerberoastingRule _rule = new();

        [Fact]
        public void Execute_EnabledUserWithSpn_IsVulnerable()
        {
            var user = ValidatorTestHelpers.User("svc_sql", ValidatorTestHelpers.Enabled, spns: new List<string> { "MSSQLSvc/db01" });

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
        }

        [Fact]
        public void Execute_DisabledUserWithSpn_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("svc_sql", ValidatorTestHelpers.Disabled, spns: new List<string> { "MSSQLSvc/db01" });

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_EnabledUserWithoutSpn_IsNotVulnerable()
        {
            var user = ValidatorTestHelpers.User("jdoe", ValidatorTestHelpers.Enabled);

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_ComputerAccountWithSpn_IsExcluded()
        {
            var user = ValidatorTestHelpers.User("WORKSTATION1$", ValidatorTestHelpers.Enabled, spns: new List<string> { "HOST/workstation1" });

            var result = _rule.Execute(ValidatorTestHelpers.SingleUserList(user));

            Assert.False(result.IsVulnerable);
        }

        [Fact]
        public void Execute_InvalidDirectoryData_ReturnsInformational()
        {
            var result = _rule.Execute(new object());

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }
    }
}
