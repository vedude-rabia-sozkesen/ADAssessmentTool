using System.Collections.Generic;
using ADAssessment.Core;
using Xunit;

namespace ADAssessment.Tests.Core
{
    /// <summary>
    /// Otomatik Compliance Mapping deliverable'ının (bkz. CLAUDE.md - "Tespit edilen
    /// zafiyetlerin ISO 27001 gibi global çerçevelere otomatik eşlenmesi") regresyon
    /// testi: her sabit (compiled) kuralın gerçek bir ISO/IEC 27001:2022 Ek A eşlemesi
    /// olduğunu doğrular - ileride eklenecek yeni bir kuralın bu alanı boş bırakması
    /// (unutulması) burada yakalanır.
    /// </summary>
    public class ComplianceMappingTests
    {
        private static readonly IReadOnlyList<IComplianceRule> AllRules = new IComplianceRule[]
        {
            new KerberoastingRule(),
            new AsRepRoastingRule(),
            new PasswordNeverExpiresRule(),
            new PasswordNotRequiredRule(),
            new StaleUserAccountsRule(),
            new UnconstrainedDelegationRule(),
            new StalePasswordRule(),
            new CannotChangePasswordRule(),
            new ReversibleEncryptionRule(),
            new DesEncryptionAllowedRule(),
            new WeakPasswordPolicyRule(),
            new ReversiblePasswordEncryptionPolicyRule(),
            new WeakLockoutPolicyRule(),
        };

        [Theory]
        [MemberData(nameof(RuleTestCases))]
        public void Rule_HasNonEmptyIso27001Mapping(IComplianceRule rule)
        {
            Assert.False(string.IsNullOrWhiteSpace(rule.Iso27001Mapping));
            Assert.Contains("ISO/IEC 27001", rule.Iso27001Mapping);
        }

        public static IEnumerable<object[]> RuleTestCases()
        {
            foreach (var rule in AllRules)
            {
                yield return new object[] { rule };
            }
        }
    }
}
