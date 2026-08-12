using System.Collections.Generic;
using ADAssessment.Core;

namespace ADAssessment.Tests.Core
{
    public class RuleEvaluatorTests
    {
        private static AdUserAccount MakeUser(
            string samAccountName = "testuser",
            int userAccountControl = 0x0200, // NORMAL_ACCOUNT, enabled
            System.DateTime? lastLogonTimestamp = null,
            System.DateTime? passwordLastSet = null,
            bool isAdminCountSet = false,
            System.Collections.Generic.IReadOnlyList<string>? spns = null)
        {
            return new AdUserAccount
            {
                SamAccountName = samAccountName,
                UserAccountControl = userAccountControl,
                LastLogonTimestamp = lastLogonTimestamp,
                PasswordLastSet = passwordLastSet,
                IsAdminCountSet = isAdminCountSet,
                ServicePrincipalNames = spns ?? System.Array.Empty<string>()
            };
        }

        private static JsonRuleDefinition SingleCondition(string targetProperty, string op, object? value, string condition = "")
        {
            return new JsonRuleDefinition
            {
                RuleId = "TEST-001",
                TargetProperty = targetProperty,
                Operator = op,
                Value = value,
                Condition = condition
            };
        }

        [Fact]
        public void IsVulnerable_DisabledAccount_AlwaysReturnsFalse()
        {
            var user = MakeUser(userAccountControl: 0x0202); // ACCOUNTDISABLE set
            var rule = SingleCondition("SamAccountName", "NotEmpty", null);

            Assert.False(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void IsVulnerable_ComputerAccount_AlwaysReturnsFalse()
        {
            var user = MakeUser(samAccountName: "WORKSTATION1$");
            var rule = SingleCondition("SamAccountName", "NotEmpty", null);

            Assert.False(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Theory]
        [InlineData(0x0020, "32", true)]  // PASSWD_NOTREQD set -> matches
        [InlineData(0x0000, "32", false)] // flag not set -> no match
        public void BitwiseAND_NotEqualZero_DetectsFlag(int uac, string flagValue, bool expected)
        {
            var user = MakeUser(userAccountControl: uac | 0x0200); // keep enabled bit
            var rule = SingleCondition("UserAccountControl", "BitwiseAND", flagValue, "NotEqualZero");

            Assert.Equal(expected, RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void BitwiseAND_EqualsZero_ReturnsTrueWhenFlagAbsent()
        {
            var user = MakeUser(userAccountControl: 0x0200); // enabled only
            var rule = SingleCondition("UserAccountControl", "BitwiseAND", "32", "EqualsZero");

            Assert.True(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void Equals_StringComparison_IsCaseInsensitive()
        {
            var user = MakeUser(isAdminCountSet: true);
            var rule = SingleCondition("IsAdminCountSet", "Equals", "TRUE");

            Assert.True(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void NotEquals_ReturnsOppositeOfEquals()
        {
            var user = MakeUser(isAdminCountSet: false);
            var rule = SingleCondition("IsAdminCountSet", "NotEquals", "true");

            Assert.True(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void Contains_MatchesWithinSpnList()
        {
            var user = MakeUser(spns: new List<string> { "HTTP/webserver.lab.local" });
            var rule = SingleCondition("ServicePrincipalNames", "Contains", "http/");

            Assert.True(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void NotContains_ReturnsFalseWhenSubstringPresent()
        {
            var user = MakeUser(samAccountName: "svc_backup");
            var rule = SingleCondition("SamAccountName", "NotContains", "svc_");

            Assert.False(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void StartsWith_And_EndsWith_WorkAsExpected()
        {
            var user = MakeUser(samAccountName: "svc_backup_test");

            Assert.True(RuleEvaluator.IsVulnerable(user, SingleCondition("SamAccountName", "StartsWith", "svc_")));
            Assert.True(RuleEvaluator.IsVulnerable(user, SingleCondition("SamAccountName", "EndsWith", "_test")));
            Assert.False(RuleEvaluator.IsVulnerable(user, SingleCondition("SamAccountName", "StartsWith", "adm_")));
        }

        [Fact]
        public void GreaterThan_And_LessThan_CompareNumbers()
        {
            var user = new AdUserAccount
            {
                SamAccountName = "manygroups",
                UserAccountControl = 0x0200, // enabled
                MemberOfCount = 10
            };

            Assert.True(RuleEvaluator.IsVulnerable(user, SingleCondition("MemberOfCount", "GreaterThan", "5")));
            Assert.False(RuleEvaluator.IsVulnerable(user, SingleCondition("MemberOfCount", "LessThan", "5")));
        }

        [Fact]
        public void GreaterThanDays_LastLogonTimestamp_TreatsNeverLoggedOnAsStale()
        {
            var user = MakeUser(lastLogonTimestamp: null);
            var rule = SingleCondition("LastLogonTimestamp", "GreaterThanDays", "90");

            Assert.True(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void GreaterThanDays_RecentLogon_IsNotStale()
        {
            var user = MakeUser(lastLogonTimestamp: System.DateTime.UtcNow.AddDays(-1));
            var rule = SingleCondition("LastLogonTimestamp", "GreaterThanDays", "90");

            Assert.False(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void GreaterThanDays_OldPasswordLastSet_IsStale()
        {
            var user = MakeUser(passwordLastSet: System.DateTime.UtcNow.AddDays(-200));
            var rule = SingleCondition("PasswordLastSet", "GreaterThanDays", "180");

            Assert.True(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void NotEmpty_And_IsEmpty_OnSpnList()
        {
            var withSpn = MakeUser(spns: new List<string> { "HTTP/x" });
            var withoutSpn = MakeUser(spns: new List<string>());

            Assert.True(RuleEvaluator.IsVulnerable(withSpn, SingleCondition("ServicePrincipalNames", "NotEmpty", null)));
            Assert.True(RuleEvaluator.IsVulnerable(withoutSpn, SingleCondition("ServicePrincipalNames", "IsEmpty", null)));
        }

        [Fact]
        public void RegexMatch_MatchingPattern_ReturnsTrue()
        {
            var user = MakeUser(samAccountName: "svc_sql_prod");
            var rule = SingleCondition("SamAccountName", "RegexMatch", "^svc_.*_prod$");

            Assert.True(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void RegexMatch_NonMatchingPattern_ReturnsFalse()
        {
            var user = MakeUser(samAccountName: "jdoe");
            var rule = SingleCondition("SamAccountName", "RegexMatch", "^svc_.*_prod$");

            Assert.False(RuleEvaluator.IsVulnerable(user, rule));
        }

        [Fact]
        public void RegexMatch_CatastrophicBacktrackingPattern_DoesNotHangAndReturnsFalse()
        {
            // Klasik ReDoS deseni: (a+)+ ile sonu eşleşmeyen bir girdi, timeout korumasız
            // regex motorlarında üstel zaman karmaşıklığına yol açar. RuleEvaluator artık
            // bir timeout uyguladığından bu test saniyeler içinde (asılı kalmadan) false
            // döner - ReDoS düzeltmesinin regresyon testi.
            var user = MakeUser(samAccountName: new string('a', 40) + "!");
            var rule = SingleCondition("SamAccountName", "RegexMatch", "^(a+)+$");

            var result = RuleEvaluator.IsVulnerable(user, rule);

            Assert.False(result);
        }

        [Fact]
        public void InvalidRegexPattern_DoesNotThrow()
        {
            var user = MakeUser();
            var rule = SingleCondition("SamAccountName", "RegexMatch", "(unterminated");

            var exception = Record.Exception(() => RuleEvaluator.IsVulnerable(user, rule));

            Assert.Null(exception);
        }

        [Fact]
        public void NestedAndOrConditions_MirrorsAD012Structure()
        {
            // AD-012.json: IsAdminCountSet == true AND (PasswordNeverExpires OR stale-90-days)
            var rule = new JsonRuleDefinition
            {
                RuleId = "AD-012",
                LogicalOperator = "AND",
                Conditions = new List<RuleConditionNode>
                {
                    new RuleConditionNode { TargetProperty = "IsAdminCountSet", Operator = "Equals", Value = "true" },
                    new RuleConditionNode
                    {
                        LogicalOperator = "OR",
                        Conditions = new List<RuleConditionNode>
                        {
                            new RuleConditionNode { TargetProperty = "UserAccountControl", Operator = "BitwiseAND", Value = 65536 },
                            new RuleConditionNode { TargetProperty = "LastLogonTimestamp", Operator = "GreaterThanDays", Value = 90 }
                        }
                    }
                }
            };

            var adminNeverExpires = MakeUser(isAdminCountSet: true, userAccountControl: 0x0200 | 0x10000);
            var adminStale = MakeUser(isAdminCountSet: true, lastLogonTimestamp: null);
            var adminFreshWithExpiry = MakeUser(isAdminCountSet: true, lastLogonTimestamp: System.DateTime.UtcNow);
            var nonAdmin = MakeUser(isAdminCountSet: false, userAccountControl: 0x0200 | 0x10000);

            Assert.True(RuleEvaluator.IsVulnerable(adminNeverExpires, rule));
            Assert.True(RuleEvaluator.IsVulnerable(adminStale, rule));
            Assert.False(RuleEvaluator.IsVulnerable(adminFreshWithExpiry, rule));
            Assert.False(RuleEvaluator.IsVulnerable(nonAdmin, rule));
        }
    }
}
