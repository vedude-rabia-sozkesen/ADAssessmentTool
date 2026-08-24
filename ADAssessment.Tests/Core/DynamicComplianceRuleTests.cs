using System.Collections.Generic;
using ADAssessment.Core;

namespace ADAssessment.Tests.Core
{
    public class DynamicComplianceRuleTests
    {
        private static JsonRuleDefinition MakeDefinition() => new JsonRuleDefinition
        {
            RuleId = "AD-011",
            Name = "Password Not Required",
            RiskLevel = "High",
            Remediation = "Fix it.",
            TargetProperty = "UserAccountControl",
            Operator = "BitwiseAND",
            Value = 32,
            Condition = "NotEqualZero"
        };

        [Fact]
        public void Execute_InvalidDirectoryDataType_ReturnsInformationalNonVulnerable()
        {
            var rule = new DynamicComplianceRule(MakeDefinition());

            var result = rule.Execute("not a user list");

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_MatchingUser_ReportsVulnerableWithRuleRiskLevel()
        {
            var rule = new DynamicComplianceRule(MakeDefinition());
            var users = new List<AdUserAccount>
            {
                new AdUserAccount { SamAccountName = "nopass", UserAccountControl = 0x0200 | 0x20 }
            };

            var result = rule.Execute(users);

            Assert.True(result.IsVulnerable);
            Assert.Equal("High", result.RiskLevel);
            Assert.Contains(result.AffectedObjects, a => a.Contains("nopass"));
        }

        [Fact]
        public void Execute_NoMatchingUsers_ReportsLowRiskNotVulnerable()
        {
            var rule = new DynamicComplianceRule(MakeDefinition());
            var users = new List<AdUserAccount>
            {
                new AdUserAccount { SamAccountName = "normal", UserAccountControl = 0x0200 }
            };

            var result = rule.Execute(users);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Low", result.RiskLevel);
            Assert.Empty(result.AffectedObjects);
        }

        [Fact]
        public void Execute_PrivilegedAffectedAccount_IsTaggedCritical()
        {
            var rule = new DynamicComplianceRule(MakeDefinition());
            var users = new List<AdUserAccount>
            {
                new AdUserAccount { SamAccountName = "admin1", UserAccountControl = 0x0200 | 0x20, IsAdminCountSet = true }
            };

            var result = rule.Execute(users);

            Assert.Contains(result.AffectedObjects, a => a.Contains("[KRİTİK YETKİLİ]") && a.Contains("admin1"));
        }

        [Fact]
        public void Execute_ComputerCategory_EvaluatesAgainstComputerListNotUserList()
        {
            var definition = new JsonRuleDefinition
            {
                RuleId = "TEST-COMPUTER",
                Name = "Obsolete OS",
                RiskLevel = "High",
                Remediation = "Upgrade the OS.",
                DataCategory = RuleDataCategory.Computer,
                TargetProperty = "OperatingSystem",
                Operator = "Contains",
                Value = "2012"
            };
            var rule = new DynamicComplianceRule(definition);
            var computers = new List<AdComputerAccount>
            {
                new AdComputerAccount { SamAccountName = "OLDPC$", OperatingSystem = "Windows Server 2012 R2" }
            };

            var result = rule.Execute(computers);

            Assert.True(result.IsVulnerable);
            Assert.Contains(result.AffectedObjects, a => a.Contains("OLDPC$"));
            // Computer kategorisinde User'a özgü [KRİTİK YETKİLİ] etiketi hiç uygulanmamalı.
            Assert.DoesNotContain(result.AffectedObjects, a => a.Contains("[KRİTİK YETKİLİ]"));
        }

        [Fact]
        public void Execute_WrongListElementType_ReturnsInformationalNotAnException()
        {
            // Tip güvenliği regresyon testi: DataCategory="User" (varsayılan) olan bir kural,
            // beklenmedik şekilde IEnumerable<AdComputerAccount> ile çağrılırsa - RuleDataCategory
            // registry'sindeki AdUserAccount tipiyle eşleşmediğinden - istisna fırlatmak veya
            // yanlışlıkla eşleştirmek yerine güvenle "Informational" dönmeli.
            var rule = new DynamicComplianceRule(MakeDefinition()); // DataCategory varsayılan "User"
            var computers = new List<AdComputerAccount>
            {
                new AdComputerAccount { SamAccountName = "PC1$", UserAccountControl = 0x0200 | 0x20 }
            };

            var result = rule.Execute(computers);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }

        [Fact]
        public void Execute_SingleObjectCategory_LdapProtocolSecurity_ReturnsSingleLabelWhenVulnerable()
        {
            var definition = new JsonRuleDefinition
            {
                RuleId = "TEST-LDAP-SIGNING",
                Name = "LDAP Signing Not Enforced",
                RiskLevel = "High",
                Remediation = "Enforce LDAP signing.",
                DataCategory = RuleDataCategory.LdapProtocol,
                TargetProperty = "IsSigningEnforced",
                Operator = "Equals",
                Value = "false"
            };
            var rule = new DynamicComplianceRule(definition);
            var insecureSettings = new LdapProtocolSecuritySettings { DomainController = "dc1.example.com", IsSigningEnforced = false };
            var secureSettings = new LdapProtocolSecuritySettings { DomainController = "dc2.example.com", IsSigningEnforced = true };

            var vulnerableResult = rule.Execute(insecureSettings);
            var safeResult = rule.Execute(secureSettings);

            Assert.True(vulnerableResult.IsVulnerable);
            Assert.Single(vulnerableResult.AffectedObjects);
            Assert.False(safeResult.IsVulnerable);
            Assert.Empty(safeResult.AffectedObjects);
        }

        [Fact]
        public void Execute_SingleObjectCategory_NullDirectoryData_ReturnsInformational()
        {
            // AssessmentController, ilgili veri kaynağı sorgusu başarısız olduğunda (ör.
            // SYSVOL erişilemedi) null geçebiliyor - tek-nesne kategorilerin bunu güvenle
            // "veri sağlanamadı" olarak ele alması gerekir, istisna fırlatmamalı.
            var definition = new JsonRuleDefinition
            {
                RuleId = "TEST-LDAP-NULL",
                DataCategory = RuleDataCategory.LdapProtocol,
                TargetProperty = "IsSigningEnforced",
                Operator = "Equals",
                Value = "false"
            };
            var rule = new DynamicComplianceRule(definition);

            var result = rule.Execute(null!);

            Assert.False(result.IsVulnerable);
            Assert.Equal("Informational", result.RiskLevel);
        }
    }
}
