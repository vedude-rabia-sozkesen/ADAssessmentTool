using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Tests.WebAPI.Fakes;
using ADAssessment.WebAPI.Controllers;
using ADAssessment.WebAPI.Models;

namespace ADAssessment.Tests.WebAPI
{
    public class AssessmentControllerTests : IDisposable
    {
        private readonly string _emptyRulesFolder;

        public AssessmentControllerTests()
        {
            _emptyRulesFolder = Path.Combine(Path.GetTempPath(), "ADAssessmentTests_AssessmentRules_" + Guid.NewGuid());
        }

        public void Dispose()
        {
            if (Directory.Exists(_emptyRulesFolder))
            {
                Directory.Delete(_emptyRulesFolder, recursive: true);
            }
        }

        private AssessmentController MakeController(
            FakeLdapDataExtractor extractor,
            FakeAuditLogger auditLogger,
            IEnumerable<IComplianceRule>? rules = null,
            FakeSysvolDataExtractor? sysvolExtractor = null,
            IEnumerable<IGroupPolicyComplianceRule>? groupPolicyRules = null,
            IEnumerable<IComputerComplianceRule>? computerRules = null,
            FakeLdapProtocolSecurityChecker? ldapProtocolChecker = null,
            IEnumerable<ILdapProtocolComplianceRule>? ldapProtocolRules = null,
            FakeSmbProtocolSecurityChecker? smbProtocolChecker = null,
            IEnumerable<ISmbProtocolComplianceRule>? smbProtocolRules = null,
            IEnumerable<IDcSyncComplianceRule>? dcSyncRules = null,
            IEnumerable<IDomainFunctionalLevelComplianceRule>? domainFunctionalLevelRules = null,
            IEnumerable<IForestComplianceRule>? forestRules = null,
            IEnumerable<ITrustComplianceRule>? trustRules = null,
            ADAssessment.Infrastructure.Persistence.IScanHistoryRepository? scanHistoryRepository = null)
        {
            var controller = new AssessmentController(
                extractor,
                sysvolExtractor ?? FakeSysvolDataExtractor.Returning(Array.Empty<GroupPolicySecuritySettings>()),
                ldapProtocolChecker ?? FakeLdapProtocolSecurityChecker.Returning(new LdapProtocolSecuritySettings()),
                smbProtocolChecker ?? FakeSmbProtocolSecurityChecker.Returning(new SmbProtocolSecuritySettings()),
                rules ?? Array.Empty<IComplianceRule>(),
                groupPolicyRules ?? Array.Empty<IGroupPolicyComplianceRule>(),
                computerRules ?? Array.Empty<IComputerComplianceRule>(),
                ldapProtocolRules ?? Array.Empty<ILdapProtocolComplianceRule>(),
                smbProtocolRules ?? Array.Empty<ISmbProtocolComplianceRule>(),
                dcSyncRules ?? Array.Empty<IDcSyncComplianceRule>(),
                domainFunctionalLevelRules ?? Array.Empty<IDomainFunctionalLevelComplianceRule>(),
                forestRules ?? Array.Empty<IForestComplianceRule>(),
                trustRules ?? Array.Empty<ITrustComplianceRule>(),
                new JsonRuleRepository(_emptyRulesFolder),
                auditLogger,
                scanHistoryRepository ?? new FakeScanHistoryRepository(),
                NullLogger<AssessmentController>.Instance);

            // ControllerBase.User, HttpContext üzerinden okunuyor - gerçek bir HTTP isteği
            // olmadan çalıştırıldığında NullReferenceException atmaması için bir HttpContext set edilir.
            controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
            return controller;
        }

        [Fact]
        public void RunScan_LdapThrows_ReturnsGenericMessageWithoutLeakingExceptionDetails()
        {
            const string sensitiveDetail = "System.DirectoryServices.DirectoryEntry.Bind failed against DC=internal,DC=corp,DC=example at 10.0.0.5";
            var extractor = FakeLdapDataExtractor.ThrowingOnConnect(new InvalidOperationException(sensitiveDetail));
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(extractor, auditLogger);

            var result = controller.RunScan();

            var objectResult = Assert.IsType<ObjectResult>(result);
            Assert.Equal(500, objectResult.StatusCode);
            string json = System.Text.Json.JsonSerializer.Serialize(objectResult.Value);
            Assert.DoesNotContain(sensitiveDetail, json);
            Assert.DoesNotContain("DirectoryEntry", json);
        }

        [Fact]
        public void RunScan_Success_LogsAuditEntryAndReturnsOk()
        {
            var users = new List<AdUserAccount> { new AdUserAccount { SamAccountName = "jdoe", UserAccountControl = 0x0200 } };
            var extractor = FakeLdapDataExtractor.Returning(users);
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(extractor, auditLogger);

            var result = controller.RunScan();

            Assert.IsType<OkObjectResult>(result);
            Assert.True(auditLogger.WasCalled);
            Assert.Equal(1, auditLogger.LastScannedUserCount);
        }

        [Fact]
        public void RunScan_SysvolThrows_LdapScanStillSucceeds()
        {
            // AssessmentController.RunScan'deki SYSVOL try/catch'inin regresyon testi:
            // GPO verisi okunamasa bile LDAP tabanlı tarama etkilenmemeli, tüm istek
            // 500'e düşmemeli.
            var users = new List<AdUserAccount> { new AdUserAccount { SamAccountName = "jdoe", UserAccountControl = 0x0200 } };
            var extractor = FakeLdapDataExtractor.Returning(users);
            var sysvolExtractor = FakeSysvolDataExtractor.ThrowingOnAccess(new IOException("SYSVOL erişilemedi (test)"));
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(extractor, auditLogger, sysvolExtractor: sysvolExtractor);

            var result = controller.RunScan();

            Assert.IsType<OkObjectResult>(result);
        }

        [Fact]
        public void RunScan_WithGroupPolicyRule_ExecutesItAgainstSysvolData()
        {
            var users = new List<AdUserAccount>();
            var extractor = FakeLdapDataExtractor.Returning(users);
            var auditLogger = new FakeAuditLogger();
            var weakPolicy = new GroupPolicySecuritySettings { GpoName = "Default Domain Policy", MinimumPasswordLength = 4, PasswordComplexityEnabled = false };
            var sysvolExtractor = FakeSysvolDataExtractor.Returning(new[] { weakPolicy });
            var controller = MakeController(
                extractor,
                auditLogger,
                sysvolExtractor: sysvolExtractor,
                groupPolicyRules: new IGroupPolicyComplianceRule[] { new WeakPasswordPolicyRule() });

            var result = controller.RunScan();

            var okResult = Assert.IsType<OkObjectResult>(result);
            string json = System.Text.Json.JsonSerializer.Serialize(okResult.Value);
            Assert.Contains("AD-013", json);
            Assert.Contains("Default Domain Policy", json);
        }

        [Fact]
        public void RunScan_Result_IncludesComplianceMappingsFromRuleMetadata()
        {
            // Otomatik Compliance Mapping deliverable'ının regresyon testi: her bulgu,
            // /api/rules'a ayrıca bakılmasına gerek kalmadan kendi FrameworkMapping ve
            // Iso27001Mapping değerlerini taşımalı.
            var users = new List<AdUserAccount>
            {
                new AdUserAccount { SamAccountName = "nopass", UserAccountControl = 0x0200 | 0x0020 }
            };
            var extractor = FakeLdapDataExtractor.Returning(users);
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(
                extractor,
                auditLogger,
                rules: new IComplianceRule[] { new PasswordNotRequiredRule() });

            var result = controller.RunScan();

            var okResult = Assert.IsType<OkObjectResult>(result);
            var response = Assert.IsType<ScanResultResponse>(okResult.Value);
            var ruleResult = Assert.Single(response.Results);
            Assert.Equal("AD-004", ruleResult.RuleId);
            Assert.NotEmpty(ruleResult.FrameworkMapping);
            Assert.Contains("ISO/IEC 27001", ruleResult.Iso27001Mapping);
        }

        [Fact]
        public void RunScan_ComputerQueryThrows_UserScanStillSucceeds()
        {
            // Bilgisayar nesnesi sorgusundaki bir hatanın (ör. yetersiz izin, timeout)
            // tüm taramayı düşürmemesi gerektiğinin regresyon testi - SYSVOL izolasyonuyla
            // aynı desen (RunScan_SysvolThrows_LdapScanStillSucceeds).
            var users = new List<AdUserAccount> { new AdUserAccount { SamAccountName = "jdoe", UserAccountControl = 0x0200 } };
            var extractor = FakeLdapDataExtractor.ThrowingOnComputerQuery(users, new InvalidOperationException("computer query failed (test)"));
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(
                extractor,
                auditLogger,
                computerRules: new IComputerComplianceRule[] { new StaleComputerAccountsRule() });

            var result = controller.RunScan();

            var okResult = Assert.IsType<OkObjectResult>(result);
            var response = Assert.IsType<ScanResultResponse>(okResult.Value);
            Assert.Equal(1, response.ScannedUserCount);
            Assert.Equal(0, response.ScannedComputerCount);
            var computerRuleResult = Assert.Single(response.Results, r => r.RuleId == "AD-016");
            Assert.Equal("Informational", computerRuleResult.RiskLevel);
        }

        [Fact]
        public void RunScan_DcSyncQueryThrows_UserScanStillSucceeds()
        {
            // DCSync hakları sorgusundaki bir hatanın (ör. domain kökü okunamıyor) tüm
            // taramayı düşürmemesi gerektiğinin regresyon testi - aynı izolasyon deseni.
            var users = new List<AdUserAccount> { new AdUserAccount { SamAccountName = "jdoe", UserAccountControl = 0x0200 } };
            var extractor = FakeLdapDataExtractor.ThrowingOnDcSyncQuery(users, new InvalidOperationException("dcsync query failed (test)"));
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(
                extractor,
                auditLogger,
                dcSyncRules: new IDcSyncComplianceRule[] { new UnexpectedDcSyncRightsRule() });

            var result = controller.RunScan();

            var okResult = Assert.IsType<OkObjectResult>(result);
            var response = Assert.IsType<ScanResultResponse>(okResult.Value);
            var dcSyncRuleResult = Assert.Single(response.Results, r => r.RuleId == "AD-023");
            Assert.Equal("Informational", dcSyncRuleResult.RiskLevel);
        }

        [Fact]
        public void RunScan_LdapProtocolCheckThrows_UserScanStillSucceeds()
        {
            // LDAP protokol güvenliği kontrolündeki bir hatanın (ör. DC'ye 389 portundan
            // erişilemiyor) tüm taramayı düşürmemesi gerektiğinin regresyon testi -
            // aynı izolasyon deseni (SYSVOL/computer).
            var users = new List<AdUserAccount> { new AdUserAccount { SamAccountName = "jdoe", UserAccountControl = 0x0200 } };
            var extractor = FakeLdapDataExtractor.Returning(users);
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(
                extractor,
                auditLogger,
                ldapProtocolChecker: FakeLdapProtocolSecurityChecker.ThrowingOnAccess(new InvalidOperationException("ldap protocol check failed (test)")),
                ldapProtocolRules: new ILdapProtocolComplianceRule[] { new LdapSigningNotEnforcedRule() });

            var result = controller.RunScan();

            var okResult = Assert.IsType<OkObjectResult>(result);
            var response = Assert.IsType<ScanResultResponse>(okResult.Value);
            var ldapRuleResult = Assert.Single(response.Results, r => r.RuleId == "AD-019");
            Assert.Equal("Informational", ldapRuleResult.RiskLevel);
        }

        [Fact]
        public void RunScan_Success_SavesToScanHistoryRepository()
        {
            // Tarama geçmişi veritabanına kaydetme entegrasyonunun regresyon testi -
            // FakeAuditLogger.WasCalled deseniyle aynı şekilde doğrulanır.
            var users = new List<AdUserAccount>
            {
                new AdUserAccount { SamAccountName = "nopass", UserAccountControl = 0x0200 | 0x0020 }
            };
            var extractor = FakeLdapDataExtractor.Returning(users);
            var auditLogger = new FakeAuditLogger();
            var scanHistoryRepository = new FakeScanHistoryRepository();
            var controller = MakeController(
                extractor,
                auditLogger,
                rules: new IComplianceRule[] { new PasswordNotRequiredRule() },
                scanHistoryRepository: scanHistoryRepository);

            var result = controller.RunScan();

            Assert.IsType<OkObjectResult>(result);
            Assert.True(scanHistoryRepository.WasCalled);
            Assert.Equal(1, scanHistoryRepository.LastVulnerableRulesCount);
            Assert.NotNull(scanHistoryRepository.LastFindings);
            Assert.Contains(scanHistoryRepository.LastFindings!, f => f.RuleId == "AD-004");
        }

        [Fact]
        public void RunScan_ScanHistoryRepositoryThrows_ScanStillSucceeds()
        {
            // Geçmiş kaydı başarısız olsa bile (ör. disk dolu) taramanın kendisi
            // 500'e düşmemeli - SYSVOL/computer izolasyonuyla aynı desen.
            var users = new List<AdUserAccount> { new AdUserAccount { SamAccountName = "jdoe", UserAccountControl = 0x0200 } };
            var extractor = FakeLdapDataExtractor.Returning(users);
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(
                extractor,
                auditLogger,
                scanHistoryRepository: new ThrowingFakeScanHistoryRepository());

            var result = controller.RunScan();

            Assert.IsType<OkObjectResult>(result);
        }

        [Fact]
        public void GetExecutiveReport_Success_ReturnsSelfContainedHtml()
        {
            var users = new List<AdUserAccount>
            {
                new AdUserAccount { SamAccountName = "nopass", UserAccountControl = 0x0200 | 0x0020 }
            };
            var extractor = FakeLdapDataExtractor.Returning(users);
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(
                extractor,
                auditLogger,
                rules: new IComplianceRule[] { new PasswordNotRequiredRule() });

            var result = controller.GetExecutiveReport();

            var contentResult = Assert.IsType<ContentResult>(result);
            Assert.Equal("text/html", contentResult.ContentType?.Split(';')[0]);
            // charset açıkça belirtilmezse istemciler Türkçe karakterleri (ğ, ş, ü vb.)
            // yanlış decode edebilir - bu, canlı testte gerçekten yaşanmış bir regresyon.
            Assert.Contains("utf-8", contentResult.ContentType, StringComparison.OrdinalIgnoreCase);
            Assert.Contains("<html", contentResult.Content);
            Assert.Contains("AD-004", contentResult.Content);
            // Zero-trust: rapor hiçbir dış kaynağa (CDN, font, script) bağlı olmamalı.
            Assert.DoesNotContain("http://", contentResult.Content);
            Assert.DoesNotContain("https://", contentResult.Content);
        }

        [Fact]
        public void RunScan_DynamicComputerCategoryRule_ExecutesAgainstComputersNotUsers()
        {
            // Faz 2 (No-Code'un tüm veri kategorilerine açılması) düzeltmesinin asıl
            // regresyon testi: eskiden TÜM No-Code JSON kuralları (kategorisi ne olursa
            // olsun) sadece 'users' listesine karşı çalıştırılıyordu. Bu test, DataCategory
            // "Computer" olan bir JSON dosyasının gerçekten computers listesine karşı
            // çalıştığını - ve tarayıcıdaki eşleşen bilgisayarın rapora yansıdığını - doğrular.
            Directory.CreateDirectory(_emptyRulesFolder);
            string ruleJson = System.Text.Json.JsonSerializer.Serialize(new
            {
                ruleId = "TEST-DYNAMIC-COMPUTER",
                name = "Obsolete OS (No-Code)",
                description = "Test-only dynamic computer rule.",
                dataCategory = "Computer",
                targetProperty = "OperatingSystem",
                @operator = "Contains",
                value = "2012",
                riskLevel = "High",
                remediation = "Upgrade the OS."
            });
            File.WriteAllText(Path.Combine(_emptyRulesFolder, "TEST-DYNAMIC-COMPUTER.json"), ruleJson);

            var users = new List<AdUserAccount> { new AdUserAccount { SamAccountName = "jdoe", UserAccountControl = 0x0200 } };
            var computers = new List<AdComputerAccount> { new AdComputerAccount { SamAccountName = "OLDPC$", OperatingSystem = "Windows Server 2012 R2" } };
            var extractor = FakeLdapDataExtractor.Returning(users, computers);
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(extractor, auditLogger);

            var result = controller.RunScan();

            var okResult = Assert.IsType<OkObjectResult>(result);
            var response = Assert.IsType<ScanResultResponse>(okResult.Value);
            var dynamicRuleResult = Assert.Single(response.Results, r => r.RuleId == "TEST-DYNAMIC-COMPUTER");
            Assert.True(dynamicRuleResult.IsVulnerable);
            Assert.Contains(dynamicRuleResult.AffectedObjects, a => a.Contains("OLDPC$"));
        }

        [Fact]
        public void GetExecutiveReport_LdapThrows_ReturnsGenericErrorWithoutLeakingDetails()
        {
            const string sensitiveDetail = "System.DirectoryServices.DirectoryEntry.Bind failed against DC=internal,DC=corp,DC=example";
            var extractor = FakeLdapDataExtractor.ThrowingOnConnect(new InvalidOperationException(sensitiveDetail));
            var auditLogger = new FakeAuditLogger();
            var controller = MakeController(extractor, auditLogger);

            var result = controller.GetExecutiveReport();

            var objectResult = Assert.IsType<ObjectResult>(result);
            Assert.Equal(500, objectResult.StatusCode);
            string json = System.Text.Json.JsonSerializer.Serialize(objectResult.Value);
            Assert.DoesNotContain(sensitiveDetail, json);
        }
    }
}
