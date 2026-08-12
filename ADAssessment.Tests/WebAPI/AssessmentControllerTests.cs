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

        private AssessmentController MakeController(FakeLdapDataExtractor extractor, FakeAuditLogger auditLogger, IEnumerable<IComplianceRule>? rules = null)
        {
            var controller = new AssessmentController(
                extractor,
                rules ?? Array.Empty<IComplianceRule>(),
                new JsonRuleRepository(_emptyRulesFolder),
                auditLogger,
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
    }
}
