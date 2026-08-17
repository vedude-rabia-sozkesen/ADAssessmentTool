using System;
using System.Collections.Generic;
using System.IO;
using Microsoft.AspNetCore.Mvc;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.WebAPI.Controllers;
using ADAssessment.WebAPI.Models;

namespace ADAssessment.Tests.WebAPI
{
    public class RulesControllerTests : IDisposable
    {
        private readonly string _tempRulesFolder;

        public RulesControllerTests()
        {
            // RulesController şu an (mevcut koddaki gibi) her zaman
            // AppDomain.CurrentDomain.BaseDirectory/rules klasörünü hedefliyor; test
            // izolasyonu için sadece bu test tarafından oluşturulan dosyaları temizliyoruz.
            _tempRulesFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");
        }

        public void Dispose()
        {
            foreach (var file in new[] { "TEST-RULES-CONTROLLER.json", "TEST-RULES-EDIT.json", "TEST-RULES-DELETE.json" })
            {
                string path = Path.Combine(_tempRulesFolder, file);
                if (File.Exists(path)) File.Delete(path);
            }
        }

        private static RulesController MakeController(string rulesFolder, IEnumerable<IComplianceRule>? staticRules = null)
        {
            return new RulesController(
                new JsonRuleRepository(rulesFolder),
                staticRules ?? Array.Empty<IComplianceRule>(),
                Array.Empty<IGroupPolicyComplianceRule>());
        }

        private static JsonRuleDefinition SimpleDefinition(string ruleId) => new JsonRuleDefinition
        {
            RuleId = ruleId,
            Name = "Test Rule",
            TargetProperty = "UserAccountControl",
            Operator = "BitwiseAND",
            Value = 32,
            Condition = "NotEqualZero"
        };

        [Fact]
        public void CreateJsonRule_ValidRuleId_WritesFileAndReturnsCreated()
        {
            var controller = MakeController(_tempRulesFolder);

            var result = controller.CreateJsonRule(SimpleDefinition("TEST-RULES-CONTROLLER"));

            Assert.IsType<CreatedAtActionResult>(result);
            Assert.True(File.Exists(Path.Combine(_tempRulesFolder, "TEST-RULES-CONTROLLER.json")));
        }

        [Theory]
        [InlineData("../../evil")]
        [InlineData("..\\..\\evil")]
        [InlineData("")]
        public void CreateJsonRule_PathTraversalOrInvalidRuleId_ReturnsBadRequestAndWritesNothingOutside(string maliciousRuleId)
        {
            var controller = MakeController(_tempRulesFolder);
            var definition = new JsonRuleDefinition { RuleId = maliciousRuleId };

            var result = controller.CreateJsonRule(definition);

            Assert.IsType<BadRequestObjectResult>(result);
        }

        [Fact]
        public void CreateJsonRule_ConflictingWithStaticRuleId_ReturnsBadRequest()
        {
            var staticRule = new FakeStaticRule("AD-001");
            var controller = MakeController(_tempRulesFolder, new[] { (IComplianceRule)staticRule });

            var result = controller.CreateJsonRule(SimpleDefinition("AD-001"));

            Assert.IsType<BadRequestObjectResult>(result);
        }

        [Fact]
        public void GetRules_CombinesStaticAndJsonRules_WithCorrectSourceTags()
        {
            var controller = MakeController(_tempRulesFolder, new[] { (IComplianceRule)new FakeStaticRule("AD-001") });
            controller.CreateJsonRule(SimpleDefinition("TEST-RULES-CONTROLLER"));

            var result = controller.GetRules();

            var okResult = Assert.IsType<OkObjectResult>(result);
            var items = Assert.IsAssignableFrom<IEnumerable<RuleListItem>>(okResult.Value);
            var list = new List<RuleListItem>(items);

            Assert.Contains(list, i => i.RuleId == "AD-001" && i.Source == "Static" && !i.IsEditable);
            Assert.Contains(list, i => i.RuleId == "TEST-RULES-CONTROLLER" && i.Source == "JsonFile" && i.IsEditable);
        }

        [Fact]
        public void UpdateJsonRule_ExistingRule_OverwritesFileAndReturnsOk()
        {
            var controller = MakeController(_tempRulesFolder);
            controller.CreateJsonRule(SimpleDefinition("TEST-RULES-EDIT"));

            var updated = SimpleDefinition("TEST-RULES-EDIT");
            updated.RiskLevel = "Low";
            var result = controller.UpdateJsonRule("TEST-RULES-EDIT", updated);

            Assert.IsType<OkObjectResult>(result);
            string content = File.ReadAllText(Path.Combine(_tempRulesFolder, "TEST-RULES-EDIT.json"));
            Assert.Contains("\"Low\"", content);
        }

        [Fact]
        public void UpdateJsonRule_NonExistentRule_ReturnsNotFound()
        {
            var controller = MakeController(_tempRulesFolder);

            var result = controller.UpdateJsonRule("DOES-NOT-EXIST", SimpleDefinition("DOES-NOT-EXIST"));

            Assert.IsType<NotFoundObjectResult>(result);
        }

        [Fact]
        public void UpdateJsonRule_StaticRuleId_ReturnsBadRequest()
        {
            var controller = MakeController(_tempRulesFolder, new[] { (IComplianceRule)new FakeStaticRule("AD-001") });

            var result = controller.UpdateJsonRule("AD-001", SimpleDefinition("AD-001"));

            Assert.IsType<BadRequestObjectResult>(result);
        }

        [Theory]
        [InlineData("../../evil")]
        [InlineData("..\\..\\evil")]
        public void UpdateJsonRule_PathTraversalRuleId_ReturnsBadRequest(string maliciousRuleId)
        {
            var controller = MakeController(_tempRulesFolder);

            var result = controller.UpdateJsonRule(maliciousRuleId, SimpleDefinition(maliciousRuleId));

            Assert.IsType<BadRequestObjectResult>(result);
        }

        [Fact]
        public void DeleteJsonRule_ExistingRule_RemovesFileAndReturnsOk()
        {
            var controller = MakeController(_tempRulesFolder);
            controller.CreateJsonRule(SimpleDefinition("TEST-RULES-DELETE"));

            var result = controller.DeleteJsonRule("TEST-RULES-DELETE");

            Assert.IsType<OkObjectResult>(result);
            Assert.False(File.Exists(Path.Combine(_tempRulesFolder, "TEST-RULES-DELETE.json")));
        }

        [Fact]
        public void DeleteJsonRule_NonExistentRule_ReturnsNotFound()
        {
            var controller = MakeController(_tempRulesFolder);

            var result = controller.DeleteJsonRule("DOES-NOT-EXIST");

            Assert.IsType<NotFoundObjectResult>(result);
        }

        [Fact]
        public void DeleteJsonRule_StaticRuleId_ReturnsBadRequestAndDoesNotThrow()
        {
            var controller = MakeController(_tempRulesFolder, new[] { (IComplianceRule)new FakeStaticRule("AD-001") });

            var result = controller.DeleteJsonRule("AD-001");

            Assert.IsType<BadRequestObjectResult>(result);
        }

        [Theory]
        [InlineData("../../evil")]
        [InlineData("..\\..\\evil")]
        public void DeleteJsonRule_PathTraversalRuleId_ReturnsBadRequest(string maliciousRuleId)
        {
            var controller = MakeController(_tempRulesFolder);

            var result = controller.DeleteJsonRule(maliciousRuleId);

            Assert.IsType<BadRequestObjectResult>(result);
        }

        [Fact]
        public void GetRules_ReturnsOkWithRuleList()
        {
            var controller = MakeController(_tempRulesFolder);

            var result = controller.GetRules();

            Assert.IsType<OkObjectResult>(result);
        }

        private sealed class FakeStaticRule : IComplianceRule
        {
            public FakeStaticRule(string ruleId) => RuleId = ruleId;
            public string RuleId { get; }
            public string Name => "Fake Static Rule";
            public string Description => "Test-only stand-in for a compiled rule.";
            public string FrameworkMapping => "N/A";
            public RuleResult Execute(object directoryData) => new RuleResult { RuleId = RuleId, IsVulnerable = false, RiskLevel = "Low" };
        }
    }
}
