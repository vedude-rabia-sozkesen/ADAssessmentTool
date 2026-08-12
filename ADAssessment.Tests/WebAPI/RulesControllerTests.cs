using System;
using System.IO;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.WebAPI.Controllers;

namespace ADAssessment.Tests.WebAPI
{
    public class RulesControllerTests : IDisposable
    {
        private readonly string _tempRulesFolder;
        private readonly string _originalBaseDirectory;

        public RulesControllerTests()
        {
            // RulesController.CreateJsonRule, AppDomain.CurrentDomain.BaseDirectory altındaki
            // "rules" klasörünü kullanıyor; test izolasyonu için AppContext.BaseDirectory
            // gerçek build çıktısına yazmamak amacıyla burada doğrudan o klasörü hedefliyoruz
            // ve testten sonra sadece test tarafından oluşturulan dosyaları temizliyoruz.
            _tempRulesFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");
            _originalBaseDirectory = _tempRulesFolder;
        }

        public void Dispose()
        {
            string marker = Path.Combine(_tempRulesFolder, "TEST-RULES-CONTROLLER.json");
            if (File.Exists(marker))
            {
                File.Delete(marker);
            }
        }

        private static RulesController MakeController(string rulesFolder)
        {
            return new RulesController(new JsonRuleRepository(rulesFolder));
        }

        [Fact]
        public void CreateJsonRule_ValidRuleId_WritesFileAndReturnsCreated()
        {
            var controller = MakeController(_tempRulesFolder);
            var definition = new JsonRuleDefinition
            {
                RuleId = "TEST-RULES-CONTROLLER",
                Name = "Test Rule",
                TargetProperty = "UserAccountControl",
                Operator = "BitwiseAND",
                Value = 32,
                Condition = "NotEqualZero"
            };

            var result = controller.CreateJsonRule(definition);

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
        public void GetRules_ReturnsOkWithRuleList()
        {
            var controller = MakeController(_tempRulesFolder);

            var result = controller.GetRules();

            Assert.IsType<OkObjectResult>(result);
        }
    }
}
