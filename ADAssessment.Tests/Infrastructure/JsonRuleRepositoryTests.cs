using System;
using System.IO;
using ADAssessment.Infrastructure.Configuration;

namespace ADAssessment.Tests.Infrastructure
{
    public class JsonRuleRepositoryTests : IDisposable
    {
        private readonly string _tempFolder;

        public JsonRuleRepositoryTests()
        {
            _tempFolder = Path.Combine(Path.GetTempPath(), "ADAssessmentTests_Rules_" + Guid.NewGuid());
        }

        public void Dispose()
        {
            if (Directory.Exists(_tempFolder))
            {
                Directory.Delete(_tempFolder, recursive: true);
            }
        }

        [Fact]
        public void LoadRules_MissingFolder_CreatesItAndReturnsEmptyList()
        {
            var repository = new JsonRuleRepository(_tempFolder);

            var rules = repository.LoadRules();

            Assert.Empty(rules);
            Assert.True(Directory.Exists(_tempFolder));
        }

        [Fact]
        public void LoadRules_ValidJsonRuleFile_IsLoadedCorrectly()
        {
            Directory.CreateDirectory(_tempFolder);
            File.WriteAllText(Path.Combine(_tempFolder, "TEST-001.json"), """
                {
                  "ruleId": "TEST-001",
                  "name": "Test Rule",
                  "targetProperty": "UserAccountControl",
                  "operator": "BitwiseAND",
                  "value": 32,
                  "condition": "NotEqualZero",
                  "riskLevel": "High"
                }
                """);

            var repository = new JsonRuleRepository(_tempFolder);
            var rules = repository.LoadRules();

            Assert.Single(rules);
            Assert.Equal("TEST-001", rules[0].RuleId);
        }

        [Fact]
        public void LoadRules_MalformedJsonFile_IsSkippedWithoutThrowing()
        {
            Directory.CreateDirectory(_tempFolder);
            File.WriteAllText(Path.Combine(_tempFolder, "broken.json"), "{ this is not valid json");
            File.WriteAllText(Path.Combine(_tempFolder, "TEST-002.json"), """{ "ruleId": "TEST-002" }""");

            var repository = new JsonRuleRepository(_tempFolder);

            var exception = Record.Exception(() => repository.LoadRules());
            var rules = repository.LoadRules();

            Assert.Null(exception);
            Assert.Single(rules);
            Assert.Equal("TEST-002", rules[0].RuleId);
        }

        [Fact]
        public void LoadRules_FileWithoutRuleId_IsSkipped()
        {
            Directory.CreateDirectory(_tempFolder);
            File.WriteAllText(Path.Combine(_tempFolder, "norule.json"), """{ "name": "no id here" }""");

            var repository = new JsonRuleRepository(_tempFolder);
            var rules = repository.LoadRules();

            Assert.Empty(rules);
        }

        [Fact]
        public void RulesFolderPath_ExplicitPath_IsUsedAsIs()
        {
            var repository = new JsonRuleRepository(_tempFolder);

            Assert.Equal(_tempFolder, repository.RulesFolderPath);
        }

        [Fact]
        public void RulesFolderPath_NoExplicitPathAndNoEnvVar_ResolvesUnderProgramData()
        {
            // WebAPI ve ConsoleApp'ın (env var/açık yol verilmediğinde) aynı makine-geneli
            // klasöre işaret etmesinin regresyon testi - bu oturumda AD-011/AD-012'nin
            // WebAPI'de görünmemesine yol açan "her exe kendi bin klasörüne bakıyor" sorununu düzeltiyor.
            string? original = Environment.GetEnvironmentVariable("AD_ASSESSMENT_RULES_PATH");
            try
            {
                Environment.SetEnvironmentVariable("AD_ASSESSMENT_RULES_PATH", null);

                var repository = new JsonRuleRepository();

                string expectedRoot = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                Assert.StartsWith(expectedRoot, repository.RulesFolderPath, StringComparison.OrdinalIgnoreCase);
                Assert.Contains("ADAssessmentTool", repository.RulesFolderPath);
            }
            finally
            {
                Environment.SetEnvironmentVariable("AD_ASSESSMENT_RULES_PATH", original);
            }
        }

        [Fact]
        public void RulesFolderPath_EnvVarSet_OverridesDefault()
        {
            string? original = Environment.GetEnvironmentVariable("AD_ASSESSMENT_RULES_PATH");
            try
            {
                Environment.SetEnvironmentVariable("AD_ASSESSMENT_RULES_PATH", _tempFolder);

                var repository = new JsonRuleRepository();

                Assert.Equal(_tempFolder, repository.RulesFolderPath);
            }
            finally
            {
                Environment.SetEnvironmentVariable("AD_ASSESSMENT_RULES_PATH", original);
            }
        }
    }
}
