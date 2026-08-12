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
    }
}
