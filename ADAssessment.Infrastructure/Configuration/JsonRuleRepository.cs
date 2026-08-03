using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Configuration
{
    /// <summary>
    /// Disk üzerindeki 'rules/' klasöründen tüm JSON tabanlı kuralları okuyup
    /// IComplianceRule nesnelerine dönüştüren dinamik kural deposu.
    /// </summary>
    public sealed class JsonRuleRepository
    {
        private readonly string _rulesFolderPath;

        public JsonRuleRepository(string? rulesFolderPath = null)
        {
            _rulesFolderPath = rulesFolderPath ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");
        }

        public IReadOnlyList<IComplianceRule> LoadRules()
        {
            var rules = new List<IComplianceRule>();

            if (!Directory.Exists(_rulesFolderPath))
            {
                Directory.CreateDirectory(_rulesFolderPath);
                Console.WriteLine($"[*] [RULES] 'rules/' klasörü oluşturuldu: {_rulesFolderPath}");
                return rules;
            }

            string[] jsonFiles = Directory.GetFiles(_rulesFolderPath, "*.json", SearchOption.AllDirectories);

            foreach (var filePath in jsonFiles)
            {
                try
                {
                    string jsonContent = File.ReadAllText(filePath);
                    var definition = JsonSerializer.Deserialize<JsonRuleDefinition>(jsonContent);

                    if (definition != null && !string.IsNullOrWhiteSpace(definition.RuleId))
                    {
                        rules.Add(new DynamicComplianceRule(definition));
                        Console.WriteLine($"[+] [JSON KURAL YÜKLENDİ] ID: {definition.RuleId} | İsim: {definition.Name}");
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[-] [JSON KURAL HATA] '{filePath}' okunamadı: {ex.Message}");
                }
            }

            return rules;
        }
    }
}
