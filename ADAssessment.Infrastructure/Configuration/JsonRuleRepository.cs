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

        /// <summary>
        /// Bu depo örneğinin okuduğu/yazdığı gerçek klasör yolu. RulesController gibi
        /// tüketicilerin kendi ayrı bir yol hesaplamak yerine bu değeri kullanması,
        /// WebAPI ve ConsoleApp'ın (ve ileride eklenecek her tüketicinin) her zaman
        /// aynı kural kümesini görmesini garanti eder.
        /// </summary>
        public string RulesFolderPath => _rulesFolderPath;

        public JsonRuleRepository(string? rulesFolderPath = null)
        {
            _rulesFolderPath = rulesFolderPath ?? ResolveDefaultRulesFolder();
        }

        /// <summary>
        /// Varsayılan kural klasörünü belirler. Önceden her çalıştırılabilir dosya
        /// (WebAPI/ConsoleApp) kendi "bin" klasöründeki ayrı bir rules/ alt klasörüne
        /// bakıyordu - bu, aynı No-Code kuralının bir arayüzde görünüp diğerinde
        /// görünmemesine yol açıyordu. Artık ikisi de, hangi klasörden çalıştırılırsa
        /// çalıştırılsın aynı yere işaret eden makine-geneli bir konumu (%ProgramData%)
        /// kullanıyor. AD_ASSESSMENT_RULES_PATH env var'ı ile açıkça geçersiz kılınabilir.
        /// </summary>
        private static string ResolveDefaultRulesFolder()
        {
            string? envOverride = Environment.GetEnvironmentVariable("AD_ASSESSMENT_RULES_PATH");
            if (!string.IsNullOrWhiteSpace(envOverride))
            {
                return envOverride;
            }

            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(programData, "ADAssessmentTool", "rules");
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
