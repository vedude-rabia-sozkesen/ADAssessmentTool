using System;
using System.Collections.Generic;
using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Sysvol
{
    /// <summary>
    /// SYSVOL üzerindeki GptTmpl.inf dosyalarının içeriğini (standart Windows
    /// "security template" INI formatı) ayrıştıran, tamamen saf (I/O'suz) sınıf.
    /// Ağ/dosya erişimi SysvolDataExtractor'a ait - bu sınıf sadece metni alır,
    /// bu ayrım sayesinde gerçek SYSVOL erişimi olmadan birim testleriyle
    /// doğrulanabilir (JsonRuleRepository'nin dosya-okuma/ayrıştırma ayrımıyla aynı prensip).
    /// </summary>
    public static class GptTmplParser
    {
        private const string SystemAccessSection = "System Access";

        public static GroupPolicySecuritySettings Parse(string gptTmplContent, string gpoName, string gpoGuid)
        {
            Dictionary<string, string> systemAccessValues = ExtractSection(gptTmplContent, SystemAccessSection);

            return new GroupPolicySecuritySettings
            {
                GpoName = gpoName,
                GpoGuid = gpoGuid,
                MinimumPasswordLength = GetInt(systemAccessValues, "MinimumPasswordLength"),
                PasswordComplexityEnabled = GetInt(systemAccessValues, "PasswordComplexity") != 0,
                MaximumPasswordAgeDays = GetInt(systemAccessValues, "MaximumPasswordAge"),
                LockoutThreshold = GetInt(systemAccessValues, "LockoutBadCount"),
                LockoutDurationMinutes = GetInt(systemAccessValues, "LockoutDuration"),
                ReversibleEncryptionEnabled = GetInt(systemAccessValues, "ClearTextPassword") != 0
            };
        }

        /// <summary>
        /// Verilen INI içeriğinden tek bir [Bölüm] altındaki "Anahtar = Değer"
        /// satırlarını, büyük/küçük harf duyarsız anahtarlarla bir sözlüğe toplar.
        /// </summary>
        private static Dictionary<string, string> ExtractSection(string content, string sectionName)
        {
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            bool inTargetSection = false;

            foreach (string rawLine in content.Split('\n'))
            {
                string line = rawLine.Trim().TrimEnd('\r');

                if (line.Length == 0 || line.StartsWith(';'))
                {
                    continue;
                }

                if (line.StartsWith('[') && line.EndsWith(']'))
                {
                    string currentSection = line[1..^1].Trim();
                    inTargetSection = string.Equals(currentSection, sectionName, StringComparison.OrdinalIgnoreCase);
                    continue;
                }

                if (!inTargetSection)
                {
                    continue;
                }

                int separatorIndex = line.IndexOf('=');
                if (separatorIndex <= 0)
                {
                    continue;
                }

                string key = line[..separatorIndex].Trim();
                string value = line[(separatorIndex + 1)..].Trim();
                values[key] = value;
            }

            return values;
        }

        private static int GetInt(Dictionary<string, string> values, string key)
        {
            if (values.TryGetValue(key, out string? raw) && int.TryParse(raw, out int parsed))
            {
                return parsed;
            }
            return 0;
        }
    }
}
