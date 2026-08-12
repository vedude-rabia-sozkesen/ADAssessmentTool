using System.Text.RegularExpressions;

namespace ADAssessment.Core
{
    /// <summary>
    /// No-Code JSON kural dosyalarının dosya adı olarak da kullanılan RuleId
    /// alanını doğrulayan yardımcı sınıf. Path traversal (../, mutlak yol vb.)
    /// içeren değerlerin dosya sistemi işlemlerine sızmasını engeller.
    /// </summary>
    public static class RuleIdValidator
    {
        private static readonly Regex AllowedPattern = new("^[A-Za-z0-9_-]{1,64}$", RegexOptions.Compiled);

        public static bool IsValid(string? ruleId)
        {
            return !string.IsNullOrWhiteSpace(ruleId) && AllowedPattern.IsMatch(ruleId);
        }
    }
}
