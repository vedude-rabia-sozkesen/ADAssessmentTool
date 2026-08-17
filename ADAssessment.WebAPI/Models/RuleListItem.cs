using ADAssessment.Core;

namespace ADAssessment.WebAPI.Models
{
    /// <summary>
    /// "Aktif Kurallar" listesinde hem sabit (compiled) C# kurallarını hem
    /// No-Code JSON kurallarını tek bir tutarlı şekilde göstermek için kullanılan
    /// görünüm modeli (WebAPI katmanına özgü - Core/Infrastructure'ı kirletmez).
    /// </summary>
    public sealed class RuleListItem
    {
        public string RuleId { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string FrameworkMapping { get; set; } = string.Empty;
        public string Iso27001Mapping { get; set; } = string.Empty;

        /// <summary>"Static" (derlenmiş C# kodu) veya "JsonFile" (rules/ klasöründeki dosya).</summary>
        public string Source { get; set; } = string.Empty;

        /// <summary>
        /// Sadece JsonFile kaynaklı VE nested (iç içe AND/OR) koşul içermeyen kurallar
        /// için true - No-Code formu yalnızca tekli koşulları düzenleyebilir.
        /// </summary>
        public bool IsEditable { get; set; }

        /// <summary>Sadece JsonFile kaynaklı kurallarda dolu - edit formunu önceden doldurmak için.</summary>
        public JsonRuleDefinition? Definition { get; set; }
    }
}
