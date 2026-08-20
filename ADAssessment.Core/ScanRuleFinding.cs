using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// Tek bir kuralın, tek bir taramadaki sonucunu, veritabanına kalıcı olarak yazılmak
    /// üzere temsil eder. RuleResult (Core)'dan farkı: FrameworkMapping/Iso27001Mapping da
    /// içerir - bu ikisi RuleResult'ta yok, sadece kural metadata'sından (RulesController/
    /// AssessmentController'ın rule.FrameworkMapping/rule.Iso27001Mapping'i) geliyor.
    /// WebAPI'nin RuleResultDto'sunun (XmlSerializer kısıtları yüzünden ayrı tutulan) Core
    /// katmanındaki karşılığı - Infrastructure katmanı WebAPI'ye bağımlı olamayacağından
    /// (Clean Architecture bağımlılık yönü), bu tip burada, Core'da tanımlanır.
    /// </summary>
    public sealed record ScanRuleFinding(
        string RuleId,
        bool IsVulnerable,
        string RiskLevel,
        string FrameworkMapping,
        string Iso27001Mapping,
        IReadOnlyList<string> AffectedObjects,
        string Remediation);
}
