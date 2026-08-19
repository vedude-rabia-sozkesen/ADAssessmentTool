namespace ADAssessment.Core
{
    /// <summary>
    /// ForestOptionalFeatureSettings verisi üzerinde çalışan kuralları diğer kategorilerden
    /// ayırt etmek için kullanılan işaretleyici (marker) arayüz. Aynı desen: bkz.
    /// IDomainFunctionalLevelComplianceRule, IDcSyncComplianceRule.
    /// </summary>
    public interface IForestComplianceRule : IComplianceRule
    {
    }
}
