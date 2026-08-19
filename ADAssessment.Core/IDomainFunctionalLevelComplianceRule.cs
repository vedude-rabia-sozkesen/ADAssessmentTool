namespace ADAssessment.Core
{
    /// <summary>
    /// DomainFunctionalLevelSettings verisi üzerinde çalışan kuralları diğer kategorilerden
    /// ayırt etmek için kullanılan işaretleyici (marker) arayüz. Aynı desen: bkz.
    /// IDcSyncComplianceRule, ILdapProtocolComplianceRule, IComputerComplianceRule.
    /// </summary>
    public interface IDomainFunctionalLevelComplianceRule : IComplianceRule
    {
    }
}
