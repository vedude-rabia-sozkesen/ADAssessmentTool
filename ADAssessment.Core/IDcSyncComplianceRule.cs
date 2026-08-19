namespace ADAssessment.Core
{
    /// <summary>
    /// DcSyncRightsSettings verisi üzerinde çalışan kuralları diğer kategorilerden ayırt
    /// etmek için kullanılan işaretleyici (marker) arayüz. Aynı desen: bkz.
    /// ILdapProtocolComplianceRule, ISmbProtocolComplianceRule, IComputerComplianceRule.
    /// </summary>
    public interface IDcSyncComplianceRule : IComplianceRule
    {
    }
}
