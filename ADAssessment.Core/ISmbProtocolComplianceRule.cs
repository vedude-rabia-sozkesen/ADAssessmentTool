namespace ADAssessment.Core
{
    /// <summary>
    /// SmbProtocolSecuritySettings verisi üzerinde çalışan kuralları diğer kategorilerden
    /// ayırt etmek için kullanılan işaretleyici (marker) arayüz. Aynı desen:
    /// bkz. ILdapProtocolComplianceRule, IGroupPolicyComplianceRule, IComputerComplianceRule.
    /// </summary>
    public interface ISmbProtocolComplianceRule : IComplianceRule
    {
    }
}
