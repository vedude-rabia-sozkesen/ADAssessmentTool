namespace ADAssessment.Core
{
    /// <summary>
    /// LdapProtocolSecuritySettings verisi üzerinde çalışan kuralları diğer kategorilerden
    /// (kullanıcı, GPO, bilgisayar) ayırt etmek için kullanılan işaretleyici (marker) arayüz.
    /// Aynı desen: bkz. IGroupPolicyComplianceRule, IComputerComplianceRule.
    /// </summary>
    public interface ILdapProtocolComplianceRule : IComplianceRule
    {
    }
}
