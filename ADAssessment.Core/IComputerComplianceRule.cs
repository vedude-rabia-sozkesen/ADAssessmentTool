namespace ADAssessment.Core
{
    /// <summary>
    /// AdComputerAccount verisi üzerinde çalışan kuralları, kullanıcı bazlı (AdUserAccount)
    /// ve GPO bazlı (GroupPolicySecuritySettings) kurallardan ayırt etmek için kullanılan
    /// işaretleyici (marker) arayüz. IComplianceRule'ün Execute(object) imzasını değiştirmeden,
    /// DI katmanının "bu kural hangi veriyle çalıştırılmalı" sorusunu cevaplamasını sağlar
    /// (bkz. IGroupPolicyComplianceRule - aynı desen).
    /// </summary>
    public interface IComputerComplianceRule : IComplianceRule
    {
    }
}
