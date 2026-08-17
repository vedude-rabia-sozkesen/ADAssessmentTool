namespace ADAssessment.Core
{
    /// <summary>
    /// GroupPolicySecuritySettings verisi üzerinde çalışan kuralları, kullanıcı bazlı
    /// (AdUserAccount) kurallardan ayırt etmek için kullanılan işaretleyici (marker)
    /// arayüz. IComplianceRule'ün Execute(object) imzasını değiştirmeden, DI
    /// katmanının "bu kural hangi veriyle çalıştırılmalı" sorusunu cevaplamasını sağlar.
    /// </summary>
    public interface IGroupPolicyComplianceRule : IComplianceRule
    {
    }
}
