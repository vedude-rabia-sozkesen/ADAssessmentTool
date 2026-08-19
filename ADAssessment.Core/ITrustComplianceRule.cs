namespace ADAssessment.Core
{
    /// <summary>
    /// IEnumerable&lt;AdTrustRelationship&gt; verisi üzerinde çalışan kuralları diğer
    /// kategorilerden ayırt etmek için kullanılan işaretleyici (marker) arayüz. Aynı desen:
    /// bkz. IComputerComplianceRule, IForestComplianceRule.
    /// </summary>
    public interface ITrustComplianceRule : IComplianceRule
    {
    }
}
