namespace ADAssessment.Core
{
    /// <summary>
    /// Domain kök nesnesinin msDS-Behavior-Version özniteliğinden okunan, domain
    /// fonksiyonel seviyesini (Domain Functional Level - DFL) temsil eden veri modeli.
    /// DFL, domain'deki TÜM Domain Controller'ların en az hangi Windows Server sürümünü
    /// çalıştırdığını (ve dolayısıyla hangi güvenlik özelliklerinin - örn. AES Kerberos
    /// desteği, Authentication Policy Silos - kullanılabilir olduğunu) belirler.
    /// </summary>
    public sealed class DomainFunctionalLevelSettings
    {
        public string DomainDistinguishedName { get; init; } = string.Empty;

        /// Ham msDS-Behavior-Version değeri: 0=2000, 1=2003 Interim, 2=2003, 3=2008,
        /// 4=2008 R2, 5=2012, 6=2012 R2, 7=2016.
        public int FunctionalLevel { get; init; } = -1;
    }
}
