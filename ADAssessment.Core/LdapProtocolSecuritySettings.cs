namespace ADAssessment.Core
{
    /// <summary>
    /// Domain Controller'ın LDAP protokolü seviyesindeki güvenlik davranışını temsil eder.
    /// GroupPolicySecuritySettings'ten farklı olarak bu veri bir dosyadan (GptTmpl.inf)
    /// veya LDAP özniteliğinden okunmaz - DC'ye gerçek bir protokol seviyesi bağlantı
    /// denemesi yapılarak (bkz. ILdapProtocolSecurityChecker) gözlemlenir.
    /// </summary>
    public sealed class LdapProtocolSecuritySettings
    {
        public string DomainController { get; init; } = string.Empty;

        /// DC, imzasız/şifresiz bir kanal üzerinden gelen basit (simple) bind isteklerini
        /// reddediyor mu? Reddetmiyorsa, kimlik bilgileri ağda bütünlük korumasız
        /// (imzasız) şekilde dolaşabilir - bu, LDAP relay saldırılarına (bir saldırganın
        /// yakaladığı bir kimlik doğrulama denemesini başka bir hedefe ilettiği saldırı
        /// türü) karşı savunmasızlık anlamına gelir.
        public bool IsSigningEnforced { get; init; }
    }
}
