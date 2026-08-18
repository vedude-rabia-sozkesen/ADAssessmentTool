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

        /// DC, LDAPS (TLS şifreli) bağlantılarda Channel Binding Token (CBT - bir kimlik
        /// doğrulama işlemini üzerinde gerçekleştiği spesifik TLS oturumuna bağlayan
        /// güvenlik mekanizması) olmadan gelen bind isteklerini reddediyor mu?
        /// Reddetmiyorsa, TLS şifreli olsa bile yakalanmış bir kimlik doğrulama işlemi
        /// başka bir TLS oturumuna aktarılıp tekrar oynatılabilir (relay saldırısı,
        /// ADV190023). LDAP signing'den farklı bir zafiyet yüzeyidir - biri şifresiz
        /// kanalı, diğeri şifreli kanaldaki oturum bağlama eksikliğini hedefler.
        public bool IsChannelBindingEnforced { get; init; }
    }
}
