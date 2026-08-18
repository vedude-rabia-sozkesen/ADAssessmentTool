using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Ldap
{
    /// <summary>
    /// LdapProtocolSecurityChecker'ın soyutlaması - AssessmentController gibi tüketicilerin
    /// gerçek bir ağ bağlantısına doğrudan bağımlı olmadan test edilebilmesini sağlar.
    /// </summary>
    public interface ILdapProtocolSecurityChecker
    {
        LdapProtocolSecuritySettings CheckProtocolSecurity();
    }
}
