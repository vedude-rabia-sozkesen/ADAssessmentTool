using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Smb
{
    /// <summary>
    /// SmbProtocolSecurityChecker'ın soyutlaması - AssessmentController gibi tüketicilerin
    /// gerçek bir ağ bağlantısına doğrudan bağımlı olmadan test edilebilmesini sağlar.
    /// </summary>
    public interface ISmbProtocolSecurityChecker
    {
        SmbProtocolSecuritySettings CheckAnonymousAccess();
    }
}
