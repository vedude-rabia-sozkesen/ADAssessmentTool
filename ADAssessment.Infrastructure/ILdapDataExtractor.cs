using System.Collections.Generic;
using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Ldap
{
    /// <summary>
    /// LdapDataExtractor'ın soyutlaması. AssessmentController gibi tüketicilerin
    /// System.DirectoryServices'e (ve dolayısıyla gerçek bir Active Directory'ye)
    /// doğrudan bağımlı olmadan test edilebilmesini sağlar (Dependency Inversion Principle).
    /// </summary>
    public interface ILdapDataExtractor
    {
        IReadOnlyList<AdUserAccount> GetActiveUsers();

        IReadOnlyList<AdComputerAccount> GetComputerAccounts();

        DcSyncRightsSettings GetDcSyncRights();
    }
}
