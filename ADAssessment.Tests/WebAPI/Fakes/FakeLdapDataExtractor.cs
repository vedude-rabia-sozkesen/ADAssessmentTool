using System;
using System.Collections.Generic;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.Tests.WebAPI.Fakes
{
    /// <summary>
    /// ILdapDataExtractor'ın test projesindeki sahte implementasyonu. Gerçek bir
    /// System.DirectoryServices.DirectoryEntry/AD bağlantısı gerektirmeden
    /// AssessmentController'ın başarı ve hata yollarını test etmeyi sağlar.
    /// </summary>
    internal sealed class FakeLdapDataExtractor : ILdapDataExtractor
    {
        private readonly IReadOnlyList<AdUserAccount>? _users;
        private readonly Exception? _exceptionToThrow;

        public static FakeLdapDataExtractor Returning(IReadOnlyList<AdUserAccount> users) => new(users, null);

        public static FakeLdapDataExtractor ThrowingOnConnect(Exception exception) => new(null, exception);

        private FakeLdapDataExtractor(IReadOnlyList<AdUserAccount>? users, Exception? exceptionToThrow)
        {
            _users = users;
            _exceptionToThrow = exceptionToThrow;
        }

        public IReadOnlyList<AdUserAccount> GetActiveUsers()
        {
            if (_exceptionToThrow != null)
            {
                throw _exceptionToThrow;
            }

            return _users ?? Array.Empty<AdUserAccount>();
        }
    }
}
