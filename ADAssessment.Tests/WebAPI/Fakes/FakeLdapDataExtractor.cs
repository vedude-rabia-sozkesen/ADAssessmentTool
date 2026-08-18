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
        private readonly IReadOnlyList<AdComputerAccount>? _computers;
        private readonly Exception? _exceptionToThrow;
        private readonly Exception? _computerExceptionToThrow;

        public static FakeLdapDataExtractor Returning(IReadOnlyList<AdUserAccount> users, IReadOnlyList<AdComputerAccount>? computers = null) => new(users, computers, null, null);

        public static FakeLdapDataExtractor ThrowingOnConnect(Exception exception) => new(null, null, exception, null);

        /// <summary>
        /// GetActiveUsers başarılı dönerken GetComputerAccounts'ın hata fırlattığı durumu
        /// simüle eder - AssessmentController'daki bilgisayar sorgusu izolasyonunu
        /// (try/catch) test etmek için gerekli.
        /// </summary>
        public static FakeLdapDataExtractor ThrowingOnComputerQuery(IReadOnlyList<AdUserAccount> users, Exception exception) => new(users, null, null, exception);

        private FakeLdapDataExtractor(IReadOnlyList<AdUserAccount>? users, IReadOnlyList<AdComputerAccount>? computers, Exception? exceptionToThrow, Exception? computerExceptionToThrow)
        {
            _users = users;
            _computers = computers;
            _exceptionToThrow = exceptionToThrow;
            _computerExceptionToThrow = computerExceptionToThrow;
        }

        public IReadOnlyList<AdUserAccount> GetActiveUsers()
        {
            if (_exceptionToThrow != null)
            {
                throw _exceptionToThrow;
            }

            return _users ?? Array.Empty<AdUserAccount>();
        }

        public IReadOnlyList<AdComputerAccount> GetComputerAccounts()
        {
            if (_exceptionToThrow != null)
            {
                throw _exceptionToThrow;
            }

            if (_computerExceptionToThrow != null)
            {
                throw _computerExceptionToThrow;
            }

            return _computers ?? Array.Empty<AdComputerAccount>();
        }
    }
}
