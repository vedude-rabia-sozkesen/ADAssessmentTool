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
        private readonly DcSyncRightsSettings? _dcSyncRights;
        private readonly DomainFunctionalLevelSettings? _domainFunctionalLevel;
        private readonly ForestOptionalFeatureSettings? _forestFeatures;
        private readonly Exception? _exceptionToThrow;
        private readonly Exception? _computerExceptionToThrow;
        private readonly Exception? _dcSyncExceptionToThrow;
        private readonly Exception? _functionalLevelExceptionToThrow;
        private readonly Exception? _forestExceptionToThrow;

        public static FakeLdapDataExtractor Returning(IReadOnlyList<AdUserAccount> users, IReadOnlyList<AdComputerAccount>? computers = null, DcSyncRightsSettings? dcSyncRights = null, DomainFunctionalLevelSettings? domainFunctionalLevel = null, ForestOptionalFeatureSettings? forestFeatures = null) => new(users, computers, dcSyncRights, domainFunctionalLevel, forestFeatures, null, null, null, null, null);

        public static FakeLdapDataExtractor ThrowingOnConnect(Exception exception) => new(null, null, null, null, null, exception, null, null, null, null);

        /// <summary>
        /// GetActiveUsers başarılı dönerken GetComputerAccounts'ın hata fırlattığı durumu
        /// simüle eder - AssessmentController'daki bilgisayar sorgusu izolasyonunu
        /// (try/catch) test etmek için gerekli.
        /// </summary>
        public static FakeLdapDataExtractor ThrowingOnComputerQuery(IReadOnlyList<AdUserAccount> users, Exception exception) => new(users, null, null, null, null, null, exception, null, null, null);

        /// <summary>
        /// GetActiveUsers başarılı dönerken GetDcSyncRights'ın hata fırlattığı durumu
        /// simüle eder - AssessmentController'daki DCSync sorgusu izolasyonunu test etmek için.
        /// </summary>
        public static FakeLdapDataExtractor ThrowingOnDcSyncQuery(IReadOnlyList<AdUserAccount> users, Exception exception) => new(users, null, null, null, null, null, null, exception, null, null);

        /// <summary>
        /// GetActiveUsers başarılı dönerken GetDomainFunctionalLevel'ın hata fırlattığı durumu
        /// simüle eder - AssessmentController'daki fonksiyonel seviye sorgusu izolasyonunu
        /// test etmek için.
        /// </summary>
        public static FakeLdapDataExtractor ThrowingOnFunctionalLevelQuery(IReadOnlyList<AdUserAccount> users, Exception exception) => new(users, null, null, null, null, null, null, null, exception, null);

        /// <summary>
        /// GetActiveUsers başarılı dönerken GetForestOptionalFeatures'ın hata fırlattığı
        /// durumu simüle eder - AssessmentController'daki forest özellik sorgusu
        /// izolasyonunu test etmek için.
        /// </summary>
        public static FakeLdapDataExtractor ThrowingOnForestFeatureQuery(IReadOnlyList<AdUserAccount> users, Exception exception) => new(users, null, null, null, null, null, null, null, null, exception);

        private FakeLdapDataExtractor(IReadOnlyList<AdUserAccount>? users, IReadOnlyList<AdComputerAccount>? computers, DcSyncRightsSettings? dcSyncRights, DomainFunctionalLevelSettings? domainFunctionalLevel, ForestOptionalFeatureSettings? forestFeatures, Exception? exceptionToThrow, Exception? computerExceptionToThrow, Exception? dcSyncExceptionToThrow, Exception? functionalLevelExceptionToThrow, Exception? forestExceptionToThrow)
        {
            _users = users;
            _computers = computers;
            _dcSyncRights = dcSyncRights;
            _domainFunctionalLevel = domainFunctionalLevel;
            _forestFeatures = forestFeatures;
            _exceptionToThrow = exceptionToThrow;
            _computerExceptionToThrow = computerExceptionToThrow;
            _dcSyncExceptionToThrow = dcSyncExceptionToThrow;
            _functionalLevelExceptionToThrow = functionalLevelExceptionToThrow;
            _forestExceptionToThrow = forestExceptionToThrow;
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

        public DcSyncRightsSettings GetDcSyncRights()
        {
            if (_exceptionToThrow != null)
            {
                throw _exceptionToThrow;
            }

            if (_dcSyncExceptionToThrow != null)
            {
                throw _dcSyncExceptionToThrow;
            }

            return _dcSyncRights ?? new DcSyncRightsSettings();
        }

        public DomainFunctionalLevelSettings GetDomainFunctionalLevel()
        {
            if (_exceptionToThrow != null)
            {
                throw _exceptionToThrow;
            }

            if (_functionalLevelExceptionToThrow != null)
            {
                throw _functionalLevelExceptionToThrow;
            }

            return _domainFunctionalLevel ?? new DomainFunctionalLevelSettings();
        }

        public ForestOptionalFeatureSettings GetForestOptionalFeatures()
        {
            if (_exceptionToThrow != null)
            {
                throw _exceptionToThrow;
            }

            if (_forestExceptionToThrow != null)
            {
                throw _forestExceptionToThrow;
            }

            return _forestFeatures ?? new ForestOptionalFeatureSettings();
        }
    }
}
