using System;
using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.Tests.WebAPI.Fakes
{
    /// <summary>
    /// ILdapConnectionTester'ın test projesindeki sahte implementasyonu - gerçek bir AD
    /// bağlantısı gerektirmeden AdConnectionController'ın doğrulama-başarılı/başarısız/
    /// hata-fırlatan yollarını test etmeyi sağlar.
    /// </summary>
    internal sealed class FakeLdapConnectionTester : ILdapConnectionTester
    {
        private readonly bool _result;
        private readonly Exception? _exceptionToThrow;

        public static FakeLdapConnectionTester Returning(bool result) => new(result, null);

        public static FakeLdapConnectionTester Throwing(Exception exception) => new(false, exception);

        private FakeLdapConnectionTester(bool result, Exception? exceptionToThrow)
        {
            _result = result;
            _exceptionToThrow = exceptionToThrow;
        }

        public bool TestConnection(LdapConnectionOptions options)
        {
            if (_exceptionToThrow != null)
            {
                throw _exceptionToThrow;
            }

            return _result;
        }
    }
}
