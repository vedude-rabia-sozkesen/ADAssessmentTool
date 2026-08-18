using System;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.Tests.WebAPI.Fakes
{
    /// <summary>
    /// ILdapProtocolSecurityChecker'ın test projesindeki sahte implementasyonu. Gerçek bir
    /// ağ bağlantısı denemesi gerektirmeden AssessmentController'ın LDAP protokol
    /// güvenliği kurallarını nasıl çalıştırdığını test etmeyi sağlar.
    /// </summary>
    internal sealed class FakeLdapProtocolSecurityChecker : ILdapProtocolSecurityChecker
    {
        private readonly LdapProtocolSecuritySettings? _settings;
        private readonly Exception? _exceptionToThrow;

        public static FakeLdapProtocolSecurityChecker Returning(LdapProtocolSecuritySettings settings) => new(settings, null);

        public static FakeLdapProtocolSecurityChecker ThrowingOnAccess(Exception exception) => new(null, exception);

        private FakeLdapProtocolSecurityChecker(LdapProtocolSecuritySettings? settings, Exception? exceptionToThrow)
        {
            _settings = settings;
            _exceptionToThrow = exceptionToThrow;
        }

        public LdapProtocolSecuritySettings CheckSigningEnforcement()
        {
            if (_exceptionToThrow != null)
            {
                throw _exceptionToThrow;
            }

            return _settings ?? new LdapProtocolSecuritySettings();
        }
    }
}
