using System;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Smb;

namespace ADAssessment.Tests.WebAPI.Fakes
{
    /// <summary>
    /// ISmbProtocolSecurityChecker'ın test projesindeki sahte implementasyonu. Gerçek bir
    /// ağ bağlantısı denemesi gerektirmeden AssessmentController'ın SMB protokol
    /// güvenliği kurallarını nasıl çalıştırdığını test etmeyi sağlar.
    /// </summary>
    internal sealed class FakeSmbProtocolSecurityChecker : ISmbProtocolSecurityChecker
    {
        private readonly SmbProtocolSecuritySettings? _settings;
        private readonly Exception? _exceptionToThrow;

        public static FakeSmbProtocolSecurityChecker Returning(SmbProtocolSecuritySettings settings) => new(settings, null);

        public static FakeSmbProtocolSecurityChecker ThrowingOnAccess(Exception exception) => new(null, exception);

        private FakeSmbProtocolSecurityChecker(SmbProtocolSecuritySettings? settings, Exception? exceptionToThrow)
        {
            _settings = settings;
            _exceptionToThrow = exceptionToThrow;
        }

        public SmbProtocolSecuritySettings CheckAnonymousAccess()
        {
            if (_exceptionToThrow != null)
            {
                throw _exceptionToThrow;
            }

            return _settings ?? new SmbProtocolSecuritySettings();
        }
    }
}
