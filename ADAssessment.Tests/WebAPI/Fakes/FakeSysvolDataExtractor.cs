using System;
using System.Collections.Generic;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Sysvol;

namespace ADAssessment.Tests.WebAPI.Fakes
{
    /// <summary>
    /// ISysvolDataExtractor'ın test projesindeki sahte implementasyonu. Gerçek bir
    /// SMB/SYSVOL erişimi gerektirmeden AssessmentController'ın GPO-tabanlı kuralları
    /// nasıl çalıştırdığını (ve SYSVOL erişimi başarısız olduğunda LDAP taramasının
    /// etkilenmediğini) test etmeyi sağlar.
    /// </summary>
    internal sealed class FakeSysvolDataExtractor : ISysvolDataExtractor
    {
        private readonly IReadOnlyList<GroupPolicySecuritySettings>? _policies;
        private readonly Exception? _exceptionToThrow;

        public static FakeSysvolDataExtractor Returning(IReadOnlyList<GroupPolicySecuritySettings> policies) => new(policies, null);

        public static FakeSysvolDataExtractor ThrowingOnAccess(Exception exception) => new(null, exception);

        private FakeSysvolDataExtractor(IReadOnlyList<GroupPolicySecuritySettings>? policies, Exception? exceptionToThrow)
        {
            _policies = policies;
            _exceptionToThrow = exceptionToThrow;
        }

        public IReadOnlyList<GroupPolicySecuritySettings> GetSecuritySettings()
        {
            if (_exceptionToThrow != null)
            {
                throw _exceptionToThrow;
            }

            return _policies ?? Array.Empty<GroupPolicySecuritySettings>();
        }
    }
}
