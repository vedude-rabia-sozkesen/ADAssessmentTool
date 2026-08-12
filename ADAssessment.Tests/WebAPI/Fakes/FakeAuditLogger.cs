using System.Collections.Generic;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Logging;

namespace ADAssessment.Tests.WebAPI.Fakes
{
    /// <summary>
    /// IAuditLogger'ın test projesindeki sahte implementasyonu - dosya sistemine
    /// dokunmadan çağrıldığını doğrulamak için son çağrının parametrelerini saklar.
    /// </summary>
    internal sealed class FakeAuditLogger : IAuditLogger
    {
        public bool WasCalled { get; private set; }
        public string? LastInitiator { get; private set; }
        public int LastScannedUserCount { get; private set; }

        public void LogAssessment(string initiator, int scannedUserCount, IEnumerable<RuleResult> results)
        {
            WasCalled = true;
            LastInitiator = initiator;
            LastScannedUserCount = scannedUserCount;
        }
    }
}
