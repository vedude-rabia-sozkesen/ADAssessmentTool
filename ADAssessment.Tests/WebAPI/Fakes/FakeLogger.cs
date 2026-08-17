using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace ADAssessment.Tests.WebAPI.Fakes
{
    /// <summary>
    /// ILogger&lt;T&gt;'nin test projesindeki sahte implementasyonu - loglanan mesajları
    /// (formatlanmış haliyle) bir listede tutar, böylece "şu olayda loglama yapıldı mı"
    /// regresyon testleri harici bir mocking kütüphanesi olmadan yazılabilir.
    /// </summary>
    internal sealed class FakeLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
        }
    }
}
