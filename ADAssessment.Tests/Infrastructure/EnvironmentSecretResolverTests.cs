using System;
using ADAssessment.Infrastructure.Configuration;

namespace ADAssessment.Tests.Infrastructure
{
    /// <summary>
    /// AD_ASSESSMENT_* ve ASPNETCORE_ENVIRONMENT ortam değişkenleri process-global
    /// olduğundan, bu sınıftaki her test kendi kullandığı değişkenleri try/finally ile
    /// orijinal (test öncesi) değerine geri yükler. xUnit varsayılan olarak aynı sınıf
    /// içindeki testleri sıralı çalıştırdığından (paralel değil) bu, testler arası
    /// veri sızıntısını engellemek için yeterlidir.
    /// </summary>
    public class EnvironmentSecretResolverTests
    {
        private const string JwtSecretVar = "AD_ASSESSMENT_JWT_SECRET";
        private const string ApiUsernameVar = "AD_ASSESSMENT_API_USERNAME";
        private const string ApiPasswordHashVar = "AD_ASSESSMENT_API_PASSWORD_HASH";
        private const string AllowFallbackVar = "AD_ASSESSMENT_ALLOW_INSECURE_FALLBACK";
        private const string AspNetEnvVar = "ASPNETCORE_ENVIRONMENT";

        private static void WithEnv(Action action, params (string Name, string? Value)[] variables)
        {
            var originalValues = new (string Name, string? Value)[variables.Length];
            for (int i = 0; i < variables.Length; i++)
            {
                originalValues[i] = (variables[i].Name, Environment.GetEnvironmentVariable(variables[i].Name));
                Environment.SetEnvironmentVariable(variables[i].Name, variables[i].Value);
            }

            try
            {
                action();
            }
            finally
            {
                foreach (var (name, value) in originalValues)
                {
                    Environment.SetEnvironmentVariable(name, value);
                }
            }
        }

        [Fact]
        public void ResolveJwtSigningOptions_ValidEnvSecret_IsReturnedAsIs()
        {
            const string validKey = "ThisIsA32PlusCharacterLongTestSecret!!";

            WithEnv(() =>
            {
                var resolver = new EnvironmentSecretResolver();

                var options = resolver.ResolveJwtSigningOptions();

                Assert.Equal(validKey, options.Key);
            }, (JwtSecretVar, validKey), (AspNetEnvVar, "Production"));
        }

        [Fact]
        public void ResolveJwtSigningOptions_MissingInDevelopment_GeneratesAndCachesKey()
        {
            WithEnv(() =>
            {
                var resolver = new EnvironmentSecretResolver();

                var first = resolver.ResolveJwtSigningOptions();
                var second = resolver.ResolveJwtSigningOptions();

                Assert.False(string.IsNullOrWhiteSpace(first.Key));
                Assert.Equal(first.Key, second.Key); // aynı instance -> aynı (cache'lenmiş) değer
            }, (JwtSecretVar, null), (AspNetEnvVar, "Development"));
        }

        [Fact]
        public void ResolveJwtSigningOptions_MissingInDevelopment_DifferentInstancesGenerateDifferentKeys()
        {
            WithEnv(() =>
            {
                var first = new EnvironmentSecretResolver().ResolveJwtSigningOptions();
                var second = new EnvironmentSecretResolver().ResolveJwtSigningOptions();

                Assert.NotEqual(first.Key, second.Key);
            }, (JwtSecretVar, null), (AspNetEnvVar, "Development"));
        }

        [Fact]
        public void ResolveJwtSigningOptions_MissingOutsideDevelopment_ThrowsFailClosed()
        {
            WithEnv(() =>
            {
                var resolver = new EnvironmentSecretResolver();

                Assert.Throws<InvalidOperationException>(() => resolver.ResolveJwtSigningOptions());
            }, (JwtSecretVar, null), (AspNetEnvVar, "Production"));
        }

        [Fact]
        public void ResolveJwtSigningOptions_TooShortKey_IsTreatedAsMissing()
        {
            WithEnv(() =>
            {
                var resolver = new EnvironmentSecretResolver();

                Assert.Throws<InvalidOperationException>(() => resolver.ResolveJwtSigningOptions());
            }, (JwtSecretVar, "tooshort"), (AspNetEnvVar, "Production"));
        }

        [Fact]
        public void ResolveApiCredentials_ValidEnvValues_AreReturnedAsIs()
        {
            WithEnv(() =>
            {
                var resolver = new EnvironmentSecretResolver();

                var credentials = resolver.ResolveApiCredentials();

                Assert.Equal("opsuser", credentials.Username);
                Assert.Equal("100000.salt.hash", credentials.PasswordHash);
            }, (ApiUsernameVar, "opsuser"), (ApiPasswordHashVar, "100000.salt.hash"), (AspNetEnvVar, "Production"));
        }

        [Fact]
        public void ResolveApiCredentials_MissingInDevelopment_GeneratesAndCachesCredentials()
        {
            WithEnv(() =>
            {
                var resolver = new EnvironmentSecretResolver();

                var first = resolver.ResolveApiCredentials();
                var second = resolver.ResolveApiCredentials();

                Assert.Equal(first.Username, second.Username);
                Assert.Equal(first.PasswordHash, second.PasswordHash);
            }, (ApiUsernameVar, null), (ApiPasswordHashVar, null), (AspNetEnvVar, "Development"));
        }

        [Fact]
        public void ResolveApiCredentials_MissingOutsideDevelopment_ThrowsFailClosed()
        {
            WithEnv(() =>
            {
                var resolver = new EnvironmentSecretResolver();

                Assert.Throws<InvalidOperationException>(() => resolver.ResolveApiCredentials());
            }, (ApiUsernameVar, null), (ApiPasswordHashVar, null), (AspNetEnvVar, "Production"));
        }

        [Fact]
        public void ResolveLdapOptions_AllowUnsecureFallback_DefaultsToFalse()
        {
            WithEnv(() =>
            {
                var resolver = new EnvironmentSecretResolver();

                var options = resolver.ResolveLdapOptions();

                Assert.False(options.AllowUnsecureFallback);
            }, (AllowFallbackVar, null));
        }

        [Fact]
        public void ResolveLdapOptions_AllowUnsecureFallback_TrueWhenExplicitlySet()
        {
            WithEnv(() =>
            {
                var resolver = new EnvironmentSecretResolver();

                var options = resolver.ResolveLdapOptions();

                Assert.True(options.AllowUnsecureFallback);
            }, (AllowFallbackVar, "true"));
        }

        [Fact]
        public void ResolveLdapOptions_AllowUnsecureFallback_FalseWhenGarbageValue()
        {
            WithEnv(() =>
            {
                var resolver = new EnvironmentSecretResolver();

                var options = resolver.ResolveLdapOptions();

                Assert.False(options.AllowUnsecureFallback);
            }, (AllowFallbackVar, "not-a-bool"));
        }
    }
}
