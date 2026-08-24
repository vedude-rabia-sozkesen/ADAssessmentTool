using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.Tests.WebAPI.Fakes;
using ADAssessment.WebAPI.Controllers;
using ADAssessment.WebAPI.Models;
using Xunit;

namespace ADAssessment.Tests.WebAPI
{
    public class AdConnectionControllerTests
    {
        private static AdConnectionController MakeController(InMemoryAdConnectionSettingsStore store, ILdapConnectionTester? tester = null)
        {
            // Varsayılan: doğrulama başarılı - mevcut testlerin çoğu "ayar geçerli, kaydedildi"
            // senaryosunu test ediyor, doğrulama başarısız/hata senaryolarını test eden
            // testler kendi FakeLdapConnectionTester'ını açıkça geçer.
            return new AdConnectionController(store, tester ?? FakeLdapConnectionTester.Returning(true), NullLogger<AdConnectionController>.Instance);
        }

        [Fact]
        public void GetStatus_NothingConfigured_ReturnsNotConfigured()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);

            var result = controller.GetStatus();

            var okResult = Assert.IsType<OkObjectResult>(result);
            var status = Assert.IsType<AdConnectionStatusResponse>(okResult.Value);
            Assert.False(status.Configured);
            Assert.Null(status.LdapPath);
        }

        [Fact]
        public void SetConnection_ValidRequest_StoresItAndStatusReflectsIt()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);
            var request = new AdConnectionRequest
            {
                LdapPath = "LDAPS://192.0.2.1:636/DC=contoso,DC=local",
                Username = "svc-adassessment",
                Password = "super-secret",
                UseLdaps = true,
                AllowUnsecureFallback = true
            };

            var result = controller.SetConnection(request);

            Assert.IsType<OkObjectResult>(result);
            var current = store.GetCurrent();
            Assert.NotNull(current);
            Assert.Equal("LDAPS://192.0.2.1:636/DC=contoso,DC=local", current!.LdapPath);
            Assert.Equal("svc-adassessment", current.Username);
            Assert.True(current.AllowUnsecureFallback);
        }

        [Fact]
        public void SetConnection_ResponseNeverContainsPassword()
        {
            // Parolanın yanlışlıkla response'a sızmadığını (serileştirilen tipte hiç
            // Password alanı olmadığını) doğrulayan regresyon testi.
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);
            var request = new AdConnectionRequest { LdapPath = "LDAPS://192.0.2.1:636/DC=contoso,DC=local", Password = "super-secret-value" };

            var result = controller.SetConnection(request);

            var okResult = Assert.IsType<OkObjectResult>(result);
            string json = System.Text.Json.JsonSerializer.Serialize(okResult.Value);
            Assert.DoesNotContain("super-secret-value", json);
        }

        [Fact]
        public void SetConnection_EmptyLdapPath_ReturnsBadRequest()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);
            var request = new AdConnectionRequest { LdapPath = "" };

            var result = controller.SetConnection(request);

            Assert.IsType<BadRequestObjectResult>(result);
            Assert.Null(store.GetCurrent());
        }

        [Fact]
        public void SetConnection_VerificationFails_ReturnsBadRequestAndDoesNotStore()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store, FakeLdapConnectionTester.Returning(false));
            var request = new AdConnectionRequest { LdapPath = "LDAPS://192.0.2.1:636/DC=contoso,DC=local", Username = "wrong-user", Password = "wrong-pass" };

            var result = controller.SetConnection(request);

            Assert.IsType<BadRequestObjectResult>(result);
            Assert.Null(store.GetCurrent());
        }

        [Fact]
        public void SetConnection_VerificationThrows_ReturnsBadRequestWithoutLeakingDetailsAndDoesNotStore()
        {
            const string sensitiveDetail = "System.DirectoryServices.DirectoryEntry.Bind failed against DC=internal,DC=corp,DC=example at 10.0.0.5";
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store, FakeLdapConnectionTester.Throwing(new System.InvalidOperationException(sensitiveDetail)));
            var request = new AdConnectionRequest { LdapPath = "LDAPS://192.0.2.1:636/DC=contoso,DC=local" };

            var result = controller.SetConnection(request);

            var badRequest = Assert.IsType<BadRequestObjectResult>(result);
            Assert.Null(store.GetCurrent());
            string json = System.Text.Json.JsonSerializer.Serialize(badRequest.Value);
            Assert.DoesNotContain(sensitiveDetail, json);
        }

        [Fact]
        public void GetStatus_AfterSet_NeverExposesPassword()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);
            controller.SetConnection(new AdConnectionRequest { LdapPath = "LDAPS://192.0.2.1:636/DC=contoso,DC=local", Password = "super-secret-value" });

            var result = controller.GetStatus();

            var okResult = Assert.IsType<OkObjectResult>(result);
            string json = System.Text.Json.JsonSerializer.Serialize(okResult.Value);
            Assert.DoesNotContain("super-secret-value", json);
        }

        [Fact]
        public void ClearConnection_RemovesStoredSettings()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);
            controller.SetConnection(new AdConnectionRequest { LdapPath = "LDAPS://192.0.2.1:636/DC=contoso,DC=local" });

            var result = controller.ClearConnection();

            Assert.IsType<OkObjectResult>(result);
            Assert.Null(store.GetCurrent());
        }
    }
}
