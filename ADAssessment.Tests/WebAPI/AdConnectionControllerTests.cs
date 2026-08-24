using Microsoft.AspNetCore.Mvc;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.WebAPI.Controllers;
using ADAssessment.WebAPI.Models;
using Xunit;

namespace ADAssessment.Tests.WebAPI
{
    public class AdConnectionControllerTests
    {
        [Fact]
        public void GetStatus_NothingConfigured_ReturnsNotConfigured()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = new AdConnectionController(store);

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
            var controller = new AdConnectionController(store);
            var request = new AdConnectionRequest
            {
                LdapPath = "LDAPS://192.168.92.100:636/DC=lab,DC=local",
                Username = "svc-adassessment",
                Password = "super-secret",
                UseLdaps = true,
                AllowUnsecureFallback = true
            };

            var result = controller.SetConnection(request);

            Assert.IsType<OkObjectResult>(result);
            var current = store.GetCurrent();
            Assert.NotNull(current);
            Assert.Equal("LDAPS://192.168.92.100:636/DC=lab,DC=local", current!.LdapPath);
            Assert.Equal("svc-adassessment", current.Username);
            Assert.True(current.AllowUnsecureFallback);
        }

        [Fact]
        public void SetConnection_ResponseNeverContainsPassword()
        {
            // Parolanın yanlışlıkla response'a sızmadığını (serileştirilen tipte hiç
            // Password alanı olmadığını) doğrulayan regresyon testi.
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = new AdConnectionController(store);
            var request = new AdConnectionRequest { LdapPath = "LDAPS://192.168.92.100:636/DC=lab,DC=local", Password = "super-secret-value" };

            var result = controller.SetConnection(request);

            var okResult = Assert.IsType<OkObjectResult>(result);
            string json = System.Text.Json.JsonSerializer.Serialize(okResult.Value);
            Assert.DoesNotContain("super-secret-value", json);
        }

        [Fact]
        public void SetConnection_EmptyLdapPath_ReturnsBadRequest()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = new AdConnectionController(store);
            var request = new AdConnectionRequest { LdapPath = "" };

            var result = controller.SetConnection(request);

            Assert.IsType<BadRequestObjectResult>(result);
            Assert.Null(store.GetCurrent());
        }

        [Fact]
        public void GetStatus_AfterSet_NeverExposesPassword()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = new AdConnectionController(store);
            controller.SetConnection(new AdConnectionRequest { LdapPath = "LDAPS://192.168.92.100:636/DC=lab,DC=local", Password = "super-secret-value" });

            var result = controller.GetStatus();

            var okResult = Assert.IsType<OkObjectResult>(result);
            string json = System.Text.Json.JsonSerializer.Serialize(okResult.Value);
            Assert.DoesNotContain("super-secret-value", json);
        }

        [Fact]
        public void ClearConnection_RemovesStoredSettings()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = new AdConnectionController(store);
            controller.SetConnection(new AdConnectionRequest { LdapPath = "LDAPS://192.168.92.100:636/DC=lab,DC=local" });

            var result = controller.ClearConnection();

            Assert.IsType<OkObjectResult>(result);
            Assert.Null(store.GetCurrent());
        }
    }
}
