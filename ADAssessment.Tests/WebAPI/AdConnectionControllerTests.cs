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

        private static AdConnectionRequest ValidRequest() => new()
        {
            DcHostname = "DC01.contoso.local",
            IpAddress = "192.0.2.1",
            Username = "svc-adassessment",
            Password = "super-secret",
            UseLdaps = true,
            AllowUnsecureFallback = true
        };

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
        public void SetConnection_ValidRequest_BuildsLdapPathFromHostnameAndIp()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);

            var result = controller.SetConnection(ValidRequest());

            Assert.IsType<OkObjectResult>(result);
            var current = store.GetCurrent();
            Assert.NotNull(current);
            // "DC01.contoso.local" -> ilk etiket ("DC01") atılır, kalan ("contoso.local")
            // "DC=contoso,DC=local" olur; IP adresiyle birlikte tam path inşa edilir.
            Assert.Equal("LDAP://192.0.2.1/DC=contoso,DC=local", current!.LdapPath);
            Assert.Equal("svc-adassessment", current.Username);
            Assert.True(current.AllowUnsecureFallback);
        }

        [Fact]
        public void SetConnection_ChildDomainHostname_BuildsMultiLabelDn()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);
            var request = ValidRequest();
            request.DcHostname = "DC02.child.contoso.local";

            controller.SetConnection(request);

            Assert.Equal("LDAP://192.0.2.1/DC=child,DC=contoso,DC=local", store.GetCurrent()!.LdapPath);
        }

        [Fact]
        public void SetConnection_ResponseNeverContainsPassword()
        {
            // Parolanın yanlışlıkla response'a sızmadığını (serileştirilen tipte hiç
            // Password alanı olmadığını) doğrulayan regresyon testi.
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);

            var result = controller.SetConnection(ValidRequest());

            var okResult = Assert.IsType<OkObjectResult>(result);
            string json = System.Text.Json.JsonSerializer.Serialize(okResult.Value);
            Assert.DoesNotContain("super-secret", json);
        }

        [Fact]
        public void SetConnection_EmptyDcHostname_ReturnsBadRequest()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);
            var request = ValidRequest();
            request.DcHostname = "";

            var result = controller.SetConnection(request);

            Assert.IsType<BadRequestObjectResult>(result);
            Assert.Null(store.GetCurrent());
        }

        [Fact]
        public void SetConnection_EmptyIpAddress_ReturnsBadRequest()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);
            var request = ValidRequest();
            request.IpAddress = "";

            var result = controller.SetConnection(request);

            Assert.IsType<BadRequestObjectResult>(result);
            Assert.Null(store.GetCurrent());
        }

        [Fact]
        public void SetConnection_DcHostnameNotFullyQualified_ReturnsBadRequest()
        {
            // Nokta içermeyen bir isimden ("DC01") domain adı güvenilir şekilde
            // çıkarılamaz - kullanıcıya net bir "FQDN gerekli" hatası dönmeli.
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);
            var request = ValidRequest();
            request.DcHostname = "DC01";

            var result = controller.SetConnection(request);

            Assert.IsType<BadRequestObjectResult>(result);
            Assert.Null(store.GetCurrent());
        }

        [Fact]
        public void SetConnection_VerificationFails_ReturnsBadRequestAndDoesNotStore()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store, FakeLdapConnectionTester.Returning(false));

            var result = controller.SetConnection(ValidRequest());

            Assert.IsType<BadRequestObjectResult>(result);
            Assert.Null(store.GetCurrent());
        }

        [Fact]
        public void SetConnection_VerificationThrows_ReturnsBadRequestWithoutLeakingDetailsAndDoesNotStore()
        {
            const string sensitiveDetail = "System.DirectoryServices.DirectoryEntry.Bind failed against DC=internal,DC=corp,DC=example at 10.0.0.5";
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store, FakeLdapConnectionTester.Throwing(new System.InvalidOperationException(sensitiveDetail)));

            var result = controller.SetConnection(ValidRequest());

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
            controller.SetConnection(ValidRequest());

            var result = controller.GetStatus();

            var okResult = Assert.IsType<OkObjectResult>(result);
            string json = System.Text.Json.JsonSerializer.Serialize(okResult.Value);
            Assert.DoesNotContain("super-secret", json);
        }

        [Fact]
        public void ClearConnection_RemovesStoredSettings()
        {
            var store = new InMemoryAdConnectionSettingsStore();
            var controller = MakeController(store);
            controller.SetConnection(ValidRequest());

            var result = controller.ClearConnection();

            Assert.IsType<OkObjectResult>(result);
            Assert.Null(store.GetCurrent());
        }
    }
}
