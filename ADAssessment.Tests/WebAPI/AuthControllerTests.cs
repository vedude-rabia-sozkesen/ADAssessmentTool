using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using ADAssessment.Tests.WebAPI.Fakes;
using ADAssessment.WebAPI.Controllers;

namespace ADAssessment.Tests.WebAPI
{
    public class AuthControllerTests
    {
        private static AuthController MakeController(FakeSecretResolver fakeResolver, Microsoft.Extensions.Logging.ILogger<AuthController>? logger = null)
        {
            var controller = new AuthController(fakeResolver, logger ?? NullLogger<AuthController>.Instance);
            // Başarısız girişte HttpContext.Connection.RemoteIpAddress loglandığından,
            // gerçek bir HTTP isteği olmadan çalıştırıldığında NullReferenceException
            // atmaması için bir HttpContext set edilir.
            controller.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
            return controller;
        }

        [Fact]
        public void Login_WithCorrectCredentials_ReturnsOkWithToken()
        {
            var fakeResolver = new FakeSecretResolver(username: "opsuser", plainPassword: "CorrectPass!1");
            var controller = MakeController(fakeResolver);

            var result = controller.Login(new LoginModel { Username = "opsuser", Password = "CorrectPass!1" });

            var okResult = Assert.IsType<OkObjectResult>(result);
            string? token = okResult.Value!.GetType().GetProperty("Token")!.GetValue(okResult.Value) as string;
            Assert.False(string.IsNullOrWhiteSpace(token));
        }

        [Fact]
        public void Login_WithWrongPassword_ReturnsUnauthorized()
        {
            var fakeResolver = new FakeSecretResolver(username: "opsuser", plainPassword: "CorrectPass!1");
            var controller = MakeController(fakeResolver);

            var result = controller.Login(new LoginModel { Username = "opsuser", Password = "WrongPass!1" });

            Assert.IsType<UnauthorizedObjectResult>(result);
        }

        [Fact]
        public void Login_WithUnknownUsername_ReturnsUnauthorized()
        {
            var fakeResolver = new FakeSecretResolver(username: "opsuser", plainPassword: "CorrectPass!1");
            var controller = MakeController(fakeResolver);

            var result = controller.Login(new LoginModel { Username = "someoneelse", Password = "CorrectPass!1" });

            Assert.IsType<UnauthorizedObjectResult>(result);
        }

        [Fact]
        public void Login_WithWrongPassword_LogsFailedAttemptWithoutLoggingPassword()
        {
            // OWASP A09 (Security Logging & Monitoring Failures) düzeltmesinin regresyon
            // testi: başarısız denemenin kullanıcı adıyla loglandığını, ama denenen
            // parolanın hiçbir log satırına sızmadığını doğrular.
            var fakeResolver = new FakeSecretResolver(username: "opsuser", plainPassword: "CorrectPass!1");
            var fakeLogger = new FakeLogger<AuthController>();
            var controller = MakeController(fakeResolver, fakeLogger);

            controller.Login(new LoginModel { Username = "opsuser", Password = "TotallyWrongSecret!9" });

            Assert.Contains(fakeLogger.Messages, m => m.Contains("opsuser"));
            Assert.DoesNotContain(fakeLogger.Messages, m => m.Contains("TotallyWrongSecret!9"));
        }
    }
}
