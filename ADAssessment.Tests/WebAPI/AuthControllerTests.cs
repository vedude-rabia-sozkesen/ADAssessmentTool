using Microsoft.AspNetCore.Mvc;
using ADAssessment.Tests.WebAPI.Fakes;
using ADAssessment.WebAPI.Controllers;

namespace ADAssessment.Tests.WebAPI
{
    public class AuthControllerTests
    {
        [Fact]
        public void Login_WithCorrectCredentials_ReturnsOkWithToken()
        {
            var fakeResolver = new FakeSecretResolver(username: "opsuser", plainPassword: "CorrectPass!1");
            var controller = new AuthController(fakeResolver);

            var result = controller.Login(new LoginModel { Username = "opsuser", Password = "CorrectPass!1" });

            var okResult = Assert.IsType<OkObjectResult>(result);
            string? token = okResult.Value!.GetType().GetProperty("Token")!.GetValue(okResult.Value) as string;
            Assert.False(string.IsNullOrWhiteSpace(token));
        }

        [Fact]
        public void Login_WithWrongPassword_ReturnsUnauthorized()
        {
            var fakeResolver = new FakeSecretResolver(username: "opsuser", plainPassword: "CorrectPass!1");
            var controller = new AuthController(fakeResolver);

            var result = controller.Login(new LoginModel { Username = "opsuser", Password = "WrongPass!1" });

            Assert.IsType<UnauthorizedObjectResult>(result);
        }

        [Fact]
        public void Login_WithUnknownUsername_ReturnsUnauthorized()
        {
            var fakeResolver = new FakeSecretResolver(username: "opsuser", plainPassword: "CorrectPass!1");
            var controller = new AuthController(fakeResolver);

            var result = controller.Login(new LoginModel { Username = "someoneelse", Password = "CorrectPass!1" });

            Assert.IsType<UnauthorizedObjectResult>(result);
        }
    }
}
