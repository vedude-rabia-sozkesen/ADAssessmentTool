using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using ADAssessment.Infrastructure.Configuration;

namespace ADAssessment.WebAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        public const string TokenIssuer = "ADAssessmentTool";
        public const string TokenAudience = "ADAssessmentTool";

        private readonly ISecretResolver _secretResolver;
        private readonly ILogger<AuthController> _logger;

        public AuthController(ISecretResolver secretResolver, ILogger<AuthController> logger)
        {
            _secretResolver = secretResolver;
            _logger = logger;
        }

        [HttpPost("login")]
        [EnableRateLimiting("login")]
        public IActionResult Login([FromBody] LoginModel model)
        {
            ApiCredentialOptions credentials = _secretResolver.ResolveApiCredentials();

            bool usernameMatches = string.Equals(model.Username, credentials.Username, StringComparison.Ordinal);
            bool passwordMatches = PasswordHasher.Verify(model.Password, credentials.PasswordHash);

            if (!usernameMatches || !passwordMatches)
            {
                // OWASP A09 (Security Logging & Monitoring Failures): başarısız giriş
                // denemeleri, brute-force tespiti/alarm üretebilmek için loglanır.
                // Parola ASLA loglanmaz - sadece denenen kullanıcı adı ve istemci IP'si.
                _logger.LogWarning(
                    "Başarısız giriş denemesi. Kullanıcı adı: {AttemptedUsername}, IP: {RemoteIp}",
                    model.Username,
                    HttpContext.Connection.RemoteIpAddress);
                return Unauthorized(new { Message = "Geçersiz kullanıcı adı veya şifre." });
            }

            JwtSigningOptions signingOptions = _secretResolver.ResolveJwtSigningOptions();
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(signingOptions.Key);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, model.Username),
                    new Claim(ClaimTypes.Role, "SecurityAnalyst")
                }),
                Issuer = TokenIssuer,
                Audience = TokenAudience,
                Expires = DateTime.UtcNow.AddHours(8),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            string tokenString = tokenHandler.WriteToken(token);

            return Ok(new { Token = tokenString, ExpiresInHours = 8 });
        }
    }

    public class LoginModel
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
    }
}
