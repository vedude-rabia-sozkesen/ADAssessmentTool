using Microsoft.AspNetCore.Mvc;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.WebAPI.Models;

using Microsoft.AspNetCore.Authorization;

namespace ADAssessment.WebAPI.Controllers
{
    /// <summary>
    /// Dashboard'dan "hangi AD'ye, hangi hesapla bağlanılacağının" arayüzden
    /// yapılandırılmasını sağlar. [Authorize] gereği önce dashboard girişi yapılmış
    /// olmalı - AD bağlantı ayarını sadece giriş yapmış bir analist değiştirebilir.
    /// Ayar sadece bellekte (IAdConnectionSettingsStore) tutulur, diske hiç yazılmaz.
    /// </summary>
    [Authorize(Roles = "SecurityAnalyst")]
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class AdConnectionController : ControllerBase
    {
        private readonly IAdConnectionSettingsStore _settingsStore;

        public AdConnectionController(IAdConnectionSettingsStore settingsStore)
        {
            _settingsStore = settingsStore;
        }

        [HttpGet("status")]
        public IActionResult GetStatus()
        {
            var current = _settingsStore.GetCurrent();

            return Ok(new AdConnectionStatusResponse
            {
                Configured = current != null,
                LdapPath = current?.LdapPath,
                Username = current?.Username
            });
        }

        [HttpPost]
        public IActionResult SetConnection([FromBody] AdConnectionRequest request)
        {
            if (request == null || string.IsNullOrWhiteSpace(request.LdapPath))
            {
                return BadRequest(new { Message = "Geçersiz bağlantı ayarı. LDAP Path/IP boş olamaz." });
            }

            var options = new LdapConnectionOptions
            {
                LdapPath = request.LdapPath.Trim(),
                Username = request.Username,
                Password = request.Password,
                UseLdaps = request.UseLdaps,
                // Zero Trust: bu alan formda açıkça işaretlenmedikçe false kalır - env
                // var tabanlı ResolveLdapOptions ile aynı fail-closed varsayılan.
                AllowUnsecureFallback = request.AllowUnsecureFallback
            };

            _settingsStore.Set(options);

            return Ok(new { Message = "AD bağlantı ayarları kaydedildi." });
        }

        [HttpPost("clear")]
        public IActionResult ClearConnection()
        {
            _settingsStore.Clear();
            return Ok(new { Message = "AD bağlantı ayarları temizlendi." });
        }
    }
}
