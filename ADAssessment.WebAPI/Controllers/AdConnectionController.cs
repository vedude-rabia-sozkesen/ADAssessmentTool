using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
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
    /// Kaydetmeden önce gerçek bir bağlantı denemesiyle (ILdapConnectionTester) doğrulanır -
    /// yanlış/çalışmayan bir ayar hiçbir zaman kaydedilmez.
    /// </summary>
    [Authorize(Roles = "SecurityAnalyst")]
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class AdConnectionController : ControllerBase
    {
        private readonly IAdConnectionSettingsStore _settingsStore;
        private readonly ILdapConnectionTester _connectionTester;
        private readonly ILogger<AdConnectionController> _logger;

        public AdConnectionController(
            IAdConnectionSettingsStore settingsStore,
            ILdapConnectionTester connectionTester,
            ILogger<AdConnectionController> logger)
        {
            _settingsStore = settingsStore;
            _connectionTester = connectionTester;
            _logger = logger;
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

            // Kaydetmeden önce doğrulama: yanlış kullanıcı adı/parola, ulaşılamayan bir
            // sunucu ya da hatalı bir LDAP Path hiçbir zaman sessizce kaydedilmez - kullanıcı
            // formu doldururken hatasını hemen görür, taramayı çalıştırana kadar beklemez.
            try
            {
                if (!_connectionTester.TestConnection(options))
                {
                    return BadRequest(new { Message = "AD bağlantısı doğrulanamadı. Bilgileri kontrol edip tekrar deneyin." });
                }
            }
            catch (Exception ex)
            {
                // Ham hata mesajı (sunucu adı, dahili path, LDAP hata detayları içerebilir)
                // client'a döndürülmez - AssessmentController.RunScan ile aynı ilke.
                _logger.LogWarning(ex, "AD bağlantı ayarları doğrulanırken hata oluştu.");
                return BadRequest(new { Message = "AD bağlantısı doğrulanamadı. Kullanıcı adı, parola, LDAP Path ve ağ erişimini kontrol edin." });
            }

            _settingsStore.Set(options);

            return Ok(new { Message = "AD bağlantısı doğrulandı ve kaydedildi." });
        }

        [HttpPost("clear")]
        public IActionResult ClearConnection()
        {
            _settingsStore.Clear();
            return Ok(new { Message = "AD bağlantı ayarları temizlendi." });
        }
    }
}
