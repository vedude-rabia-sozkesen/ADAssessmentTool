using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.Infrastructure.Logging;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Sysvol;
using ADAssessment.WebAPI.Models;

using Microsoft.AspNetCore.Authorization;

namespace ADAssessment.WebAPI.Controllers
{
    [Authorize(Roles = "SecurityAnalyst")]
    [ApiController]
    [Route("api/[controller]")]
    public class AssessmentController : ControllerBase
    {
        private readonly ILdapDataExtractor _extractor;
        private readonly ISysvolDataExtractor _sysvolExtractor;
        private readonly IEnumerable<IComplianceRule> _staticRules;
        private readonly IEnumerable<IGroupPolicyComplianceRule> _groupPolicyRules;
        private readonly JsonRuleRepository _jsonRepository;
        private readonly IAuditLogger _auditLogger;
        private readonly ILogger<AssessmentController> _logger;

        public AssessmentController(
            ILdapDataExtractor extractor,
            ISysvolDataExtractor sysvolExtractor,
            IEnumerable<IComplianceRule> staticRules,
            IEnumerable<IGroupPolicyComplianceRule> groupPolicyRules,
            JsonRuleRepository jsonRepository,
            IAuditLogger auditLogger,
            ILogger<AssessmentController> logger)
        {
            _extractor = extractor;
            _sysvolExtractor = sysvolExtractor;
            _staticRules = staticRules;
            _groupPolicyRules = groupPolicyRules;
            _jsonRepository = jsonRepository;
            _auditLogger = auditLogger;
            _logger = logger;
        }

        [HttpPost("scan")]
        public IActionResult RunScan()
        {
            try
            {
                var users = _extractor.GetActiveUsers();

                // SYSVOL/GPO okuma, LDAP tabanlı taramadan bağımsız bir hata kaynağı -
                // erişilemezse (ağ/izin sorunu) tüm taramayı düşürmek yerine sadece GPO
                // tabanlı kurallar "veri sağlanamadı" (Informational) sonucunu döner.
                IReadOnlyList<GroupPolicySecuritySettings>? groupPolicies = null;
                try
                {
                    groupPolicies = _sysvolExtractor.GetSecuritySettings();
                }
                catch (Exception sysvolEx)
                {
                    _logger.LogWarning(sysvolEx, "SYSVOL/GPO verisi okunamadı, GPO tabanlı kurallar bu taramada atlandı.");
                }

                var rules = new List<IComplianceRule>(_staticRules);
                var dynamicRules = _jsonRepository.LoadRules();
                rules.AddRange(dynamicRules);

                var results = new List<RuleResult>();

                foreach (var rule in rules)
                {
                    results.Add(rule.Execute(users));
                }

                foreach (var rule in _groupPolicyRules)
                {
                    results.Add(rule.Execute(groupPolicies!));
                }

                int totalRulesExecuted = rules.Count + _groupPolicyRules.Count();

                string initiator = User.Identity?.Name ?? "WebAPI_User";
                _auditLogger.LogAssessment(initiator, users.Count, results);

                // Kurallar farklı kaynaklardan (statik, JSON, GPO) farklı sırayla geldiğinden
                // (JSON dosyaları için dosya sistemi sıralaması garanti değildir), sonuçlar
                // client'a dönmeden önce RuleId'ye göre sıralanır - "AD-001..AD-015" gibi sabit
                // uzunluklu numaralandırma için düz string sıralaması sayısal sırayla eşleşir.
                var orderedResults = results.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).ToList();

                // SIEM (Security Information and Event Management - kurumların güvenlik
                // olaylarını merkezi topladığı sistem) entegrasyonu için hem JSON hem XML
                // olarak sunulabilecek, kararlı bir dış sözleşme (ScanResultResponse) - istemci
                // Accept header'ında "application/xml" isterse ASP.NET Core aynı nesneyi
                // otomatik olarak XML'e çevirir, kod tarafında ayrı bir dallanma gerekmez.
                var response = new ScanResultResponse
                {
                    Status = "Success",
                    ScannedUserCount = users.Count,
                    TotalRulesExecuted = totalRulesExecuted,
                    VulnerableRulesCount = results.Count(r => r.IsVulnerable),
                    Results = orderedResults.Select(r => new RuleResultDto
                    {
                        RuleId = r.RuleId,
                        IsVulnerable = r.IsVulnerable,
                        RiskLevel = r.RiskLevel,
                        AffectedObjects = r.AffectedObjects.ToList(),
                        Remediation = r.Remediation
                    }).ToList()
                };

                return Ok(response);
            }
            catch (Exception ex)
            {
                // Ham hata mesajı (sunucu adı, dahili path, LDAP hata detayları içerebilir)
                // client'a döndürülmez; sadece sunucu tarafı loguna yazılır.
                _logger.LogError(ex, "AD güvenlik taraması sırasında beklenmeyen bir hata oluştu.");
                return StatusCode(500, new { Status = "Error", Message = "Tarama sırasında beklenmeyen bir hata oluştu. Lütfen sistem yöneticisiyle iletişime geçin." });
            }
        }
    }
}
