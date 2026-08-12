using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.Infrastructure.Logging;
using ADAssessment.Infrastructure.Configuration;

using Microsoft.AspNetCore.Authorization;

namespace ADAssessment.WebAPI.Controllers
{
    [Authorize(Roles = "SecurityAnalyst")]
    [ApiController]
    [Route("api/[controller]")]
    public class AssessmentController : ControllerBase
    {
        private readonly ILdapDataExtractor _extractor;
        private readonly IEnumerable<IComplianceRule> _staticRules;
        private readonly JsonRuleRepository _jsonRepository;
        private readonly IAuditLogger _auditLogger;
        private readonly ILogger<AssessmentController> _logger;

        public AssessmentController(
            ILdapDataExtractor extractor,
            IEnumerable<IComplianceRule> staticRules,
            JsonRuleRepository jsonRepository,
            IAuditLogger auditLogger,
            ILogger<AssessmentController> logger)
        {
            _extractor = extractor;
            _staticRules = staticRules;
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

                var rules = new List<IComplianceRule>(_staticRules);
                var dynamicRules = _jsonRepository.LoadRules();
                rules.AddRange(dynamicRules);

                var results = new List<RuleResult>();

                foreach (var rule in rules)
                {
                    results.Add(rule.Execute(users));
                }

                string initiator = User.Identity?.Name ?? "WebAPI_User";
                _auditLogger.LogAssessment(initiator, users.Count, results);

                return Ok(new
                {
                    Status = "Success",
                    ScannedUserCount = users.Count,
                    TotalRulesExecuted = rules.Count,
                    VulnerableRulesCount = results.Count(r => r.IsVulnerable),
                    Results = results
                });
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
