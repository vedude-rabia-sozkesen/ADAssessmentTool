using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.Infrastructure.Logging;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Smb;
using ADAssessment.Infrastructure.Sysvol;
using ADAssessment.WebAPI.Models;
using ADAssessment.WebAPI.Reporting;

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
        private readonly ILdapProtocolSecurityChecker _ldapProtocolChecker;
        private readonly ISmbProtocolSecurityChecker _smbProtocolChecker;
        private readonly IEnumerable<IComplianceRule> _staticRules;
        private readonly IEnumerable<IGroupPolicyComplianceRule> _groupPolicyRules;
        private readonly IEnumerable<IComputerComplianceRule> _computerRules;
        private readonly IEnumerable<ILdapProtocolComplianceRule> _ldapProtocolRules;
        private readonly IEnumerable<ISmbProtocolComplianceRule> _smbProtocolRules;
        private readonly IEnumerable<IDcSyncComplianceRule> _dcSyncRules;
        private readonly IEnumerable<IDomainFunctionalLevelComplianceRule> _domainFunctionalLevelRules;
        private readonly IEnumerable<IForestComplianceRule> _forestRules;
        private readonly IEnumerable<ITrustComplianceRule> _trustRules;
        private readonly JsonRuleRepository _jsonRepository;
        private readonly IAuditLogger _auditLogger;
        private readonly ILogger<AssessmentController> _logger;

        public AssessmentController(
            ILdapDataExtractor extractor,
            ISysvolDataExtractor sysvolExtractor,
            ILdapProtocolSecurityChecker ldapProtocolChecker,
            ISmbProtocolSecurityChecker smbProtocolChecker,
            IEnumerable<IComplianceRule> staticRules,
            IEnumerable<IGroupPolicyComplianceRule> groupPolicyRules,
            IEnumerable<IComputerComplianceRule> computerRules,
            IEnumerable<ILdapProtocolComplianceRule> ldapProtocolRules,
            IEnumerable<ISmbProtocolComplianceRule> smbProtocolRules,
            IEnumerable<IDcSyncComplianceRule> dcSyncRules,
            IEnumerable<IDomainFunctionalLevelComplianceRule> domainFunctionalLevelRules,
            IEnumerable<IForestComplianceRule> forestRules,
            IEnumerable<ITrustComplianceRule> trustRules,
            JsonRuleRepository jsonRepository,
            IAuditLogger auditLogger,
            ILogger<AssessmentController> logger)
        {
            _extractor = extractor;
            _sysvolExtractor = sysvolExtractor;
            _ldapProtocolChecker = ldapProtocolChecker;
            _smbProtocolChecker = smbProtocolChecker;
            _staticRules = staticRules;
            _groupPolicyRules = groupPolicyRules;
            _computerRules = computerRules;
            _ldapProtocolRules = ldapProtocolRules;
            _smbProtocolRules = smbProtocolRules;
            _dcSyncRules = dcSyncRules;
            _domainFunctionalLevelRules = domainFunctionalLevelRules;
            _forestRules = forestRules;
            _trustRules = trustRules;
            _jsonRepository = jsonRepository;
            _auditLogger = auditLogger;
            _logger = logger;
        }

        [HttpPost("scan")]
        public IActionResult RunScan()
        {
            try
            {
                var (response, _) = PerformScan();
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

        [HttpGet("report")]
        public IActionResult GetExecutiveReport()
        {
            try
            {
                var (response, score) = PerformScan();
                string initiator = User.Identity?.Name ?? "WebAPI_User";
                string html = ExecutiveReportHtmlBuilder.Build(response, score, initiator, DateTime.UtcNow);
                // charset=utf-8 açıkça belirtilmezse bazı istemciler (varsayılan Content-Type
                // yorumlaması farklılık gösterebildiğinden) Türkçe karakterleri (ğ, ş, ı, ü vb.)
                // yanlış decode edebilir - rapor bütün metni UTF-8, bunu netleştirmek gerekiyor.
                return Content(html, "text/html; charset=utf-8");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Yönetici raporu üretilirken beklenmeyen bir hata oluştu.");
                return StatusCode(500, new { Status = "Error", Message = "Rapor üretilirken beklenmeyen bir hata oluştu. Lütfen sistem yöneticisiyle iletişime geçin." });
            }
        }

        /// <summary>
        /// Hem /scan (JSON/XML) hem /report (HTML) uç noktalarının paylaştığı taramayı
        /// çalıştırır - iki ayrı isteğin AD'ye iki kez sorgu atmasını (ve denetim izine
        /// iki kayıt düşmesini) önlemek yerine, her istek kendi taramasını yapar; asıl
        /// amaç kod tekrarını (aynı kural çalıştırma/sıralama/eşleme mantığı) önlemektir.
        /// </summary>
        private (ScanResultResponse Response, SecurityScoreResult Score) PerformScan()
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

            // Bilgisayar nesnesi sorgusu da aynı sebeple (LDAP tabanlı kullanıcı taramasından
            // bağımsız bir hata kaynağı oluşturmasın diye) izole edilir.
            IReadOnlyList<AdComputerAccount>? computers = null;
            try
            {
                computers = _extractor.GetComputerAccounts();
            }
            catch (Exception computerEx)
            {
                _logger.LogWarning(computerEx, "Bilgisayar nesnesi verisi okunamadı, bilgisayar tabanlı kurallar bu taramada atlandı.");
            }

            // LDAP protokol güvenliği kontrolü de gerçek bir ağ bağlantısı denemesi
            // içerdiğinden (bkz. LdapProtocolSecurityChecker), aynı sebeple izole edilir.
            LdapProtocolSecuritySettings? ldapProtocolSecurity = null;
            try
            {
                ldapProtocolSecurity = _ldapProtocolChecker.CheckProtocolSecurity();
            }
            catch (Exception ldapProtocolEx)
            {
                _logger.LogWarning(ldapProtocolEx, "LDAP protokol güvenliği kontrol edilemedi, ilgili kurallar bu taramada atlandı.");
            }

            // SMB protokol güvenliği kontrolü de gerçek bir ağ bağlantısı denemesi
            // içerdiğinden, aynı sebeple izole edilir.
            SmbProtocolSecuritySettings? smbProtocolSecurity = null;
            try
            {
                smbProtocolSecurity = _smbProtocolChecker.CheckAnonymousAccess();
            }
            catch (Exception smbProtocolEx)
            {
                _logger.LogWarning(smbProtocolEx, "SMB protokol güvenliği kontrol edilemedi, ilgili kurallar bu taramada atlandı.");
            }

            // DCSync hakları kontrolü de domain kökünün DACL'ini okuyan ayrı bir sorgu
            // olduğundan, aynı sebeple izole edilir.
            DcSyncRightsSettings? dcSyncRights = null;
            try
            {
                dcSyncRights = _extractor.GetDcSyncRights();
            }
            catch (Exception dcSyncEx)
            {
                _logger.LogWarning(dcSyncEx, "DCSync hakları kontrol edilemedi, ilgili kurallar bu taramada atlandı.");
            }

            // Domain fonksiyonel seviyesi kontrolü de domain kökünü okuyan ayrı bir sorgu
            // olduğundan, aynı sebeple izole edilir.
            DomainFunctionalLevelSettings? domainFunctionalLevel = null;
            try
            {
                domainFunctionalLevel = _extractor.GetDomainFunctionalLevel();
            }
            catch (Exception functionalLevelEx)
            {
                _logger.LogWarning(functionalLevelEx, "Domain fonksiyonel seviyesi kontrol edilemedi, ilgili kurallar bu taramada atlandı.");
            }

            // Forest seviyesi isteğe bağlı özellik kontrolü (AD Recycle Bin) de RootDSE +
            // Configuration NC okuyan ayrı bir sorgu olduğundan, aynı sebeple izole edilir.
            ForestOptionalFeatureSettings? forestFeatures = null;
            try
            {
                forestFeatures = _extractor.GetForestOptionalFeatures();
            }
            catch (Exception forestEx)
            {
                _logger.LogWarning(forestEx, "Forest seviyesi özellikler kontrol edilemedi, ilgili kurallar bu taramada atlandı.");
            }

            // Trust ilişkileri kontrolü de CN=System konteynerini okuyan ayrı bir sorgu
            // olduğundan, aynı sebeple izole edilir.
            IReadOnlyList<AdTrustRelationship>? trusts = null;
            try
            {
                trusts = _extractor.GetTrustRelationships();
            }
            catch (Exception trustEx)
            {
                _logger.LogWarning(trustEx, "Trust ilişkileri kontrol edilemedi, ilgili kurallar bu taramada atlandı.");
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

            foreach (var rule in _computerRules)
            {
                results.Add(rule.Execute(computers!));
            }

            foreach (var rule in _ldapProtocolRules)
            {
                results.Add(rule.Execute(ldapProtocolSecurity!));
            }

            foreach (var rule in _smbProtocolRules)
            {
                results.Add(rule.Execute(smbProtocolSecurity!));
            }

            foreach (var rule in _dcSyncRules)
            {
                results.Add(rule.Execute(dcSyncRights!));
            }

            foreach (var rule in _domainFunctionalLevelRules)
            {
                results.Add(rule.Execute(domainFunctionalLevel!));
            }

            foreach (var rule in _forestRules)
            {
                results.Add(rule.Execute(forestFeatures!));
            }

            foreach (var rule in _trustRules)
            {
                results.Add(rule.Execute(trusts!));
            }

            int totalRulesExecuted = rules.Count + _groupPolicyRules.Count() + _computerRules.Count() + _ldapProtocolRules.Count() + _smbProtocolRules.Count() + _dcSyncRules.Count() + _domainFunctionalLevelRules.Count() + _forestRules.Count() + _trustRules.Count();

            string initiator = User.Identity?.Name ?? "WebAPI_User";
            _auditLogger.LogAssessment(initiator, users.Count, results);

            // Kurallar farklı kaynaklardan (statik, JSON, GPO, bilgisayar) farklı sırayla
            // geldiğinden (JSON dosyaları için dosya sistemi sıralaması garanti değildir),
            // sonuçlar client'a dönmeden önce RuleId'ye göre sıralanır - "AD-001..AD-018" gibi
            // sabit uzunluklu numaralandırma için düz string sıralaması sayısal sırayla eşleşir.
            var orderedResults = results.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).ToList();

            // Otomatik Compliance Mapping: her bulgunun (finding) hangi çerçeve
            // kontrolüne karşılık geldiği, SIEM tüketicisinin ayrıca /api/rules'a
            // bakmasına gerek kalmadan doğrudan sonuçta görünsün diye burada eklenir.
            var ruleMetadataById = rules
                .Concat(_groupPolicyRules)
                .Concat(_computerRules)
                .Concat(_ldapProtocolRules)
                .Concat(_smbProtocolRules)
                .Concat(_dcSyncRules)
                .Concat(_domainFunctionalLevelRules)
                .Concat(_forestRules)
                .Concat(_trustRules)
                .GroupBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);

            // SIEM (Security Information and Event Management - kurumların güvenlik
            // olaylarını merkezi topladığı sistem) entegrasyonu için hem JSON hem XML
            // olarak sunulabilecek, kararlı bir dış sözleşme (ScanResultResponse) - istemci
            // Accept header'ında "application/xml" isterse ASP.NET Core aynı nesneyi
            // otomatik olarak XML'e çevirir, kod tarafında ayrı bir dallanma gerekmez.
            var response = new ScanResultResponse
            {
                Status = "Success",
                ScannedUserCount = users.Count,
                ScannedComputerCount = computers?.Count ?? 0,
                TotalRulesExecuted = totalRulesExecuted,
                VulnerableRulesCount = results.Count(r => r.IsVulnerable),
                Results = orderedResults.Select(r =>
                {
                    ruleMetadataById.TryGetValue(r.RuleId, out var ruleMetadata);
                    return new RuleResultDto
                    {
                        RuleId = r.RuleId,
                        IsVulnerable = r.IsVulnerable,
                        RiskLevel = r.RiskLevel,
                        FrameworkMapping = ruleMetadata?.FrameworkMapping ?? string.Empty,
                        Iso27001Mapping = ruleMetadata?.Iso27001Mapping ?? string.Empty,
                        AffectedObjects = r.AffectedObjects.ToList(),
                        Remediation = r.Remediation
                    };
                }).ToList()
            };

            var score = SecurityScoreCalculator.Calculate(results);

            return (response, score);
        }
    }
}
