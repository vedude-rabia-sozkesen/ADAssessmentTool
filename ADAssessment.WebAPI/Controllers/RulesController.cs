using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.WebAPI.Models;

using Microsoft.AspNetCore.Authorization;

namespace ADAssessment.WebAPI.Controllers
{
    [Authorize(Roles = "SecurityAnalyst")]
    [ApiController]
    [Route("api/[controller]")]
    // JsonRuleDefinition.Value ("object" tipinde, No-Code kural motorunun herhangi bir JSON
    // değerini tutabilmesi için) XmlSerializer tarafından serileştirilemez - bu controller
    // XML content negotiation'a hiç girmesin diye JSON'a sabitlenir.
    [Produces("application/json")]
    public class RulesController : ControllerBase
    {
        private readonly JsonRuleRepository _jsonRepository;
        private readonly IReadOnlyList<IComplianceRule> _staticRules;

        public RulesController(
            JsonRuleRepository jsonRepository,
            IEnumerable<IComplianceRule> staticRules,
            IEnumerable<IGroupPolicyComplianceRule> groupPolicyRules,
            IEnumerable<IComputerComplianceRule> computerRules,
            IEnumerable<ILdapProtocolComplianceRule> ldapProtocolRules,
            IEnumerable<ISmbProtocolComplianceRule> smbProtocolRules,
            IEnumerable<IDcSyncComplianceRule> dcSyncRules,
            IEnumerable<IDomainFunctionalLevelComplianceRule> domainFunctionalLevelRules,
            IEnumerable<IForestComplianceRule> forestRules,
            IEnumerable<ITrustComplianceRule> trustRules)
        {
            _jsonRepository = jsonRepository;
            // GPO, bilgisayar, LDAP/SMB protokol, DCSync, domain fonksiyonel seviyesi,
            // forest özellik ve trust tabanlı kurallar da derlenmiş kod olduğundan
            // (Source="Static") aynı listeye dahil edilir - hepsi zaten IComplianceRule
            // olduğundan cast'e gerek kalmaz.
            _staticRules = staticRules.Concat(groupPolicyRules).Concat(computerRules).Concat(ldapProtocolRules).Concat(smbProtocolRules).Concat(dcSyncRules).Concat(domainFunctionalLevelRules).Concat(forestRules).Concat(trustRules).ToList();
        }

        [HttpGet]
        public IActionResult GetRules()
        {
            var items = new List<RuleListItem>();

            foreach (var rule in _staticRules)
            {
                items.Add(new RuleListItem
                {
                    RuleId = rule.RuleId,
                    Name = rule.Name,
                    Description = rule.Description,
                    FrameworkMapping = rule.FrameworkMapping,
                    Iso27001Mapping = rule.Iso27001Mapping,
                    Source = "Static",
                    IsEditable = false,
                    DataCategory = InferStaticRuleCategory(rule)
                });
            }

            foreach (var rule in _jsonRepository.LoadRules())
            {
                if (rule is not DynamicComplianceRule dynamicRule) continue;

                bool hasNestedConditions = dynamicRule.Definition.Conditions != null && dynamicRule.Definition.Conditions.Count > 0;

                items.Add(new RuleListItem
                {
                    RuleId = rule.RuleId,
                    Name = rule.Name,
                    Description = rule.Description,
                    FrameworkMapping = rule.FrameworkMapping,
                    Iso27001Mapping = rule.Iso27001Mapping,
                    Source = "JsonFile",
                    IsEditable = !hasNestedConditions,
                    Definition = dynamicRule.Definition,
                    DataCategory = dynamicRule.DataCategory
                });
            }

            var orderedItems = items.OrderBy(i => i.RuleId, StringComparer.OrdinalIgnoreCase).ToList();
            return Ok(orderedItems);
        }

        /// <summary>
        /// Frontend'in "Hedef Veri Kategorisi" dropdown'ını (optgroup'larla) doldurması için.
        /// RuleDataCategory tek doğruluk kaynağı olduğundan buradaki liste asla backend'in
        /// gerçekte desteklediği kategorilerden sapamaz.
        /// </summary>
        [HttpGet("categories")]
        public IActionResult GetCategories()
        {
            var result = RuleDataCategory.AllCategories.Select(c => new
            {
                Value = c,
                Label = RuleDataCategory.GetDisplayLabel(c),
                Group = RuleDataCategory.GetGroupLabel(c)
            });
            return Ok(result);
        }

        /// <summary>
        /// Frontend'in "Hedef Özellik" dropdown'ını seçilen kategoriye göre dinamik olarak
        /// doldurması için - reflection ile üretilir, bu yüzden RuleEvaluator'ın gerçekte
        /// çözebildiği alanlarla birebir aynı kaynaktan gelir (drift imkansız).
        /// </summary>
        [HttpGet("schema/{category}")]
        public IActionResult GetSchema(string category)
        {
            if (!RuleDataCategory.IsValid(category))
            {
                return BadRequest(new { Message = "Bilinmeyen veri kategorisi." });
            }

            return Ok(RuleDataCategory.GetPropertyNames(category));
        }

        [HttpPost]
        public IActionResult CreateJsonRule([FromBody] JsonRuleDefinition ruleDefinition)
        {
            if (ruleDefinition == null || !RuleIdValidator.IsValid(ruleDefinition.RuleId))
            {
                return BadRequest(new { Message = "Geçersiz kural tanımı. RuleId sadece harf, rakam, '-' ve '_' karakterlerinden oluşabilir (1-64 karakter)." });
            }

            if (_staticRules.Any(r => string.Equals(r.RuleId, ruleDefinition.RuleId, StringComparison.OrdinalIgnoreCase)))
            {
                return BadRequest(new { Message = "Bu RuleId sabit (derlenmiş) bir kural tarafından kullanılıyor, No-Code kural olarak eklenemez." });
            }

            if (!ValidateDataCategoryAndProperty(ruleDefinition, out IActionResult? categoryError))
            {
                return categoryError!;
            }

            string filePath = ResolveRuleFilePath(ruleDefinition.RuleId, out IActionResult? pathError);
            if (pathError != null) return pathError;

            string jsonString = JsonSerializer.Serialize(ruleDefinition, new JsonSerializerOptions { WriteIndented = true });
            System.IO.File.WriteAllText(filePath, jsonString);

            return CreatedAtAction(nameof(GetRules), new { id = ruleDefinition.RuleId }, new { Message = "No-Code JSON kuralı başarıyla eklendi.", FilePath = filePath });
        }

        [HttpPut("{ruleId}")]
        public IActionResult UpdateJsonRule(string ruleId, [FromBody] JsonRuleDefinition ruleDefinition)
        {
            if (!RuleIdValidator.IsValid(ruleId))
            {
                return BadRequest(new { Message = "Geçersiz RuleId." });
            }

            if (_staticRules.Any(r => string.Equals(r.RuleId, ruleId, StringComparison.OrdinalIgnoreCase)))
            {
                return BadRequest(new { Message = "Sabit (derlenmiş) kurallar düzenlenemez." });
            }

            string filePath = ResolveRuleFilePath(ruleId, out IActionResult? pathError);
            if (pathError != null) return pathError;

            if (!System.IO.File.Exists(filePath))
            {
                return NotFound(new { Message = "Güncellenecek kural bulunamadı." });
            }

            if (ruleDefinition == null)
            {
                return BadRequest(new { Message = "Geçersiz kural tanımı." });
            }

            if (!ValidateDataCategoryAndProperty(ruleDefinition, out IActionResult? categoryError))
            {
                return categoryError!;
            }

            // RuleId her zaman route'tan gelen değere sabitlenir; body'den farklı bir
            // RuleId gönderilerek dosya adının/kimlik doğrulamasının atlatılması engellenir.
            ruleDefinition.RuleId = ruleId;

            string jsonString = JsonSerializer.Serialize(ruleDefinition, new JsonSerializerOptions { WriteIndented = true });
            System.IO.File.WriteAllText(filePath, jsonString);

            return Ok(new { Message = "No-Code JSON kuralı başarıyla güncellendi." });
        }

        [HttpDelete("{ruleId}")]
        public IActionResult DeleteJsonRule(string ruleId)
        {
            if (!RuleIdValidator.IsValid(ruleId))
            {
                return BadRequest(new { Message = "Geçersiz RuleId." });
            }

            if (_staticRules.Any(r => string.Equals(r.RuleId, ruleId, StringComparison.OrdinalIgnoreCase)))
            {
                return BadRequest(new { Message = "Sabit (derlenmiş) kurallar silinemez." });
            }

            string filePath = ResolveRuleFilePath(ruleId, out IActionResult? pathError);
            if (pathError != null) return pathError;

            if (!System.IO.File.Exists(filePath))
            {
                return NotFound(new { Message = "Silinecek kural bulunamadı." });
            }

            System.IO.File.Delete(filePath);

            return Ok(new { Message = "No-Code JSON kuralı başarıyla silindi." });
        }

        /// <summary>
        /// Bir sabit (derlenmiş) kuralın hangi marker interface'i (bkz. RuleDataCategory
        /// registry'sindeki tiplerle eşleşen IComputerComplianceRule, ITrustComplianceRule
        /// vb.) implemente ettiğine bakarak "Aktif Kurallar" listesinde göstermek için bir
        /// kategori tahmin eder. Hiçbiriyle eşleşmezse (kurucu ctor'daki temel
        /// IEnumerable&lt;IComplianceRule&gt; grubu) varsayılan "User" kabul edilir.
        /// </summary>
        private static string InferStaticRuleCategory(IComplianceRule rule)
        {
            if (rule is IComputerComplianceRule) return RuleDataCategory.Computer;
            if (rule is IGroupPolicyComplianceRule) return RuleDataCategory.GroupPolicy;
            if (rule is ILdapProtocolComplianceRule) return RuleDataCategory.LdapProtocol;
            if (rule is ISmbProtocolComplianceRule) return RuleDataCategory.SmbProtocol;
            if (rule is IDcSyncComplianceRule) return RuleDataCategory.DcSync;
            if (rule is IDomainFunctionalLevelComplianceRule) return RuleDataCategory.DomainFunctionalLevel;
            if (rule is IForestComplianceRule) return RuleDataCategory.ForestOptionalFeature;
            if (rule is ITrustComplianceRule) return RuleDataCategory.Trust;
            return RuleDataCategory.User;
        }

        /// <summary>
        /// No-Code kural kaydı/güncellemesi anında DataCategory'nin geçerli olduğunu ve
        /// (nested olmayan tekli koşullarda) TargetProperty'nin gerçekten o kategoride var
        /// olan bir özellik olduğunu doğrular. Bu kontrol olmadan yanlış yazılmış bir alan
        /// adı (ör. "SamAcountName") sessizce hiçbir zaman eşleşmeyen, hatasız görünen ama
        /// aslında hiç işe yaramayan bir kural olarak kayıt anında fark edilmeden kalırdı -
        /// hata artık kayıt anında, açık bir mesajla verilir.
        /// </summary>
        private static bool ValidateDataCategoryAndProperty(JsonRuleDefinition ruleDefinition, out IActionResult? error)
        {
            string category = RuleDataCategory.Normalize(ruleDefinition.DataCategory);
            if (!RuleDataCategory.IsValid(category))
            {
                error = new BadRequestObjectResult(new { Message = $"Bilinmeyen veri kategorisi: '{ruleDefinition.DataCategory}'." });
                return false;
            }

            ruleDefinition.DataCategory = category;

            var knownProperties = new HashSet<string>(RuleDataCategory.GetPropertyNames(category), StringComparer.OrdinalIgnoreCase);

            if (ruleDefinition.Conditions != null && ruleDefinition.Conditions.Count > 0)
            {
                if (!ValidateConditionProperties(ruleDefinition.Conditions, knownProperties, category, out error))
                {
                    return false;
                }
            }
            else if (!string.IsNullOrWhiteSpace(ruleDefinition.TargetProperty) && !knownProperties.Contains(ruleDefinition.TargetProperty))
            {
                error = new BadRequestObjectResult(new { Message = $"'{ruleDefinition.TargetProperty}' özelliği '{category}' kategorisinde bulunamadı." });
                return false;
            }

            error = null;
            return true;
        }

        private static bool ValidateConditionProperties(List<RuleConditionNode> conditions, HashSet<string> knownProperties, string category, out IActionResult? error)
        {
            foreach (var node in conditions)
            {
                if (node.Conditions != null && node.Conditions.Count > 0)
                {
                    if (!ValidateConditionProperties(node.Conditions, knownProperties, category, out error))
                    {
                        return false;
                    }
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(node.TargetProperty) && !knownProperties.Contains(node.TargetProperty))
                {
                    error = new BadRequestObjectResult(new { Message = $"'{node.TargetProperty}' özelliği '{category}' kategorisinde bulunamadı." });
                    return false;
                }
            }

            error = null;
            return true;
        }

        /// <summary>
        /// RuleId'den rules/ klasörü altında güvenli bir dosya yolu üretir. Path traversal
        /// koruması: RuleIdValidator regex kontrolüne ek olarak, üretilen tam yolun gerçekten
        /// rules/ klasörü altında kaldığı ayrıca doğrulanır (savunma derinliği). Klasör olarak
        /// _jsonRepository ile AYNI değer kullanılır - kendi başına ayrı bir yol hesaplanmaz,
        /// aksi halde WebAPI'nin okuduğu/yazdığı klasörler birbirinden sapabilir.
        /// </summary>
        private string ResolveRuleFilePath(string ruleId, out IActionResult? error)
        {
            string rulesFolder = _jsonRepository.RulesFolderPath;
            if (!Directory.Exists(rulesFolder)) Directory.CreateDirectory(rulesFolder);

            string filePath = Path.Combine(rulesFolder, $"{ruleId}.json");

            string fullRulesFolder = Path.GetFullPath(rulesFolder) + Path.DirectorySeparatorChar;
            string fullFilePath = Path.GetFullPath(filePath);

            if (!fullFilePath.StartsWith(fullRulesFolder, StringComparison.OrdinalIgnoreCase))
            {
                error = new BadRequestObjectResult(new { Message = "Geçersiz kural tanımı. RuleId geçersiz bir dosya yolu üretiyor." });
                return string.Empty;
            }

            error = null;
            return filePath;
        }
    }
}
