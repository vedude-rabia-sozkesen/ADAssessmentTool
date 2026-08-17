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
            IEnumerable<IGroupPolicyComplianceRule> groupPolicyRules)
        {
            _jsonRepository = jsonRepository;
            // GPO tabanlı kurallar da derlenmiş kod olduğundan (Source="Static") aynı
            // listeye dahil edilir - IGroupPolicyComplianceRule zaten IComplianceRule
            // olduğundan cast'e gerek kalmaz.
            _staticRules = staticRules.Concat(groupPolicyRules).ToList();
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
                    IsEditable = false
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
                    Definition = dynamicRule.Definition
                });
            }

            var orderedItems = items.OrderBy(i => i.RuleId, StringComparer.OrdinalIgnoreCase).ToList();
            return Ok(orderedItems);
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
