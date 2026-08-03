using Microsoft.AspNetCore.Mvc;
using System;
using System.IO;
using System.Text.Json;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Configuration;

using Microsoft.AspNetCore.Authorization;

namespace ADAssessment.WebAPI.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class RulesController : ControllerBase
    {
        private readonly JsonRuleRepository _jsonRepository;

        public RulesController(JsonRuleRepository jsonRepository)
        {
            _jsonRepository = jsonRepository;
        }

        [HttpGet]
        public IActionResult GetRules()
        {
            var rules = _jsonRepository.LoadRules();
            return Ok(rules);
        }

        [HttpPost]
        public IActionResult CreateJsonRule([FromBody] JsonRuleDefinition ruleDefinition)
        {
            if (ruleDefinition == null || string.IsNullOrWhiteSpace(ruleDefinition.RuleId))
            {
                return BadRequest(new { Message = "Geçersiz kural tanımı. RuleId zorunludur." });
            }

            string rulesFolder = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules");
            if (!Directory.Exists(rulesFolder)) Directory.CreateDirectory(rulesFolder);

            string filePath = Path.Combine(rulesFolder, $"{ruleDefinition.RuleId}.json");
            string jsonString = JsonSerializer.Serialize(ruleDefinition, new JsonSerializerOptions { WriteIndented = true });

            System.IO.File.WriteAllText(filePath, jsonString);

            return CreatedAtAction(nameof(GetRules), new { id = ruleDefinition.RuleId }, new { Message = "No-Code JSON kuralı başarıyla eklendi.", FilePath = filePath });
        }
    }
}
