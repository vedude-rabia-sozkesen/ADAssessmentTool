using System;
using Microsoft.AspNetCore.Mvc;
using ADAssessment.Infrastructure.Persistence;

using Microsoft.AspNetCore.Authorization;

namespace ADAssessment.WebAPI.Controllers
{
    /// <summary>
    /// Tamamlanmış taramaların kalıcı geçmişini (SQLite tabanlı IScanHistoryRepository)
    /// listeleme/arama/detay görüntüleme uç noktaları. AssessmentController'ın taramayı
    /// ÇALIŞTIRAN tarafı olmasının aksine, bu controller sadece daha önce kaydedilmiş
    /// sonuçları OKUR - hiçbir tarama tetiklemez.
    /// </summary>
    [Authorize(Roles = "SecurityAnalyst")]
    [ApiController]
    [Route("api/[controller]")]
    [Produces("application/json")]
    public class HistoryController : ControllerBase
    {
        private const int DefaultLimit = 50;
        private const int MaxLimit = 200;

        private readonly IScanHistoryRepository _scanHistoryRepository;

        public HistoryController(IScanHistoryRepository scanHistoryRepository)
        {
            _scanHistoryRepository = scanHistoryRepository;
        }

        [HttpGet]
        public IActionResult GetRecentScans([FromQuery] int limit = DefaultLimit, [FromQuery] int offset = 0)
        {
            if (limit <= 0 || limit > MaxLimit)
            {
                limit = DefaultLimit;
            }
            if (offset < 0)
            {
                offset = 0;
            }

            var scans = _scanHistoryRepository.GetRecentScans(limit, offset);
            return Ok(scans);
        }

        [HttpGet("{id:int}")]
        public IActionResult GetScanById(int id)
        {
            var detail = _scanHistoryRepository.GetScanById(id);
            if (detail == null)
            {
                return NotFound(new { Message = "Belirtilen ID'ye sahip bir tarama geçmişi bulunamadı." });
            }

            return Ok(detail);
        }

        [HttpGet("search")]
        public IActionResult SearchScans([FromQuery] DateTime? from, [FromQuery] DateTime? to, [FromQuery] string? initiator)
        {
            var scans = _scanHistoryRepository.SearchScans(from, to, initiator);
            return Ok(scans);
        }
    }
}
