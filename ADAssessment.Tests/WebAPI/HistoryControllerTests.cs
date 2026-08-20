using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Persistence;
using ADAssessment.WebAPI.Controllers;
using Xunit;

namespace ADAssessment.Tests.WebAPI
{
    public class HistoryControllerTests
    {
        private sealed class FakeRepository : IScanHistoryRepository
        {
            public IReadOnlyList<ScanHistorySummary> RecentScans { get; set; } = Array.Empty<ScanHistorySummary>();
            public ScanHistoryDetail? DetailToReturn { get; set; }
            public IReadOnlyList<ScanHistorySummary> SearchResults { get; set; } = Array.Empty<ScanHistorySummary>();

            public int SaveScan(DateTime timestampUtc, string initiator, int scannedUserCount, int scannedComputerCount, int totalRulesExecuted, int vulnerableRulesCount, int securityScore, string securityGrade, IEnumerable<ScanRuleFinding> findings) => 1;

            public IReadOnlyList<ScanHistorySummary> GetRecentScans(int limit, int offset) => RecentScans;

            public ScanHistoryDetail? GetScanById(int id) => DetailToReturn;

            public IReadOnlyList<ScanHistorySummary> SearchScans(DateTime? fromUtc, DateTime? toUtc, string? initiator) => SearchResults;
        }

        private static ScanHistorySummary SampleSummary(int id) => new(id, DateTime.UtcNow, "burak", 18, 2, 33, 5, 72, "C");

        [Fact]
        public void GetRecentScans_ReturnsOkWithList()
        {
            var repository = new FakeRepository { RecentScans = new[] { SampleSummary(1) } };
            var controller = new HistoryController(repository);

            var result = controller.GetRecentScans();

            var okResult = Assert.IsType<OkObjectResult>(result);
            var scans = Assert.IsAssignableFrom<IReadOnlyList<ScanHistorySummary>>(okResult.Value);
            Assert.Single(scans);
        }

        [Fact]
        public void GetScanById_ExistingId_ReturnsOk()
        {
            var summary = SampleSummary(1);
            var detail = new ScanHistoryDetail(summary, Array.Empty<ScanRuleFinding>());
            var repository = new FakeRepository { DetailToReturn = detail };
            var controller = new HistoryController(repository);

            var result = controller.GetScanById(1);

            Assert.IsType<OkObjectResult>(result);
        }

        [Fact]
        public void GetScanById_NonExistentId_ReturnsNotFound()
        {
            var repository = new FakeRepository { DetailToReturn = null };
            var controller = new HistoryController(repository);

            var result = controller.GetScanById(999);

            Assert.IsType<NotFoundObjectResult>(result);
        }

        [Fact]
        public void SearchScans_ReturnsOkWithResults()
        {
            var repository = new FakeRepository { SearchResults = new[] { SampleSummary(2) } };
            var controller = new HistoryController(repository);

            var result = controller.SearchScans(null, null, "burak");

            var okResult = Assert.IsType<OkObjectResult>(result);
            var scans = Assert.IsAssignableFrom<IReadOnlyList<ScanHistorySummary>>(okResult.Value);
            Assert.Single(scans);
        }

        [Fact]
        public void GetRecentScans_InvalidLimit_FallsBackToDefault()
        {
            var repository = new FakeRepository { RecentScans = new[] { SampleSummary(1) } };
            var controller = new HistoryController(repository);

            var result = controller.GetRecentScans(limit: -5, offset: -10);

            Assert.IsType<OkObjectResult>(result);
        }
    }
}
