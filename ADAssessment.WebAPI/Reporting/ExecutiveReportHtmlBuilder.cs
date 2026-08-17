using System;
using System.Linq;
using System.Net;
using System.Text;
using ADAssessment.Core;
using ADAssessment.WebAPI.Models;

namespace ADAssessment.WebAPI.Reporting
{
    /// <summary>
    /// "Yönetici raporu: HTML/PDF, yüksek seviye güvenlik skorları, grafikler, görsel
    /// risk göstergeleri" deliverable'ının HTML kısmı. Kasıtlı olarak hiçbir üçüncü parti
    /// PDF/grafik kütüphanesi kullanmaz (Zero Trust - yeni bağımlılık = yeni gözden
    /// geçirilmesi gereken tedarik zinciri riski): tamamen kendinden yeterli (self-contained)
    /// tek bir HTML dosyası üretir - satır içi (inline) CSS ve elle yazılmış SVG grafik
    /// içerir, hiçbir dış CDN/font/script'e bağımlı değildir. Kullanıcı bu HTML'i
    /// tarayıcıda açıp "Yazdır &gt; PDF olarak kaydet" ile PDF'e çevirebilir - PDF üretimi
    /// için ayrı bir kütüphane/motor gerekmez, işletim sisteminin/tarayıcının kendi
    /// yazdırma motoru kullanılır.
    /// </summary>
    public static class ExecutiveReportHtmlBuilder
    {
        public static string Build(ScanResultResponse scan, SecurityScoreResult score, string generatedBy, DateTime generatedAtUtc)
        {
            string scoreColor = score.Score switch
            {
                >= 90 => "#16a34a",
                >= 75 => "#65a30d",
                >= 60 => "#ca8a04",
                >= 40 => "#ea580c",
                _ => "#dc2626"
            };

            var vulnerable = scan.Results.Where(r => r.IsVulnerable).ToList();
            var isoGroups = vulnerable
                .Where(r => !string.IsNullOrWhiteSpace(r.Iso27001Mapping))
                .GroupBy(r => r.Iso27001Mapping)
                .Select(g => (Mapping: g.Key, Count: g.Count()))
                .OrderByDescending(g => g.Count)
                .ToList();

            int maxCategoryCount = new[] { score.HighCount, score.MediumCount, score.LowCount }.DefaultIfEmpty(0).Max();
            maxCategoryCount = Math.Max(maxCategoryCount, 1); // sıfıra bölme koruması

            var sb = new StringBuilder();
            sb.Append("<!DOCTYPE html><html lang=\"tr\"><head><meta charset=\"utf-8\">");
            sb.Append("<title>AD Güvenlik Değerlendirme Raporu</title>");
            sb.Append(BuildStyles());
            sb.Append("</head><body>");

            sb.Append("<div class=\"page\">");
            sb.Append("<header>");
            sb.Append("<h1>Active Directory Güvenlik Değerlendirme Raporu</h1>");
            sb.Append($"<p class=\"meta\">Oluşturulma: {Html(generatedAtUtc.ToLocalTime().ToString("dd.MM.yyyy HH:mm"))} &middot; Taranan hesap sayısı: {scan.ScannedUserCount} &middot; Çalıştırılan kural sayısı: {scan.TotalRulesExecuted}</p>");
            sb.Append("</header>");

            sb.Append("<section class=\"score-card\">");
            sb.Append($"<div class=\"score-circle\" style=\"border-color:{scoreColor}; color:{scoreColor};\">{score.Score}</div>");
            sb.Append("<div class=\"score-details\">");
            sb.Append($"<div class=\"score-grade\" style=\"color:{scoreColor};\">Not: {Html(score.Grade)}</div>");
            sb.Append($"<div class=\"score-sub\">{scan.VulnerableRulesCount} / {scan.TotalRulesExecuted} kuralda zafiyet tespit edildi.</div>");
            sb.Append("</div>");
            sb.Append("</section>");

            sb.Append("<section>");
            sb.Append("<h2>Risk Seviyesi Dağılımı</h2>");
            sb.Append(BuildRiskBarChart(score, maxCategoryCount));
            sb.Append("</section>");

            if (isoGroups.Count > 0)
            {
                sb.Append("<section>");
                sb.Append("<h2>ISO/IEC 27001:2022 Uyumluluk Etkisi</h2>");
                sb.Append("<table class=\"compliance-table\"><thead><tr><th>Ek A Kontrolü</th><th>Etkilenen Kural Sayısı</th></tr></thead><tbody>");
                foreach (var (mapping, count) in isoGroups)
                {
                    sb.Append($"<tr><td>{Html(mapping)}</td><td>{count}</td></tr>");
                }
                sb.Append("</tbody></table>");
                sb.Append("</section>");
            }

            sb.Append("<section>");
            sb.Append("<h2>Tespit Edilen Zafiyetler</h2>");
            if (vulnerable.Count == 0)
            {
                sb.Append("<p class=\"no-findings\">Bu taramada herhangi bir zafiyet tespit edilmedi.</p>");
            }
            else
            {
                sb.Append("<table class=\"findings-table\"><thead><tr><th>Kural</th><th>Risk</th><th>Çerçeve Eşlemesi</th><th>ISO 27001</th><th>Etkilenen Nesne Sayısı</th></tr></thead><tbody>");
                foreach (var r in vulnerable.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase))
                {
                    string riskClass = "risk-" + r.RiskLevel.ToLowerInvariant();
                    sb.Append("<tr>");
                    sb.Append($"<td>{Html(r.RuleId)}</td>");
                    sb.Append($"<td><span class=\"badge {riskClass}\">{Html(r.RiskLevel)}</span></td>");
                    sb.Append($"<td>{Html(r.FrameworkMapping)}</td>");
                    sb.Append($"<td>{Html(r.Iso27001Mapping)}</td>");
                    sb.Append($"<td>{r.AffectedObjects.Count}</td>");
                    sb.Append("</tr>");
                }
                sb.Append("</tbody></table>");
            }
            sb.Append("</section>");

            sb.Append("<footer>");
            sb.Append($"<p>Bu rapor {Html(generatedBy)} tarafından ADAssessment Tool ile üretilmiştir. Kurumsal ağ dışına hiçbir veri gönderilmemiştir.</p>");
            sb.Append("</footer>");

            sb.Append("</div></body></html>");

            return sb.ToString();
        }

        private static string BuildRiskBarChart(SecurityScoreResult score, int maxCategoryCount)
        {
            const int barAreaWidth = 400;
            const int barHeight = 28;
            const int barGap = 12;

            var rows = new (string Label, int Count, string Color)[]
            {
                ("High", score.HighCount, "#dc2626"),
                ("Medium", score.MediumCount, "#ca8a04"),
                ("Low", score.LowCount, "#65a30d")
            };

            int svgHeight = rows.Length * (barHeight + barGap);
            var sb = new StringBuilder();
            sb.Append($"<svg viewBox=\"0 0 560 {svgHeight}\" class=\"risk-chart\" role=\"img\" aria-label=\"Risk seviyesi dağılım grafiği\">");

            int y = 0;
            foreach (var (label, count, color) in rows)
            {
                int barWidth = (int)Math.Round((double)count / maxCategoryCount * barAreaWidth);
                sb.Append($"<text x=\"0\" y=\"{y + barHeight - 9}\" class=\"chart-label\">{Html(label)}</text>");
                sb.Append($"<rect x=\"90\" y=\"{y}\" width=\"{Math.Max(barWidth, count > 0 ? 4 : 0)}\" height=\"{barHeight}\" fill=\"{color}\" rx=\"4\"></rect>");
                sb.Append($"<text x=\"{90 + barAreaWidth + 12}\" y=\"{y + barHeight - 9}\" class=\"chart-count\">{count}</text>");
                y += barHeight + barGap;
            }

            sb.Append("</svg>");
            return sb.ToString();
        }

        private static string BuildStyles()
        {
            // Bilinçli olarak açık (light) tema - koyu arkaplan yazdırıldığında hem
            // mürekkep israfına hem çoğu yazıcı/PDF motorunda kötü sonuca yol açar.
            return @"<style>
                * { box-sizing: border-box; }
                body { font-family: Segoe UI, Arial, sans-serif; background: #f8fafc; color: #1e293b; margin: 0; }
                .page { max-width: 900px; margin: 0 auto; padding: 32px; }
                header h1 { font-size: 22px; margin-bottom: 4px; }
                .meta { color: #64748b; font-size: 13px; margin-top: 0; }
                section { margin-top: 28px; }
                h2 { font-size: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
                .score-card { display: flex; align-items: center; gap: 24px; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px; }
                .score-circle { width: 84px; height: 84px; border-radius: 50%; border: 6px solid; display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: 700; flex-shrink: 0; }
                .score-grade { font-size: 18px; font-weight: 700; }
                .score-sub { color: #475569; font-size: 13px; margin-top: 4px; }
                .risk-chart { width: 100%; max-width: 560px; }
                .chart-label { font-size: 12px; fill: #1e293b; }
                .chart-count { font-size: 12px; fill: #1e293b; }
                table { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 13px; }
                th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e2e8f0; }
                th { background: #f1f5f9; font-weight: 600; }
                .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; color: #fff; }
                .risk-high { background: #dc2626; }
                .risk-medium { background: #ca8a04; }
                .risk-low { background: #65a30d; }
                .no-findings { color: #16a34a; font-weight: 600; }
                footer { margin-top: 36px; color: #94a3b8; font-size: 11px; }
                @media print {
                    body { background: #fff; }
                    section { page-break-inside: avoid; }
                }
            </style>";
        }

        private static string Html(string value) => WebUtility.HtmlEncode(value ?? string.Empty);
    }
}
