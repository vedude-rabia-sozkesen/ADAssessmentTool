namespace ADAssessment.Core
{
    /// <summary>
    /// AD Recycle Bin (Silinen Öğeler Kutusu), yanlışlıkla veya kötü niyetle silinen bir AD
    /// nesnesinin (kullanıcı, grup, GPO vb.) tüm özellikleriyle birlikte geri getirilmesini
    /// sağlayan, forest seviyesinde tek seferlik etkinleştirilen bir özelliktir - kapalıysa,
    /// bir saldırganın izlerini gizlemek için sildiği bir nesne (veya operasyonel bir hata)
    /// kalıcı olarak kaybolur, adli inceleme (forensics) ve kurtarma imkanı ortadan kalkar.
    /// </summary>
    public sealed class RecycleBinNotEnabledRule : IForestComplianceRule
    {
        public string RuleId => "AD-031";

        public string Name => "AD Recycle Bin (Silinen Öğeler Kutusu) Devre Dışı";

        public string Description => "Forest seviyesinde AD Recycle Bin özelliği etkinleştirilmemiş. Bu özellik kapalıyken silinen bir AD nesnesi (kasıtlı iz gizleme veya operasyonel hata sonucu) tüm özellikleriyle geri getirilemez - bu hem adli inceleme hem de olağan iş sürekliliği için ciddi bir kayıptır.";

        public string FrameworkMapping => "MITRE ATT&CK T1070 (Indicator Removal)";
        public string Iso27001Mapping => "ISO/IEC 27001:2022 - A.8.13 (Bilgi Yedekleme)";

        public string Remediation => "1. PowerShell ile etkinleştirin: Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target '<forest kök domain adı>'.\n" +
                                     "2. Bu işlem GERİ ALINAMAZ ama tamamen zararsızdır (mevcut hiçbir nesneyi/ayarı etkilemez) - production'da doğrudan etkinleştirilebilir.\n" +
                                     "3. Etkinleştirmeden ÖNCE silinmiş nesneler bu korumadan faydalanamaz - ne kadar erken etkinleştirilirse o kadar iyi.";

        public RuleResult Execute(object directoryData)
        {
            if (directoryData is not ForestOptionalFeatureSettings settings || settings.IsRecycleBinEnabled == null)
            {
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            bool isVulnerable = settings.IsRecycleBinEnabled == false;

            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = isVulnerable,
                RiskLevel = isVulnerable ? "Medium" : "Low",
                AffectedObjects = isVulnerable ? new[] { "Forest genelinde AD Recycle Bin etkin değil" } : System.Array.Empty<string>(),
                Remediation = this.Remediation
            };
        }
    }
}
