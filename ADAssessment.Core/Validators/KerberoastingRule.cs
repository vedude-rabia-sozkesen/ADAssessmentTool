using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{

    /// Active Directory ortamlarında Kerberoasting (T1558.003) saldırılarına karşı 
    /// potansiyel risk barındıran servis hesaplarını (SPN tanımlı) tespit eden kural sınıfı.

    public sealed class KerberoastingRule : IComplianceRule
    {
        // Kuralın benzersiz kimlik kodu
        public string RuleId => "AD-001";

        // Kuralın kısa adı
        public string Name => "Kerberoasting Riski Barındıran Hesaplar";

        // Güvenlik ekibinin anlayacağı detaylı açıklama
        public string Description => "Sistemde Service Principal Name (SPN) tanımı olan, ancak hassas gruplara üye veya zayıf yapılandırılmış hesaplar Kerberoasting saldırılarına karşı açık hedef oluşturur.";

        // MITRE ATT&CK matrisindeki karşılığı
        public string FrameworkMapping => "MITRE ATT&CK T1558.003 (Credential Access)";

        // Sistem yöneticileri için adım adım sıkılaştırma (Hardening) kılavuzu
        public string Remediation => "1. Kullanılmayan SPN kayıtlarını temizleyin.\n" +
                                     "2. Aktif servis hesaplarının parolalarını en az 25 karakterli, karmaşık hale getirin.\n" +
                                     "3. Mümkünse Group Managed Service Accounts (gMSA) mimarisine geçiş yapın.";

        /// Altyapı katmanından gelen kullanıcı listesini analiz eden ana iş mantığı.
        /// <param name="directoryData">Ham Active Directory kullanıcı listesi (IEnumerable-AdUserAccount).</param>
        /// <returns>Analiz sonuçlarını barındıran RuleResult nesnesi.</returns>
        public RuleResult Execute(object directoryData)
        {
            // Gevşek bağlılık (Loose Coupling) gereği gelen nesneyi güvenli bir şekilde listeye cast ediyoruz
            if (directoryData is not IEnumerable<AdUserAccount> userList)
            {
                // Geçersiz veri tipi gelirse sistemi patlatmak yerine güvenli boş sonuç dönüyoruz
                return new RuleResult
                {
                    RuleId = this.RuleId,
                    IsVulnerable = false,
                    RiskLevel = "Informational",
                    Remediation = "Analiz edilecek geçerli veri sağlanamadı."
                };
            }

            var vulnerableAccounts = new List<string>();

            // Performans kritik döngü: Tüm kullanıcıları tarıyoruz
            // Performans kritik döngü: Tüm kullanıcıları tarıyoruz
            foreach (var user in userList)
            {
                // KESİNTİSİZ SİBER GÜVENLİK FİLTRESİ:
                // 1. Hesap aktif olacak (IsEnabled)
                // 2. Üzerinde en az 1 tane SPN tanımı olacak (ServicePrincipalNames.Count > 0)
                // 3. Bilgisayar hesabı OLMAYACAK (SamAccountName sonu '$' ile bitenler bilgisayar hesabıdır, eliyoruz)

                bool isComputerAccount = !string.IsNullOrEmpty(user.SamAccountName) && user.SamAccountName.EndsWith("$"); //olası null başvuru uyarısından dolayı ilk koşulu ekledik
                bool hasSpn = user.ServicePrincipalNames != null && user.ServicePrincipalNames.Count > 0;

                if (user.IsEnabled && hasSpn && !isComputerAccount)
                {
                    // Riski daha da detaylandırıyoruz: Eğer bu SPN'li hesap aynı zamanda AdminCount=1 ise
                    // bu en yüksek öncelikli (Critical) risktir.
                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]" : "[STANDART SERVİS]";

                    vulnerableAccounts.Add($"{riskDetail} {user.SamAccountName} (SPN Sayısı: {user.ServicePrincipalNames?.Count ?? 0})");
                }
            }

            // Bulgulara göre sonucu sarmalayıp üst katmana iletiyoruz
            return new RuleResult
            {
                RuleId = this.RuleId,
                IsVulnerable = vulnerableAccounts.Count > 0,
                // Eğer riskli hesap bulunduysa kritikliği 'High' (Yüksek) çekiyoruz
                RiskLevel = vulnerableAccounts.Count > 0 ? "High" : "Low",
                AffectedObjects = vulnerableAccounts,
                Remediation = this.Remediation
            };
        }
    }
}