using System;
using System.Collections.Generic;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.ConsoleApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[*] Active Directory Güvenlik Analiz Aracı Başlatılıyor...");
            try
            {
                // 1. LDAP Bağlantısı ve Veri Çekme
                string ldapPath = "LDAP://DC=radyum,DC=local"; // Kendi domain yapına göre güncelle
                Console.WriteLine($"[*] {ldapPath} adresine bağlantı kuruluyor...");

                var extractor = new LdapDataExtractor(ldapPath);
                Console.WriteLine("[*] Kullanıcı verileri sayfalı (paged) olarak çekiliyor...");

                // Orijinal kodundaki gibi direkt IReadOnlyList<AdUserAccount> dönen metodu çağırıyoruz
                var users = extractor.GetActiveUsers();
                Console.WriteLine($"[+] Başarıyla {users.Count} adet kullanıcı hesabı analiz için çekildi.\n");

                // 2. Kuralın Örneklendirilmesi (Instantiate)
                Console.WriteLine("[*] Güvenlik analizleri başlatılıyor...");
                var kerberoastingRule = new KerberoastingRule();

                // 3. Kuralın Çalıştırılması (Execute)
                var result = kerberoastingRule.Execute(users);

                // 4. Sonuçların Ekrana Yazdırılması
                Console.WriteLine("==================================================");
                Console.WriteLine($"Kural ID: {result.RuleId}");
                // Orijinal RuleResult modelinde Name olmadığı için kural nesnesinden (kerberoastingRule.Name) çekiyoruz
                Console.WriteLine($"Kural Adı: {kerberoastingRule.Name}");
                Console.WriteLine($"Risk Durumu: {(result.IsVulnerable ? "ZAFİYET BULUNDU!" : "Sistem Güvenli")}");
                Console.WriteLine($"Risk Seviyesi: {result.RiskLevel}");
                Console.WriteLine("==================================================");

                if (result.IsVulnerable)
                {
                    Console.WriteLine("\n[!] Risk Altındaki Hesaplar:");
                    foreach (var affectedObject in result.AffectedObjects)
                    {
                        Console.WriteLine($"  -> {affectedObject}");
                    }

                    Console.WriteLine("\n[*] Çözüm Önerisi:");
                    Console.WriteLine(result.Remediation);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Bir Hata Oluştu: {ex.Message}");
            }

            Console.WriteLine("\n[*] İşlem tamamlandı. Çıkış yapmak için bir tuşa basın...");
            Console.ReadKey();
        }
    }
}