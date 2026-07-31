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
                string ldapPath = "LDAP://192.168.92.100/DC=lab,DC=local"; 
                Console.WriteLine($"[*] {ldapPath} adresine bağlantı kuruluyor...");

                var extractor = new LdapDataExtractor(ldapPath); //ldap verilerini çekmek için 
                Console.WriteLine("[*] Kullanıcı verileri sayfalı (paged) olarak çekiliyor...");

                // Orijinal kodundaki gibi direkt IReadOnlyList<AdUserAccount> dönen metodu çağırıyoruz
                var users = extractor.GetActiveUsers();
                Console.WriteLine($"[+] Başarıyla {users.Count} adet kullanıcı hesabı analiz için çekildi.\n");

                // 2. Kuralların Tanımlanması ve Çalıştırılması
                Console.WriteLine("[*] Güvenlik analizleri başlatılıyor...\n");

                // Tüm kuralları (10 adet) bir listede topluyoruz
                var rules = new List<IComplianceRule>
                {
                    new KerberoastingRule(),            // AD-001
                    new AsRepRoastingRule(),            // AD-002
                    new PasswordNeverExpiresRule(),     // AD-003
                    new PasswordNotRequiredRule(),      // AD-004
                    new StaleUserAccountsRule(),        // AD-005
                    new UnconstrainedDelegationRule(),  // AD-006
                    new StalePasswordRule(),            // AD-007
                    new CannotChangePasswordRule(),     // AD-008
                    new ReversibleEncryptionRule(),     // AD-009
                    new DesEncryptionAllowedRule()      // AD-010
                };

                // Kuralları sırayla döngüye sokup çalıştırıyoruz
                foreach (var rule in rules)
                {
                    var result = rule.Execute(users);

                    Console.WriteLine("==================================================");
                    Console.WriteLine($"Kural ID: {result.RuleId}");
                    Console.WriteLine($"Kural Adı: {rule.Name}");
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
                    Console.WriteLine();
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