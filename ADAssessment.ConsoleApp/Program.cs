using System;
using System.Collections.Generic;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.Infrastructure.Logging;

namespace ADAssessment.ConsoleApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[*] Active Directory Güvenlik Analiz Aracı Başlatılıyor...");
            try
            {
                // 1. Secret Resolver ile Şifresiz/Hardcoded Olmayan Güvenli Konfigürasyon Çözme
                ISecretResolver secretResolver = new EnvironmentSecretResolver();
                LdapConnectionOptions options = secretResolver.ResolveLdapOptions();

                Console.WriteLine($"[*] {options.GetFormattedLdapPath()} adresine Zero Trust LDAPS bağlantısı kuruluyor...");

                var extractor = new LdapDataExtractor(options);
                Console.WriteLine("[*] Kullanıcı verileri sayfalı (paged) olarak çekiliyor...");

                var users = extractor.GetActiveUsers();
                Console.WriteLine($"[+] Başarıyla {users.Count} adet kullanıcı hesabı analiz için çekildi.\n");

                // 2. Kuralların Tanımlanması ve Çalıştırılması
                Console.WriteLine("[*] Güvenlik analizleri başlatılıyor...\n");

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

                // No-Code JSON Kural Deposundan Dinamik Kuralları Yükleme (No-Code Rule Engine)
                var jsonRepository = new JsonRuleRepository();
                var dynamicRules = jsonRepository.LoadRules();
                rules.AddRange(dynamicRules);

                var results = new List<RuleResult>();

                foreach (var rule in rules)
                {
                    var result = rule.Execute(users);
                    results.Add(result);

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

                // 3. Denetim İzleme (Audit Logging) Kaydı
                IAuditLogger auditLogger = new AuditLogger();
                auditLogger.LogAssessment(Environment.UserName, users.Count, results);

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