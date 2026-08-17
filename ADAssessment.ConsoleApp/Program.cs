using System;
using System.Collections.Generic;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.Infrastructure.Logging;
using ADAssessment.Infrastructure.Sysvol;

namespace ADAssessment.ConsoleApp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length > 0 && string.Equals(args[0], "hash-password", StringComparison.OrdinalIgnoreCase))
            {
                RunHashPasswordCommand();
                return;
            }

            if (args.Length > 0 && string.Equals(args[0], "verify-audit-log", StringComparison.OrdinalIgnoreCase))
            {
                string? path = args.Length > 1 ? args[1] : null;
                RunVerifyAuditLogCommand(path);
                return;
            }

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

                // SYSVOL/GPO Verisinin Çekilmesi - LDAP'tan bağımsız bir hata kaynağı,
                // erişilemezse GPO tabanlı kurallar sadece "veri sağlanamadı" der,
                // kullanıcı bazlı tarama etkilenmez.
                IReadOnlyList<GroupPolicySecuritySettings>? groupPolicies = null;
                try
                {
                    Console.WriteLine("[*] SYSVOL üzerinden Group Policy güvenlik ayarları okunuyor...");
                    var sysvolExtractor = new SysvolDataExtractor(options);
                    groupPolicies = sysvolExtractor.GetSecuritySettings();
                    Console.WriteLine($"[+] {groupPolicies.Count} adet GPO güvenlik politikası okundu.\n");
                }
                catch (Exception sysvolEx)
                {
                    Console.WriteLine($"[-] [SYSVOL UYARISI] Group Policy verisi okunamadı ({sysvolEx.Message}). GPO tabanlı kurallar bu taramada atlanacak.\n");
                }

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

                var groupPolicyRules = new List<IGroupPolicyComplianceRule>
                {
                    new WeakPasswordPolicyRule(),                    // AD-013
                    new ReversiblePasswordEncryptionPolicyRule(),    // AD-014
                    new WeakLockoutPolicyRule()                      // AD-015
                };

                var results = new List<RuleResult>();

                void PrintAndCollect(IComplianceRule rule, RuleResult result)
                {
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

                foreach (var rule in rules)
                {
                    PrintAndCollect(rule, rule.Execute(users));
                }

                foreach (var rule in groupPolicyRules)
                {
                    PrintAndCollect(rule, rule.Execute(groupPolicies!));
                }

                // 3. Denetim İzleme (Audit Logging) Kaydı
                IAuditLogger auditLogger = new AuditLogger();
                auditLogger.LogAssessment(Environment.UserName, users.Count, results);

            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] Bir Hata Oluştu: {ex.Message}");
            }

            Console.WriteLine("\n[*] İşlem tamamlandı.");

            // Standart giriş yönlendirilmemişse (interaktif terminal) kullanıcıdan tuşa
            // basmasını bekle; otomasyon/CI/scheduled task gibi non-interactive çalıştırmalarda
            // (stdin redirected) ReadKey() istisna fırlatacağından atlanır.
            if (!Console.IsInputRedirected)
            {
                Console.WriteLine("Çıkış yapmak için bir tuşa basın...");
                Console.ReadKey();
            }
        }

        /// <summary>
        /// Production ortamında WebAPI için AD_ASSESSMENT_API_PASSWORD_HASH ortam
        /// değişkenine set edilecek PBKDF2 hash'ini üretmek üzere kullanılan yardımcı
        /// komut. Parola ekrana yazdırılmadan (maskelenerek) okunur.
        /// Kullanım: ADAssessment.ConsoleApp.exe hash-password
        /// </summary>
        // OWASP A07 (Identification & Authentication Failures) gereği: aracın kendi
        // dashboard hesabı için asgari parola uzunluğu zorunlu kılınır. Bu, dashboard'a
        // erişimi olan bir servis/yönetici hesabı için makul bir alt sınırdır.
        private const int MinPasswordLength = 12;

        private static void RunHashPasswordCommand()
        {
            Console.WriteLine("[*] AD_ASSESSMENT_API_PASSWORD_HASH üretimi.");
            string password = ReadMaskedPassword("Parola girin: ");
            string confirm = ReadMaskedPassword("Parolayı tekrar girin: ");

            if (!string.Equals(password, confirm, StringComparison.Ordinal))
            {
                Console.WriteLine("[-] Parolalar eşleşmiyor.");
                return;
            }

            if (string.IsNullOrWhiteSpace(password))
            {
                Console.WriteLine("[-] Parola boş olamaz.");
                return;
            }

            if (password.Length < MinPasswordLength)
            {
                Console.WriteLine($"[-] Parola en az {MinPasswordLength} karakter olmalıdır (girilen: {password.Length}).");
                return;
            }

            string hash = PasswordHasher.Hash(password);
            Console.WriteLine("\n[+] AD_ASSESSMENT_API_PASSWORD_HASH ortam değişkenine set edilecek değer:");
            Console.WriteLine(hash);
        }

        /// <summary>
        /// audit_events.log dosyasındaki SHA-256 hash-chain'in (OWASP A09 - denetim izi
        /// bütünlüğü) kırılıp kırılmadığını kontrol eden yardımcı komut.
        /// Kullanım: ADAssessment.ConsoleApp.exe verify-audit-log [dosya-yolu]
        /// </summary>
        private static void RunVerifyAuditLogCommand(string? logFilePath)
        {
            var auditLogger = new AuditLogger(logFilePath);
            AuditLogIntegrityResult result = auditLogger.VerifyIntegrity();

            if (result.IsValid)
            {
                Console.WriteLine($"[+] Denetim izi bütünlüğü doğrulandı. {result.VerifiedEntryCount} kayıt kontrol edildi, zincir sağlam.");
            }
            else
            {
                Console.WriteLine($"[-] DENETIM IZI BÜTÜNLÜĞÜ İHLAL EDİLMİŞ! {result.FailureReason}");
                Environment.ExitCode = 1;
            }
        }

        private static string ReadMaskedPassword(string prompt)
        {
            Console.Write(prompt);

            // Standart girdi bir dosyaya/pipe'a yönlendirilmişse (örn. otomasyon/CI ortamı)
            // ConsoleKeyInfo tabanlı maskeleme kullanılamaz; düz satır okumaya düşülür.
            if (Console.IsInputRedirected)
            {
                // Yönlendirilmiş girişlerde (örn. UTF-8 BOM'lu dosya/pipe) satırın başına
                // sızabilen BOM (U+FEFF) karakteri temizlenir.
                string? line = Console.ReadLine();
                return line == null ? string.Empty : line.TrimStart('﻿');
            }

            var password = new System.Text.StringBuilder();
            ConsoleKeyInfo keyInfo;

            while ((keyInfo = Console.ReadKey(intercept: true)).Key != ConsoleKey.Enter)
            {
                if (keyInfo.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Length--;
                        Console.Write("\b \b");
                    }
                    continue;
                }

                if (!char.IsControl(keyInfo.KeyChar))
                {
                    password.Append(keyInfo.KeyChar);
                    Console.Write('*');
                }
            }

            Console.WriteLine();
            return password.ToString();
        }
    }
}