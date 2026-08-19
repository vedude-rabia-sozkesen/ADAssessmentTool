using System;
using System.Collections.Generic;
using System.Linq;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.Infrastructure.Logging;
using ADAssessment.Infrastructure.Smb;
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

                // Bilgisayar (Computer) Nesnesi Verisinin Çekilmesi - kullanıcı taramasından
                // bağımsız bir hata kaynağı, erişilemezse bilgisayar tabanlı kurallar atlanır.
                IReadOnlyList<AdComputerAccount>? computers = null;
                try
                {
                    Console.WriteLine("[*] Bilgisayar nesneleri sayfalı (paged) olarak çekiliyor...");
                    computers = extractor.GetComputerAccounts();
                    Console.WriteLine($"[+] Başarıyla {computers.Count} adet bilgisayar hesabı analiz için çekildi.\n");
                }
                catch (Exception computerEx)
                {
                    Console.WriteLine($"[-] [BİLGİSAYAR UYARISI] Bilgisayar nesnesi verisi okunamadı ({computerEx.Message}). Bilgisayar tabanlı kurallar bu taramada atlanacak.\n");
                }

                // LDAP Protokol Güvenliği Kontrolü - gerçek bir bağlantı denemesi içerdiğinden
                // (LDAP signing zorunlu mu), aynı sebeple izole edilir.
                LdapProtocolSecuritySettings? ldapProtocolSecurity = null;
                try
                {
                    Console.WriteLine("[*] DC'nin LDAP protokol güvenliği (signing) kontrol ediliyor...");
                    var ldapProtocolChecker = new LdapProtocolSecurityChecker(options);
                    ldapProtocolSecurity = ldapProtocolChecker.CheckProtocolSecurity();
                    Console.WriteLine("[+] LDAP protokol güvenliği kontrolü tamamlandı.\n");
                }
                catch (Exception ldapProtocolEx)
                {
                    Console.WriteLine($"[-] [LDAP PROTOKOL UYARISI] LDAP protokol güvenliği kontrol edilemedi ({ldapProtocolEx.Message}). İlgili kurallar bu taramada atlanacak.\n");
                }

                // SMB Protokol Güvenliği Kontrolü (anonim erişim vb.) - aynı sebeple izole edilir.
                SmbProtocolSecuritySettings? smbProtocolSecurity = null;
                try
                {
                    Console.WriteLine("[*] DC'nin SMB protokol güvenliği (anonim erişim) kontrol ediliyor...");
                    var smbProtocolChecker = new SmbProtocolSecurityChecker(options);
                    smbProtocolSecurity = smbProtocolChecker.CheckAnonymousAccess();
                    Console.WriteLine("[+] SMB protokol güvenliği kontrolü tamamlandı.\n");
                }
                catch (Exception smbProtocolEx)
                {
                    Console.WriteLine($"[-] [SMB PROTOKOL UYARISI] SMB protokol güvenliği kontrol edilemedi ({smbProtocolEx.Message}). İlgili kurallar bu taramada atlanacak.\n");
                }

                // DCSync Hakları Kontrolü - domain kökünün DACL'ini okuyan ayrı bir sorgu,
                // aynı sebeple izole edilir.
                DcSyncRightsSettings? dcSyncRights = null;
                try
                {
                    Console.WriteLine("[*] Domain kökünde DCSync hakları kontrol ediliyor...");
                    dcSyncRights = extractor.GetDcSyncRights();
                    Console.WriteLine("[+] DCSync hakları kontrolü tamamlandı.\n");
                }
                catch (Exception dcSyncEx)
                {
                    Console.WriteLine($"[-] [DCSYNC UYARISI] DCSync hakları kontrol edilemedi ({dcSyncEx.Message}). İlgili kurallar bu taramada atlanacak.\n");
                }

                // Domain Fonksiyonel Seviyesi Kontrolü - domain kökünü okuyan ayrı bir
                // sorgu, aynı sebeple izole edilir.
                DomainFunctionalLevelSettings? domainFunctionalLevel = null;
                try
                {
                    Console.WriteLine("[*] Domain fonksiyonel seviyesi kontrol ediliyor...");
                    domainFunctionalLevel = extractor.GetDomainFunctionalLevel();
                    Console.WriteLine("[+] Domain fonksiyonel seviyesi kontrolü tamamlandı.\n");
                }
                catch (Exception functionalLevelEx)
                {
                    Console.WriteLine($"[-] [FONKSİYONEL SEVİYE UYARISI] Domain fonksiyonel seviyesi kontrol edilemedi ({functionalLevelEx.Message}). İlgili kurallar bu taramada atlanacak.\n");
                }

                // Forest Seviyesi Özellik Kontrolü (AD Recycle Bin) - RootDSE + Configuration
                // NC okuyan ayrı bir sorgu, aynı sebeple izole edilir.
                ForestOptionalFeatureSettings? forestFeatures = null;
                try
                {
                    Console.WriteLine("[*] Forest seviyesi özellikler (AD Recycle Bin) kontrol ediliyor...");
                    forestFeatures = extractor.GetForestOptionalFeatures();
                    Console.WriteLine("[+] Forest seviyesi özellik kontrolü tamamlandı.\n");
                }
                catch (Exception forestEx)
                {
                    Console.WriteLine($"[-] [FOREST UYARISI] Forest seviyesi özellikler kontrol edilemedi ({forestEx.Message}). İlgili kurallar bu taramada atlanacak.\n");
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
                    new DesEncryptionAllowedRule(),     // AD-010
                    new SidHistoryPresentRule(),        // AD-025
                    new KrbtgtPasswordAgeRule(),        // AD-027
                    new AesEncryptionNotSupportedRule() // AD-030
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

                var computerRules = new List<IComputerComplianceRule>
                {
                    new StaleComputerAccountsRule(),      // AD-016
                    new ObsoleteOperatingSystemRule(),    // AD-017
                    new StaleComputerPasswordRule(),       // AD-018
                    new ComputerUnconstrainedDelegationRule(),               // AD-024
                    new UnexpectedResourceBasedConstrainedDelegationRule(),  // AD-028
                    new ProtocolTransitionDelegationRule()                   // AD-029
                };

                var ldapProtocolRules = new List<ILdapProtocolComplianceRule>
                {
                    new LdapSigningNotEnforcedRule(),         // AD-019
                    new LdapChannelBindingNotEnforcedRule(),  // AD-020
                    new AnonymousLdapBindAllowedRule()        // AD-021
                };

                var smbProtocolRules = new List<ISmbProtocolComplianceRule>
                {
                    new AnonymousSmbAccessAllowedRule()       // AD-022
                };

                var dcSyncRules = new List<IDcSyncComplianceRule>
                {
                    new UnexpectedDcSyncRightsRule()          // AD-023
                };

                var domainFunctionalLevelRules = new List<IDomainFunctionalLevelComplianceRule>
                {
                    new ObsoleteDomainFunctionalLevelRule()   // AD-026
                };

                var forestRules = new List<IForestComplianceRule>
                {
                    new RecycleBinNotEnabledRule()            // AD-031
                };

                var results = new List<RuleResult>();

                void PrintAndCollect(IComplianceRule rule, RuleResult result)
                {
                    results.Add(result);

                    // "Informational" (örn. SYSVOL/GPO verisi okunamadığı için kural hiç
                    // çalıştırılamadı) durumunu "Sistem Güvenli" olarak göstermek yanıltıcı
                    // olur - kontrol edilemedi ile güvenli bulundu birbirinden ayrılmalı.
                    string riskDurumu = result.RiskLevel == "Informational"
                        ? "KONTROL EDİLEMEDİ (Veri Sağlanamadı)"
                        : result.IsVulnerable ? "ZAFİYET BULUNDU!" : "Sistem Güvenli";

                    Console.WriteLine("==================================================");
                    Console.WriteLine($"Kural ID: {result.RuleId}");
                    Console.WriteLine($"Kural Adı: {rule.Name}");
                    Console.WriteLine($"Risk Durumu: {riskDurumu}");
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

                // Kurallar farklı kaynaklardan (statik, JSON dosyaları) geldiğinden,
                // yazdırma sırası da RuleId'ye göre sıralanır.
                rules = rules.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).ToList();
                groupPolicyRules = groupPolicyRules.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).ToList();
                computerRules = computerRules.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).ToList();
                ldapProtocolRules = ldapProtocolRules.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).ToList();
                smbProtocolRules = smbProtocolRules.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).ToList();
                dcSyncRules = dcSyncRules.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).ToList();
                domainFunctionalLevelRules = domainFunctionalLevelRules.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).ToList();
                forestRules = forestRules.OrderBy(r => r.RuleId, StringComparer.OrdinalIgnoreCase).ToList();

                foreach (var rule in rules)
                {
                    PrintAndCollect(rule, rule.Execute(users));
                }

                foreach (var rule in groupPolicyRules)
                {
                    PrintAndCollect(rule, rule.Execute(groupPolicies!));
                }

                foreach (var rule in computerRules)
                {
                    PrintAndCollect(rule, rule.Execute(computers!));
                }

                foreach (var rule in ldapProtocolRules)
                {
                    PrintAndCollect(rule, rule.Execute(ldapProtocolSecurity!));
                }

                foreach (var rule in smbProtocolRules)
                {
                    PrintAndCollect(rule, rule.Execute(smbProtocolSecurity!));
                }

                foreach (var rule in dcSyncRules)
                {
                    PrintAndCollect(rule, rule.Execute(dcSyncRights!));
                }

                foreach (var rule in domainFunctionalLevelRules)
                {
                    PrintAndCollect(rule, rule.Execute(domainFunctionalLevel!));
                }

                foreach (var rule in forestRules)
                {
                    PrintAndCollect(rule, rule.Execute(forestFeatures!));
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