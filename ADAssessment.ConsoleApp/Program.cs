using System;
using ADAssessment.Infrastructure.Ldap;

namespace ADAssessment.ConsoleApp
{
    internal class Program
    {
        // .NET sisteminin programı başlatmak için aradığı o meşhur statik 'Main' yöntemi
        static void Main(string[] args)
        {
            Console.WriteLine("[*] Active Directory Güvenlik Analiz Aracı Başlatılıyor...");

            try
            {
                // Test amacıyla örnek bir LDAP adresi tanımlıyoruz
                string ldapPath = "LDAP://DC=radyum,DC=local";

                Console.WriteLine($"[*] {ldapPath} adresine bağlantı kuruluyor...");

                // Altyapı katmanındaki veri toplayıcımızı çağırıyoruz
                var extractor = new LdapDataExtractor(ldapPath);

                Console.WriteLine("[*] Kullanıcı verileri sayfalı (paged) olarak çekiliyor...");

                // NOT: Gerçek bir Domain Controller ortamında olmadığınızda bu satır 
                // bağlantı hatası verecektir, bu mimarimizin çalıştığını gösteren beklenen bir durumdur.
                var users = extractor.GetActiveUsers();

                Console.WriteLine($"[+] Başarıyla {users.Count} adet kullanıcı hesabı analiz için çekildi.");
            }
            catch (Exception ex)
            {
                // Bağlantı veya ortam yetersizliği hatalarını güvenli bir şekilde yakalıyoruz
                Console.WriteLine($"[-] Bağlantı Durumu (Beklenen Sonuç): {ex.Message}");
            }

            Console.WriteLine("\n[*] İşlem tamamlandı. Çıkış yapmak için bir tuşa basın...");
            Console.ReadKey();
        }
    }
}