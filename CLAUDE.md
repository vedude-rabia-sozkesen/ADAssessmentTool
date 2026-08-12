# CLAUDE.md — Active Directory Security Assessment

## Proje Tanımı

**Amaç:** Şirketin Active Directory (kullanıcı ve yetki yönetim) sistemini agentless (hedef makinelere yazılım kurmadan), sessizce ve iş akışını yavaşlatmadan tarayarak güvenlik açıklarını tespit eden özel bir araç geliştirmek. Kötü yapılandırmaları, saldırganların admin yetkisi çalmak için kullanabileceği gizli yolları, eski zafiyetleri ve global güvenlik standartlarından sapmaları otomatik tespit eder.

**Kritik kısıt — asla değişmez:**
- Araç yalnızca **okuma (read-only)** yapar. Hiçbir sistem ayarını değiştiremez veya silemez.
- **Domain Admin yetkisi gerektirmez.**
- **Sıfır yazma işlemi** — AD veritabanına hiçbir write-operation yapılmaz.
- 4.000+ kullanıcılı, karmaşık kurallara sahip büyük kurumsal ağları kaldırabilecek ölçekte olmalı.

## Mimari ve Teknik Yaklaşım

- **Mimari:** Clean Architecture + SOLID prensipleri. **Plugin-based sistem** — yeni bir güvenlik kuralı/uyumluluk çerçevesi eklemek için çekirdek motora dokunulmaz veya proje yeniden derlenmez; izole bir modül (.dll/paket) eklenir.
- **Teknoloji stack'i:** C# / .NET Core veya Go — Windows API ve LDAP protokolleriyle doğrudan konuşabilmek için, hedef makineye üçüncü parti bağımlılık zorlamadan.
- **Veri çekme:**
  - LDAP sorguları **paginated (sayfalanmış)** olmalı — binlerce kullanıcı profili çekilirken ağı çökertmemek/RAM taşırmamak için küçük parçalar halinde.
  - **SYSVOL parsing** — Windows SYSVOL paylaşımından Group Policy dosyaları doğrudan okunup parola kuralları, kullanıcı izinleri, temel registry ayarları kontrol edilir.
- **Analiz motoru:** Toplanan veri, bellek içinde (in-memory) çalışan **detached bir Rule Engine** tarafından işlenir. Ham veri, standart arayüzlerle (örn. `IComplianceRule`) eşleştirilerek zafiyetler işaretlenir.
- **CI/CD hazırlığı:** Kod tabanı, yeni tehditler ortaya çıktıkça sistemi bozmadan yeni kuralların otomatik test/deploy edilebileceği şekilde yapılandırılmalı.
- **AI destekli geliştirme yaklaşımı:** Kod tek seferde değil, **adım adım, modül modül prompting** ile üretilecek — hayal ürünü (hallucinated) kod üretimini engellemek ve kodu temiz tutmak için.

## Beklenen Çıktılar (Deliverables)

- **Actionable Security Intelligence:** Kerberoasting zafiyetleri, eski/pasif ayrıcalıklı hesaplar, zayıf erişim kontrolleri gibi riskler; kritiklik derecesine göre önceliklendirilmiş.
- **Otomatik Compliance Mapping:** Tespit edilen zafiyetlerin ISO 27001 gibi global çerçevelere otomatik eşlenmesi.
- **Standardize Raporlama:**
  - Yönetici raporu: HTML/PDF, yüksek seviye güvenlik skorları, grafikler, görsel risk göstergeleri.
  - Teknik çıktı: JSON/XML, mevcut SIEM sistemlerine doğrudan entegre edilebilir.

## Zero-Trust Gerekçesi (Projenin Stratejik Amacı)

Bu araç, şirketin en hassas verisi olan kimlik/erişim altyapısının **hiçbir zaman yerel ağın dışına çıkmaması** için özel olarak geliştiriliyor. Üçüncü parti araçların veri sızıntısı, tedarik zinciri zafiyeti veya gizli telemetri riskini ortadan kaldırmak, projenin var oluş nedenlerinden biri. Bu nedenle:

- Geliştirme sürecinde **dış servislere veri göndermeyen** (telemetry, analytics, dış API çağrısı vb.) bir yaklaşım tercih edilmeli.
- Üçüncü parti kütüphane/paket eklerken kaynağı ve veri toplama davranışı gözden geçirilmeli.
- Kod içine gerçek domain adı, sunucu adı, IP, kullanıcı adı gibi gerçek kurumsal veriler **asla hardcode edilmemeli** — örnek/test verileri kullanılmalı.

## Çalışma Kuralları (Claude Code için bağlayıcı talimatlar)

1. **Bu dosyadaki proje tanımı ve kısıtlar her zaman referans noktasıdır.** Herhangi bir kod değişikliği, öneri veya yeni özellik bu tanımla çelişemez.
2. **Tanımdan sapma gerektiren bir durum ortaya çıkarsa**, doğrudan değişiklik yapılmaz. Bunun yerine şu formatta soru sorulur:
   > "Proje tanımında ... demişsiniz ancak ... yaparsak daha iyi olur, değerlendirmek ister misiniz?"
3. **Onay verilmeden hiçbir değişiklik uygulanmaz.**
4. **Onay verildikten ve değişiklik yapıldıktan sonra**, şu formatta uyarı yapılır:
   > "Bana verdiğin tanımdan ... yönlerinden farklılaştık."
5. **Her aşamada zero-trust yaklaşımıyla** revizeler/eklemeler yapılır — yeni bir bağımlılık, entegrasyon veya veri akışı eklenmeden önce güvenlik riski değerlendirilir.
6. **Her önemli aşamada**, o noktadaki potansiyel güvenlik riski ve alınan/alınması gereken önlem ayrıca belirtilir.
7. Araç **read-only** ilkesini ihlal edebilecek (yazma, silme, değiştirme içeren) hiçbir kod önerisi yapılmaz; böyle bir gereksinim ortaya çıkarsa madde 2'deki onay süreci işletilir.