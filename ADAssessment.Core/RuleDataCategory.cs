using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;

namespace ADAssessment.Core
{
    /// <summary>
    /// No-Code (JSON) kural motorunun bilebileceği tüm veri kategorilerinin (kullanıcı,
    /// bilgisayar, GPO, LDAP/SMB protokol, DCSync, domain/forest ayarları, trust) TEK
    /// doğruluk kaynağı. RuleEvaluator/DynamicComplianceRule ve RulesController'ın yeni
    /// /categories, /schema uç noktaları buradan besleniyor - frontend'in artık elle
    /// bakımlı, eskiyebilen bir özellik listesi tutmasına gerek kalmıyor (bu, No-Code
    /// alanının daha önce gerçekten yaşanmış bir hatasıydı: HTML dropdown'ı backend'in
    /// desteklediği alanların eski bir alt kümesiydi).
    /// </summary>
    public static class RuleDataCategory
    {
        public const string User = "User";
        public const string Computer = "Computer";
        public const string GroupPolicy = "GroupPolicy";
        public const string LdapProtocol = "LdapProtocol";
        public const string SmbProtocol = "SmbProtocol";
        public const string DcSync = "DcSync";
        public const string DomainFunctionalLevel = "DomainFunctionalLevel";
        public const string ForestOptionalFeature = "ForestOptionalFeature";
        public const string Trust = "Trust";

        private sealed record CategoryInfo(
            Type ClrType,
            bool IsListBased,
            string? IdentifierProperty,
            string SingleObjectLabel,
            string DisplayLabel,
            string GroupLabel);

        private static readonly Dictionary<string, CategoryInfo> Categories = new(StringComparer.OrdinalIgnoreCase)
        {
            [User] = new(typeof(AdUserAccount), true, nameof(AdUserAccount.SamAccountName), "",
                "Kullanıcı Hesabı", "Kullanıcı Hesapları"),
            [Computer] = new(typeof(AdComputerAccount), true, nameof(AdComputerAccount.SamAccountName), "",
                "Bilgisayar Hesabı", "Cihazlar (Bilgisayarlar)"),
            [GroupPolicy] = new(typeof(GroupPolicySecuritySettings), true, nameof(GroupPolicySecuritySettings.GpoName), "",
                "Grup İlkesi (Parola/Kilitleme Politikası)", "AD Ayarları"),
            [Trust] = new(typeof(AdTrustRelationship), true, nameof(AdTrustRelationship.TrustPartner), "",
                "Trust İlişkisi", "AD Ayarları"),
            [LdapProtocol] = new(typeof(LdapProtocolSecuritySettings), false, null, "LDAP Protokol Güvenliği",
                "LDAP Protokol Güvenliği", "AD Ayarları"),
            [SmbProtocol] = new(typeof(SmbProtocolSecuritySettings), false, null, "SMB Protokol Güvenliği",
                "SMB Protokol Güvenliği", "AD Ayarları"),
            [DcSync] = new(typeof(DcSyncRightsSettings), false, null, "DCSync Hakları",
                "DCSync Hakları", "AD Ayarları"),
            [DomainFunctionalLevel] = new(typeof(DomainFunctionalLevelSettings), false, null, "Domain Fonksiyonel Seviyesi",
                "Domain Fonksiyonel Seviyesi", "AD Ayarları"),
            [ForestOptionalFeature] = new(typeof(ForestOptionalFeatureSettings), false, null, "Forest Özellikleri",
                "Forest Özellikleri (ör. Recycle Bin)", "AD Ayarları"),
        };

        /// <summary>Boş/null bir kategori adını her zaman "User"a (geriye dönük uyumluluk) çevirir.</summary>
        public static string Normalize(string? category) => string.IsNullOrWhiteSpace(category) ? User : category;

        public static bool IsValid(string? category) => Categories.ContainsKey(Normalize(category));

        public static Type? GetClrType(string category) => Categories.TryGetValue(category, out var info) ? info.ClrType : null;

        public static bool IsListBased(string category) => !Categories.TryGetValue(category, out var info) || info.IsListBased;

        public static string? GetIdentifierProperty(string category) => Categories.TryGetValue(category, out var info) ? info.IdentifierProperty : null;

        public static string GetSingleObjectLabel(string category) => Categories.TryGetValue(category, out var info) ? info.SingleObjectLabel : category;

        public static string GetDisplayLabel(string category) => Categories.TryGetValue(category, out var info) ? info.DisplayLabel : category;

        public static string GetGroupLabel(string category) => Categories.TryGetValue(category, out var info) ? info.GroupLabel : category;

        public static IReadOnlyList<string> AllCategories => Categories.Keys.ToList();

        /// <summary>
        /// Bir kategorinin CLR tipindeki tüm public örnek özelliklerinin adlarını
        /// (computed/expression-bodied özellikler dahil - reflection için hepsi normal
        /// birer property'dir) döner. No-Code formunun "Hedef Özellik" dropdown'ı bu
        /// listeden üretilir - RuleEvaluator'ın gerçekte hangi alanları çözebildiğiyle
        /// birebir aynı kaynaktan geldiğinden asla birbirinden sapamaz (drift).
        /// </summary>
        public static IReadOnlyList<string> GetPropertyNames(string category)
        {
            var type = GetClrType(category);
            if (type == null) return Array.Empty<string>();

            return type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Select(p => p.Name)
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }
}
