using System;
using System.Collections;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// JSON dosyalarından okunan kural tanımlarını IComplianceRule arayüzüne
    /// dönüştüren dinamik kural sarmalayıcısı (Adapter Pattern). Artık sadece kullanıcı
    /// hesaplarıyla sınırlı değil - _definition.DataCategory'ye (bkz. RuleDataCategory)
    /// göre hangi veri kaynağına (kullanıcı/bilgisayar/GPO/LDAP protokol/... ) karşı
    /// çalışacağını kendisi belirler.
    /// </summary>
    public sealed class DynamicComplianceRule : IComplianceRule
    {
        private readonly JsonRuleDefinition _definition;

        public DynamicComplianceRule(JsonRuleDefinition definition)
        {
            _definition = definition;
        }

        public string RuleId => _definition.RuleId;
        public string Name => _definition.Name;
        public string Description => _definition.Description;
        public string FrameworkMapping => _definition.FrameworkMapping;
        public string Iso27001Mapping => _definition.Iso27001Mapping;

        /// <summary>
        /// Bu kuralı üreten ham JSON tanımı. WebAPI katmanının kuralı listelerken/
        /// düzenlerken (edit formu doldururken) orijinal alanlara erişebilmesi için.
        /// </summary>
        public JsonRuleDefinition Definition => _definition;

        /// <summary>
        /// Bu kuralın hangi veri kategorisine karşı çalıştığı - AssessmentController'ın
        /// bu kuralı doğru veri kaynağına (users/computers/groupPolicies/...) yönlendirmesi
        /// için (bkz. RuleDataCategory.Normalize).
        /// </summary>
        public string DataCategory => RuleDataCategory.Normalize(_definition.DataCategory);

        public RuleResult Execute(object directoryData)
        {
            return RuleDataCategory.IsListBased(DataCategory)
                ? ExecuteListBased(directoryData)
                : ExecuteSingleObjectBased(directoryData);
        }

        /// <summary>
        /// Kullanıcı/bilgisayar/GPO/trust gibi "birden çok nesne" taşıyan kategoriler için:
        /// listedeki her nesne ayrı ayrı değerlendirilir, eşleşenler AffectedObjects'e
        /// eklenir. Tip kontrolü BİLEREK typeof(IEnumerable&lt;&gt;).MakeGenericType(...) ile
        /// yapılır - düz "is IEnumerable" KULLANILMAZ, çünkü string de IEnumerable&lt;char&gt;'dır;
        /// düz kontrol "not a user list" gibi geçersiz bir string'i yanlışlıkla karakterler
        /// listesi olarak işlerdi (mevcut bir testin tam olarak yakaladığı senaryo).
        /// </summary>
        private RuleResult ExecuteListBased(object directoryData)
        {
            Type? elementType = RuleDataCategory.GetClrType(DataCategory);
            Type? enumerableType = elementType != null ? typeof(IEnumerable<>).MakeGenericType(elementType) : null;

            if (enumerableType == null || !enumerableType.IsInstanceOfType(directoryData))
            {
                return Informational();
            }

            bool isUserCategory = string.Equals(DataCategory, RuleDataCategory.User, StringComparison.OrdinalIgnoreCase);
            string? identifierProperty = RuleDataCategory.GetIdentifierProperty(DataCategory);

            var affected = new List<string>();

            foreach (object? item in (IEnumerable)directoryData)
            {
                if (item == null) continue;
                if (!RuleEvaluator.IsVulnerable(item, _definition)) continue;

                // Kullanıcı kategorisinde mevcut "[KRİTİK YETKİLİ]"/"[STANDART HESAP]"
                // etiketleme davranışı aynen korunur (regresyon testi mevcut) - diğer
                // kategoriler için sadece o kategorinin kimlik özniteliği kullanılır.
                if (isUserCategory && item is AdUserAccount user)
                {
                    string riskDetail = user.IsAdminCountSet ? "[KRİTİK YETKİLİ]" : "[STANDART HESAP]";
                    affected.Add($"{riskDetail} {user.SamAccountName}");
                }
                else
                {
                    var label = identifierProperty != null
                        ? item.GetType().GetProperty(identifierProperty)?.GetValue(item)?.ToString()
                        : null;
                    affected.Add(label ?? item.ToString() ?? "?");
                }
            }

            return new RuleResult
            {
                RuleId = RuleId,
                IsVulnerable = affected.Count > 0,
                RiskLevel = affected.Count > 0 ? _definition.RiskLevel : "Low",
                AffectedObjects = affected,
                Remediation = _definition.Remediation
            };
        }

        /// <summary>
        /// LDAP/SMB protokol, DCSync, domain fonksiyonel seviyesi, forest özellikleri gibi
        /// "tek bir olgu/sonuç nesnesi" taşıyan kategoriler için: nesne bir kez değerlendirilir,
        /// zafiyetliyse tek bir açıklayıcı etiket AffectedObjects'e eklenir.
        /// </summary>
        private RuleResult ExecuteSingleObjectBased(object directoryData)
        {
            Type? expectedType = RuleDataCategory.GetClrType(DataCategory);
            if (expectedType == null || !expectedType.IsInstanceOfType(directoryData))
            {
                return Informational();
            }

            bool isVulnerable = RuleEvaluator.IsVulnerable(directoryData, _definition);
            var affected = new List<string>();
            if (isVulnerable)
            {
                affected.Add(RuleDataCategory.GetSingleObjectLabel(DataCategory));
            }

            return new RuleResult
            {
                RuleId = RuleId,
                IsVulnerable = isVulnerable,
                RiskLevel = isVulnerable ? _definition.RiskLevel : "Low",
                AffectedObjects = affected,
                Remediation = _definition.Remediation
            };
        }

        private RuleResult Informational() => new RuleResult
        {
            RuleId = RuleId,
            IsVulnerable = false,
            RiskLevel = "Informational",
            Remediation = "Analiz edilecek geçerli veri sağlanamadı."
        };
    }
}
