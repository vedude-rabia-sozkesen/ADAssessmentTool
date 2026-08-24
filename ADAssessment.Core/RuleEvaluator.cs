using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;

namespace ADAssessment.Core
{
    /// <summary>
    /// No-Code JSON kurallarındaki gelişmiş operatörleri, tüm veri kategorilerinin (kullanıcı,
    /// bilgisayar, GPO, LDAP/SMB protokol, DCSync, domain/forest ayarları, trust)
    /// özniteliklerini ve iç içe (AND/OR) mantıksal koşul ağaçlarını runtime'da değerlendiren
    /// esnek motor. Özellik çözümlemesi reflection ile yapılır (bkz. GetPropertyValue) - bu
    /// sayede yeni bir veri kategorisi eklendiğinde bu dosyada hiçbir değişiklik gerekmez,
    /// sadece RuleDataCategory registry'sine bir kayıt eklemek yeterlidir.
    /// </summary>
    public static class RuleEvaluator
    {
        // No-Code kurallardaki RegexMatch operatörü dışarıdan (JSON dosyası/API) gelen bir
        // desen kullanır. Kötü niyetli/dikkatsiz bir desen (catastrophic backtracking) tüm
        // kullanıcı listesi üzerinde ReDoS'a yol açabileceğinden sabit bir timeout uygulanır.
        private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(200);

        /// <summary>
        /// dataObject artık AdUserAccount'a değil, herhangi bir RuleDataCategory tipine
        /// (AdComputerAccount, LdapProtocolSecuritySettings vb.) ait olabilir - imza
        /// AdUserAccount'tan object'e geçse de, AdUserAccount zaten geçerli bir object
        /// olduğundan TÜM mevcut çağrı yerleri (AdUserAccount geçenler) değişmeden derlenir.
        /// </summary>
        public static bool IsVulnerable(object dataObject, JsonRuleDefinition rule)
        {
            // Kullanıcı hesabına özgü ön-filtre (disabled/bilgisayar hesabı atlama) SADECE
            // "User" kategorisinde uygulanır - diğer kategorilerin böyle bir kavramı yok.
            if (string.Equals(RuleDataCategory.Normalize(rule.DataCategory), RuleDataCategory.User, StringComparison.OrdinalIgnoreCase)
                && dataObject is AdUserAccount user)
            {
                bool isComputerAccount = !string.IsNullOrEmpty(user.SamAccountName) && user.SamAccountName.EndsWith("$");
                if (!user.IsEnabled || isComputerAccount) return false;
            }

            // Eğer çoklu/nested koşul ağacı tanımlanmışsa recursive değerlendir
            if (rule.Conditions != null && rule.Conditions.Count > 0)
            {
                return EvaluateConditions(dataObject, rule.Conditions, rule.LogicalOperator);
            }

            // Tekli koşul değerlendirmesi
            return EvaluateSingleCondition(dataObject, rule.TargetProperty, rule.Operator, rule.Value, rule.Condition);
        }

        private static bool EvaluateConditions(object dataObject, List<RuleConditionNode> conditions, string logicalOperator)
        {
            bool isAnd = string.Equals(logicalOperator, "AND", StringComparison.OrdinalIgnoreCase);

            foreach (var node in conditions)
            {
                bool result;
                if (node.Conditions != null && node.Conditions.Count > 0)
                {
                    result = EvaluateConditions(dataObject, node.Conditions, node.LogicalOperator);
                }
                else
                {
                    result = EvaluateSingleCondition(dataObject, node.TargetProperty, node.Operator, node.Value, node.Condition);
                }

                if (isAnd && !result) return false;
                if (!isAnd && result) return true;
            }

            return isAnd;
        }

        private static bool EvaluateSingleCondition(object dataObject, string propertyName, string op, object? rawValue, string conditionStr)
        {
            if (string.IsNullOrWhiteSpace(propertyName) || string.IsNullOrWhiteSpace(op)) return false;

            object? propVal = GetPropertyValue(dataObject, propertyName);
            string valStr = rawValue?.ToString() ?? string.Empty;

            // 1. BitwiseAND - hedef özelliğin (TargetProperty ile belirtilen, artık sadece
            // UserAccountControl değil ANY int alan olabilir - ör. AdTrustRelationship.
            // TrustAttributes) tamsayı değeri üzerinde çalışır.
            if (op.Equals("BitwiseAND", StringComparison.OrdinalIgnoreCase))
            {
                int propInt = propVal != null ? Convert.ToInt32(propVal) : 0;
                int flagValue = Convert.ToInt32(valStr);
                int bitResult = propInt & flagValue;

                if (conditionStr.Equals("EqualsZero", StringComparison.OrdinalIgnoreCase)) return bitResult == 0;
                return bitResult != 0; // Default: NotEqualZero
            }

            // 2. Equals / NotEquals
            if (op.Equals("Equals", StringComparison.OrdinalIgnoreCase))
            {
                return EqualsValues(propVal, valStr);
            }
            if (op.Equals("NotEquals", StringComparison.OrdinalIgnoreCase))
            {
                return !EqualsValues(propVal, valStr);
            }

            // 3. Contains / NotContains / StartsWith / EndsWith
            if (op.Equals("Contains", StringComparison.OrdinalIgnoreCase))
            {
                return StringContains(propVal, valStr);
            }
            if (op.Equals("NotContains", StringComparison.OrdinalIgnoreCase))
            {
                return !StringContains(propVal, valStr);
            }
            if (op.Equals("StartsWith", StringComparison.OrdinalIgnoreCase))
            {
                return propVal?.ToString()?.StartsWith(valStr, StringComparison.OrdinalIgnoreCase) ?? false;
            }
            if (op.Equals("EndsWith", StringComparison.OrdinalIgnoreCase))
            {
                return propVal?.ToString()?.EndsWith(valStr, StringComparison.OrdinalIgnoreCase) ?? false;
            }

            // 4. GreaterThan / LessThan
            if (op.Equals("GreaterThan", StringComparison.OrdinalIgnoreCase))
            {
                return CompareNumbers(propVal, valStr) > 0;
            }
            if (op.Equals("LessThan", StringComparison.OrdinalIgnoreCase))
            {
                return CompareNumbers(propVal, valStr) < 0;
            }

            // 5. GreaterThanDays / LessThanDays (Tarihsel günden büyük/küçük)
            if (op.Equals("GreaterThanDays", StringComparison.OrdinalIgnoreCase))
            {
                int targetDays = Convert.ToInt32(valStr);
                DateTime threshold = DateTime.UtcNow.AddDays(-targetDays);
                DateTime? dt = propVal as DateTime?;

                if (propertyName.Equals("LastLogonTimestamp", StringComparison.OrdinalIgnoreCase))
                {
                    return !dt.HasValue || dt.Value < threshold;
                }
                return dt.HasValue && dt.Value < threshold;
            }

            // 6. NotEmpty / IsEmpty
            if (op.Equals("NotEmpty", StringComparison.OrdinalIgnoreCase))
            {
                return !IsEmptyValue(propVal);
            }
            if (op.Equals("IsEmpty", StringComparison.OrdinalIgnoreCase))
            {
                return IsEmptyValue(propVal);
            }

            // 7. RegexMatch
            if (op.Equals("RegexMatch", StringComparison.OrdinalIgnoreCase))
            {
                if (propVal == null) return false;
                try
                {
                    return Regex.IsMatch(propVal.ToString()!, valStr, RegexOptions.IgnoreCase, RegexTimeout);
                }
                catch (RegexMatchTimeoutException)
                {
                    return false;
                }
                catch (ArgumentException)
                {
                    return false;
                }
            }

            return false;
        }

        /// <summary>
        /// Herhangi bir RuleDataCategory nesnesinden (AdUserAccount, AdComputerAccount,
        /// LdapProtocolSecuritySettings vb. - hangisi olduğu önceden bilinmez) reflection
        /// ile özellik değeri okur. BindingFlags.IgnoreCase, önceki elle yazılmış switch'in
        /// case-insensitive davranışını (ör. "UserAccountControl" == "useraccountcontrol")
        /// korur. Computed/expression-bodied özellikler (ör. IsEnabled => ...) reflection
        /// açısından sıradan birer property'dir, ayrı bir işleme gerek yoktur.
        /// </summary>
        private static object? GetPropertyValue(object dataObject, string propertyName)
        {
            var property = dataObject.GetType().GetProperty(
                propertyName,
                BindingFlags.Public | BindingFlags.Instance | BindingFlags.IgnoreCase);

            return property?.GetValue(dataObject);
        }

        private static bool EqualsValues(object? propVal, string targetVal)
        {
            if (propVal == null) return string.IsNullOrWhiteSpace(targetVal);
            if (propVal is bool b) return bool.TryParse(targetVal, out bool targetB) && b == targetB;
            return string.Equals(propVal.ToString(), targetVal, StringComparison.OrdinalIgnoreCase);
        }

        private static bool StringContains(object? propVal, string targetVal)
        {
            if (propVal == null) return false;
            if (propVal is IEnumerable<string> list)
            {
                return list.Any(item => item.Contains(targetVal, StringComparison.OrdinalIgnoreCase));
            }
            return propVal.ToString()!.Contains(targetVal, StringComparison.OrdinalIgnoreCase);
        }

        private static int CompareNumbers(object? propVal, string targetVal)
        {
            double val1 = propVal != null ? Convert.ToDouble(propVal) : 0;
            double val2 = double.TryParse(targetVal, out double d) ? d : 0;
            return val1.CompareTo(val2);
        }

        private static bool IsEmptyValue(object? propVal)
        {
            if (propVal == null) return true;
            if (propVal is ICollection col) return col.Count == 0;
            if (propVal is string s) return string.IsNullOrWhiteSpace(s);
            return false;
        }
    }
}
