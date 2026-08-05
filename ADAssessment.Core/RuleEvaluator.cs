using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace ADAssessment.Core
{
    /// <summary>
    /// No-Code JSON kurallarındaki gelişmiş operatörleri, tüm AD özniteliklerini ve 
    /// iç içe (AND/OR) mantıksal koşul ağaçlarını runtime'da değerlendiren esnek motor.
    /// </summary>
    public static class RuleEvaluator
    {
        public static bool IsVulnerable(AdUserAccount user, JsonRuleDefinition rule)
        {
            // Bilgisayar hesaplarını otomatik ele (sonu '$' ile bitenler)
            bool isComputerAccount = !string.IsNullOrEmpty(user.SamAccountName) && user.SamAccountName.EndsWith("$");
            if (!user.IsEnabled || isComputerAccount) return false;

            // Eğer çoklu/nested koşul ağacı tanımlanmışsa recursive değerlendir
            if (rule.Conditions != null && rule.Conditions.Count > 0)
            {
                return EvaluateConditions(user, rule.Conditions, rule.LogicalOperator);
            }

            // Tekli koşul değerlendirmesi
            return EvaluateSingleCondition(user, rule.TargetProperty, rule.Operator, rule.Value, rule.Condition);
        }

        private static bool EvaluateConditions(AdUserAccount user, List<RuleConditionNode> conditions, string logicalOperator)
        {
            bool isAnd = string.Equals(logicalOperator, "AND", StringComparison.OrdinalIgnoreCase);

            foreach (var node in conditions)
            {
                bool result;
                if (node.Conditions != null && node.Conditions.Count > 0)
                {
                    result = EvaluateConditions(user, node.Conditions, node.LogicalOperator);
                }
                else
                {
                    result = EvaluateSingleCondition(user, node.TargetProperty, node.Operator, node.Value, node.Condition);
                }

                if (isAnd && !result) return false;
                if (!isAnd && result) return true;
            }

            return isAnd;
        }

        private static bool EvaluateSingleCondition(AdUserAccount user, string propertyName, string op, object? rawValue, string conditionStr)
        {
            if (string.IsNullOrWhiteSpace(propertyName) || string.IsNullOrWhiteSpace(op)) return false;

            object? propVal = GetPropertyValue(user, propertyName);
            string valStr = rawValue?.ToString() ?? string.Empty;

            // 1. BitwiseAND
            if (op.Equals("BitwiseAND", StringComparison.OrdinalIgnoreCase))
            {
                int userUac = user.UserAccountControl;
                int flagValue = Convert.ToInt32(valStr);
                int bitResult = userUac & flagValue;

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
                return Regex.IsMatch(propVal.ToString()!, valStr, RegexOptions.IgnoreCase);
            }

            return false;
        }

        private static object? GetPropertyValue(AdUserAccount user, string propertyName)
        {
            return propertyName.ToLowerInvariant() switch
            {
                "useraccountcontrol" => user.UserAccountControl,
                "samaccountname" => user.SamAccountName,
                "displayname" => user.DisplayName,
                "distinguishedname" => user.DistinguishedName,
                "lastlogontimestamp" => user.LastLogonTimestamp,
                "passwordlastset" => user.PasswordLastSet,
                "isadmincountset" => user.IsAdminCountSet,
                "memberofcount" => user.MemberOfCount,
                "serviceprincipalnames" => user.ServicePrincipalNames,
                "ispreauthnotrequired" => user.IsPreauthNotRequired,
                "ispasswordneverexpires" => user.IsPasswordNeverExpires,
                "ispasswordnotrequired" => user.IsPasswordNotRequired,
                "isunconstraineddelegation" => user.IsUnconstrainedDelegation,
                "iscannotchangepassword" => user.IsCannotChangePassword,
                "isreversibleencryptionallowed" => user.IsReversibleEncryptionAllowed,
                "isdesencryptionallowed" => user.IsDesEncryptionAllowed,
                _ => null
            };
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
