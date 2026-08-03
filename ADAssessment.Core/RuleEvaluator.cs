using System;
using System.Collections.Generic;

namespace ADAssessment.Core
{
    /// <summary>
    /// No-Code JSON kurallarındaki dinamik operatörleri ve mantıksal koşulları
    /// AdUserAccount nesneleri üzerinde çalışma zamanında (runtime) değerlendiren motor.
    /// </summary>
    public static class RuleEvaluator
    {
        public static bool IsVulnerable(AdUserAccount user, JsonRuleDefinition rule)
        {
            // Bilgisayar hesaplarını otomatik ele (sonu '$' ile bitenler)
            bool isComputerAccount = !string.IsNullOrEmpty(user.SamAccountName) && user.SamAccountName.EndsWith("$");
            if (!user.IsEnabled || isComputerAccount) return false;

            // 1. BitwiseAND Operatörü (UserAccountControl sorguları için)
            if (rule.Operator.Equals("BitwiseAND", StringComparison.OrdinalIgnoreCase))
            {
                int flagValue = Convert.ToInt32(rule.Value?.ToString());
                int result = user.UserAccountControl & flagValue;

                if (rule.Condition.Equals("NotEqualZero", StringComparison.OrdinalIgnoreCase))
                    return result != 0;
                if (rule.Condition.Equals("EqualsZero", StringComparison.OrdinalIgnoreCase))
                    return result == 0;
            }

            // 2. GreaterThanDays Operatörü (LastLogonTimestamp veya PasswordLastSet tarihleri için)
            if (rule.Operator.Equals("GreaterThanDays", StringComparison.OrdinalIgnoreCase))
            {
                int targetDays = Convert.ToInt32(rule.Value?.ToString());
                DateTime threshold = DateTime.UtcNow.AddDays(-targetDays);

                if (rule.TargetProperty.Equals("LastLogonTimestamp", StringComparison.OrdinalIgnoreCase))
                {
                    return !user.LastLogonTimestamp.HasValue || user.LastLogonTimestamp.Value < threshold;
                }
                if (rule.TargetProperty.Equals("PasswordLastSet", StringComparison.OrdinalIgnoreCase))
                {
                    return user.PasswordLastSet.HasValue && user.PasswordLastSet.Value < threshold;
                }
            }

            // 3. NotEmpty Operatörü (ServicePrincipalNames gibi koleksiyonlar için)
            if (rule.Operator.Equals("NotEmpty", StringComparison.OrdinalIgnoreCase))
            {
                if (rule.TargetProperty.Equals("ServicePrincipalNames", StringComparison.OrdinalIgnoreCase))
                {
                    return user.ServicePrincipalNames != null && user.ServicePrincipalNames.Count > 0;
                }
            }

            return false;
        }
    }
}
