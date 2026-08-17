using System.Collections.Generic;
using ADAssessment.Core;

namespace ADAssessment.Infrastructure.Sysvol
{
    /// <summary>
    /// SYSVOL üzerindeki Group Policy güvenlik ayarlarını (parola/kilitleme politikası)
    /// okuyan bileşenin soyutlaması.
    /// </summary>
    public interface ISysvolDataExtractor
    {
        IReadOnlyList<GroupPolicySecuritySettings> GetSecuritySettings();
    }
}
