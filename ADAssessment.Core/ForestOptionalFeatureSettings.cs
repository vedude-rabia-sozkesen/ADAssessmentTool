namespace ADAssessment.Core
{
    /// <summary>
    /// Forest seviyesinde (tüm domain'leri kapsayan) isteğe bağlı Active Directory
    /// özelliklerinin (Optional Features) durumunu temsil eder. Şu an sadece AD Recycle
    /// Bin'i (Silinen Öğeler Kutusu) kapsıyor; ileride başka forest seviyesi özellikler
    /// eklenirse bu model genişletilebilir.
    /// </summary>
    public sealed class ForestOptionalFeatureSettings
    {
        /// null = veri okunamadı (Informational); true/false = gerçek durum.
        public bool? IsRecycleBinEnabled { get; init; }
    }
}
