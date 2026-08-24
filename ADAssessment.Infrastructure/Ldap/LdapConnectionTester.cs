namespace ADAssessment.Infrastructure.Ldap
{
    /// <summary>
    /// ILdapConnectionTester'ın tek gerçek implementasyonu - LdapDataExtractor.TestConnection'a
    /// ince bir sarmalayıcı (thin wrapper). Verilen ayarlarla YENİ, bağımsız bir extractor
    /// örneği oluşturur (DI'daki paylaşılan ILdapDataExtractor'dan bilerek farklı - o örnek
    /// zaten kaydedilmiş/aktif ayarları kullanır, ama burada test edilen ayarlar henüz
    /// kaydedilmemiş, kullanıcının formda yazdığı adaydır).
    /// </summary>
    public sealed class LdapConnectionTester : ILdapConnectionTester
    {
        public bool TestConnection(LdapConnectionOptions options)
        {
            return new LdapDataExtractor(options).TestConnection();
        }
    }
}
