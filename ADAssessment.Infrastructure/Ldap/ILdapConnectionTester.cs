namespace ADAssessment.Infrastructure.Ldap
{
    /// <summary>
    /// Kullanıcının arayüzden girdiği (henüz kaydedilmemiş) AD bağlantı ayarlarının
    /// gerçekten çalışıp çalışmadığını test eder - AdConnectionController'ın "doğrulama
    /// ile bağlan" akışı için. ILdapDataExtractor'dan (asıl veri çekme sorumluluğu) bilerek
    /// ayrı tutulur - farklı bir sorumluluk taşıyan, tek metotluk küçük bir arayüz, testlerde
    /// gerçek bir AD bağlantısına ihtiyaç duymadan sahte (fake) bir implementasyonla
    /// AdConnectionController'ı test edebilmeyi sağlar.
    /// </summary>
    public interface ILdapConnectionTester
    {
        bool TestConnection(LdapConnectionOptions options);
    }
}
