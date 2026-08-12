namespace ADAssessment.Infrastructure.Configuration
{
    /// <summary>
    /// JWT token imzalama için kullanılan simetrik anahtarı taşıyan konfigürasyon nesnesi.
    /// </summary>
    public sealed class JwtSigningOptions
    {
        public string Key { get; set; } = string.Empty;
    }
}
