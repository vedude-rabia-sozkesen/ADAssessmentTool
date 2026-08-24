namespace ADAssessment.WebAPI.Models
{
    /// <summary>
    /// GET /api/adconnection/status yanıtı. Parola KESİNLİKLE hiçbir zaman bu tipte yer
    /// almaz - sadece "yapılandırılmış mı" ve hangi hedefe/hesaba işaret ettiği (parola
    /// hariç) döner.
    /// </summary>
    public sealed class AdConnectionStatusResponse
    {
        public bool Configured { get; set; }
        public string? LdapPath { get; set; }
        public string? Username { get; set; }
    }

    /// <summary>
    /// POST /api/adconnection isteğinin gövdesi - dashboard'daki "AD Bağlantısı" formundan
    /// gelir. RuleListItem deseniyle aynı: WebAPI'ye özgü bir DTO, Core/Infrastructure'ı
    /// (LdapConnectionOptions zaten var, burada tekrar tanımlamaya gerek yok) kirletmez.
    /// </summary>
    public sealed class AdConnectionRequest
    {
        public string LdapPath { get; set; } = string.Empty;
        public string? Username { get; set; }
        public string? Password { get; set; }
        public bool UseLdaps { get; set; } = true;
        public bool AllowUnsecureFallback { get; set; }
    }
}
