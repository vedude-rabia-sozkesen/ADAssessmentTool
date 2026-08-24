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
    /// gelir. Kullanıcının LDAP path söz dizimini (LDAP://, DC=... vb.) hiç bilmesine
    /// gerek kalmasın diye DcHostname/IpAddress ayrı alanlar olarak istenir;
    /// AdConnectionController bunlardan LdapConnectionOptions.LdapPath'i inşa eder
    /// (bkz. LdapPathBuilder). RuleListItem deseniyle aynı: WebAPI'ye özgü bir DTO.
    /// </summary>
    public sealed class AdConnectionRequest
    {
        /// <summary>Tam nitelikli (FQDN) DC sunucu adı, ör. "DC01.sirketiniz.local" - domain DN'i buradan çıkarılır.</summary>
        public string DcHostname { get; set; } = string.Empty;

        /// <summary>DC'ye gerçekten bağlanılacak IP adresi.</summary>
        public string IpAddress { get; set; } = string.Empty;

        public string? Username { get; set; }
        public string? Password { get; set; }
        public bool UseLdaps { get; set; } = true;
        public bool AllowUnsecureFallback { get; set; }
    }
}
