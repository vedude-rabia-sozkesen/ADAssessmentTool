namespace ADAssessment.Core
{
    /// <summary>
    /// Bu domain'in başka bir domain/forest ile kurduğu güven ilişkisini (trust) temsil
    /// eder. Active Directory'de bir "trustedDomain" nesnesinden okunur.
    /// </summary>
    public sealed class AdTrustRelationship
    {
        public string TrustPartner { get; init; } = string.Empty;

        /// 1=Inbound, 2=Outbound, 3=Bidirectional.
        public int TrustDirection { get; init; }

        /// 1=Downlevel (NT4), 2=Uplevel (AD), 3=MIT (Kerberos realm), 4=DCE.
        public int TrustType { get; init; }

        /// trustAttributes ham bitmask değeri.
        public int TrustAttributes { get; init; }

        /// TRUST_ATTRIBUTE_WITHIN_FOREST (0x20) - aynı forest içindeki parent/child
        /// domain'ler arası trust'lar bu bayrağı taşır. Bu tür trust'larda SID History'nin
        /// forest içinde serbestçe dolaşması TASARIM GEREĞİ beklenen/güvenilir bir
        /// durumdur - SID filtering kavramı bunlara uygulanmaz.
        public bool IsWithinForest => (TrustAttributes & 0x20) != 0;

        /// TRUST_ATTRIBUTE_QUARANTINED_DOMAIN (0x4) - SID filtering (karantina) etkin mi.
        /// Etkin değilse, güvenilen (trusted) domain'deki bir saldırgan, sIDHistory'sine bu
        /// domain'in bir SID'ini (ör. Domain Admins) ekleyerek buraya sınır ötesi
        /// ayrıcalık yükseltmesi yapabilir.
        public bool IsSidFilteringEnabled => (TrustAttributes & 0x4) != 0;
    }
}
