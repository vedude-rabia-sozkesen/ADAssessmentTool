namespace ADAssessment.Core
{
    //AD üzerinde çalıştırılacak tüm kuralların türemesi gereken temel kontrat (arayüz)
    public interface IComplianceRule
    {
        //kuralın benzersiz kimlik kodu. raporlama ve filtreleme süreçlerinde kullanılır.
        string RuleId { get; }
        string Name { get; }
        string Description { get; }
        //kuralın eşleştiği siber güvenlik çerçevesi (Örn: CIS Controls v8)
        string FrameworkMapping { get; }

        //kuralın eşleştiği ISO/IEC 27001:2022 Ek A (Annex A) kontrol maddesi -
        //Otomatik Compliance Mapping deliverable'ının ISO 27001 kısmı için
        string Iso27001Mapping { get; }

        //ilgili kuralların mantıksal analizini tetikleyen ana metot
        /// <param name = "directoryData">
        //infrastructure katmanından gelen ham ve optimize edilmiş AD verisi
        // bağımlılığı azaltmak için (loose coupling) 'object' olarak kabul edilir
        //<returns> Analiz sonuçlarını, etkilenen nesneleri ve çözüm önerilerini barındıran RuleResult nesnesi
        RuleResult Execute(object directoryData);
    }
}