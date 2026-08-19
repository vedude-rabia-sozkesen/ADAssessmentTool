using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Text;
using System.Threading.RateLimiting;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.Infrastructure.Logging;
using ADAssessment.Infrastructure.Smb;
using ADAssessment.Infrastructure.Sysvol;
using ADAssessment.WebAPI.Controllers;

var builder = WebApplication.CreateBuilder(args);

// 1. Controller ve API Hizmetlerini Ekle
// AddXmlSerializerFormatters: SIEM (Security Information and Event Management) sistemlerinin
// çoğu JSON'un yanında XML de kabul eder - istemci "Accept: application/xml" header'ı
// gönderdiğinde ASP.NET Core aynı endpoint'i otomatik olarak XML üretecek şekilde çevirir
// (content negotiation). Sadece ScanResultResponse (AssessmentController) bu formatı hedefler;
// diğer controller'lar anonim tip veya "object" tipli üye içerdiğinden (XmlSerializer'ın
// serileştiremediği tipler) [Produces("application/json")] ile JSON'a sabitlenir.
builder.Services.AddControllers().AddXmlSerializerFormatters();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

// 2. JWT Bearer Kimlik Doğrulama Servisini Yapılandır
// İmzalama anahtarı Zero Trust ISecretResolver deseni ile çözülür: Production'da
// AD_ASSESSMENT_JWT_SECRET tanımlı değilse uygulama başlamaz (fail-closed).
// NOT: Aşağıda DI konteynerine bu ÖRNEĞİN kendisi (AddSingleton<ISecretResolver>(instance))
// kaydedilir - AuthController'ın token imzalarken kullandığı key ile burada doğrulama için
// kullanılan key'in (Development'ta rastgele üretiliyor olabilir) aynı olması bunu gerektirir.
var sharedSecretResolver = new EnvironmentSecretResolver();
var jwtSigningOptions = sharedSecretResolver.ResolveJwtSigningOptions();
var key = Encoding.UTF8.GetBytes(jwtSigningOptions.Key);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment();
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidIssuer = AuthController.TokenIssuer,
        ValidateAudience = true,
        ValidAudience = AuthController.TokenAudience
    };
});

builder.Services.AddAuthorization();

// 3. Zero Trust & Infrastructure Servislerini DI Konteynerine Kaydet
builder.Services.AddSingleton<ISecretResolver>(sharedSecretResolver);
builder.Services.AddSingleton<IAuditLogger, AuditLogger>();
builder.Services.AddSingleton<JsonRuleRepository>();

// Active Directory Data Extractor Servisi
builder.Services.AddScoped<ILdapDataExtractor>(sp =>
{
    var secretResolver = sp.GetRequiredService<ISecretResolver>();
    var options = secretResolver.ResolveLdapOptions();
    return new LdapDataExtractor(options);
});

// SYSVOL/GPO Veri Çekici Servisi - aynı LDAP bağlantı bilgilerini (servis hesabı)
// yeniden kullanır, ayrı env var gerekmez.
builder.Services.AddScoped<ISysvolDataExtractor>(sp =>
{
    var secretResolver = sp.GetRequiredService<ISecretResolver>();
    var options = secretResolver.ResolveLdapOptions();
    return new SysvolDataExtractor(options);
});

// LDAP Protokol Güvenliği Denetleyicisi (LDAP signing zorunluluğu vb.) - yine aynı
// bağlantı bilgilerini yeniden kullanır.
builder.Services.AddScoped<ILdapProtocolSecurityChecker>(sp =>
{
    var secretResolver = sp.GetRequiredService<ISecretResolver>();
    var options = secretResolver.ResolveLdapOptions();
    return new LdapProtocolSecurityChecker(options);
});

// SMB Protokol Güvenliği Denetleyicisi (anonim erişim vb.) - yine aynı bağlantı
// bilgilerini yeniden kullanır.
builder.Services.AddScoped<ISmbProtocolSecurityChecker>(sp =>
{
    var secretResolver = sp.GetRequiredService<ISecretResolver>();
    var options = secretResolver.ResolveLdapOptions();
    return new SmbProtocolSecurityChecker(options);
});

// Tüm Sabit C# Uyum Kurallarını DI'a Kaydet
builder.Services.AddTransient<IComplianceRule, KerberoastingRule>();
builder.Services.AddTransient<IComplianceRule, AsRepRoastingRule>();
builder.Services.AddTransient<IComplianceRule, PasswordNeverExpiresRule>();
builder.Services.AddTransient<IComplianceRule, PasswordNotRequiredRule>();
builder.Services.AddTransient<IComplianceRule, StaleUserAccountsRule>();
builder.Services.AddTransient<IComplianceRule, UnconstrainedDelegationRule>();
builder.Services.AddTransient<IComplianceRule, StalePasswordRule>();
builder.Services.AddTransient<IComplianceRule, CannotChangePasswordRule>();
builder.Services.AddTransient<IComplianceRule, ReversibleEncryptionRule>();
builder.Services.AddTransient<IComplianceRule, DesEncryptionAllowedRule>();
builder.Services.AddTransient<IComplianceRule, SidHistoryPresentRule>();
builder.Services.AddTransient<IComplianceRule, KrbtgtPasswordAgeRule>();
builder.Services.AddTransient<IComplianceRule, AesEncryptionNotSupportedRule>();

// SYSVOL/GPO Tabanlı Uyum Kurallarını DI'a Kaydet
builder.Services.AddTransient<IGroupPolicyComplianceRule, WeakPasswordPolicyRule>();
builder.Services.AddTransient<IGroupPolicyComplianceRule, ReversiblePasswordEncryptionPolicyRule>();
builder.Services.AddTransient<IGroupPolicyComplianceRule, WeakLockoutPolicyRule>();

// Bilgisayar (Computer) Nesnesi Tabanlı Uyum Kurallarını DI'a Kaydet
builder.Services.AddTransient<IComputerComplianceRule, StaleComputerAccountsRule>();
builder.Services.AddTransient<IComputerComplianceRule, ObsoleteOperatingSystemRule>();
builder.Services.AddTransient<IComputerComplianceRule, StaleComputerPasswordRule>();
builder.Services.AddTransient<IComputerComplianceRule, ComputerUnconstrainedDelegationRule>();
builder.Services.AddTransient<IComputerComplianceRule, UnexpectedResourceBasedConstrainedDelegationRule>();
builder.Services.AddTransient<IComputerComplianceRule, ProtocolTransitionDelegationRule>();
builder.Services.AddTransient<IComputerComplianceRule, MissingLapsProtectionRule>();

// LDAP Protokol Güvenliği Tabanlı Uyum Kurallarını DI'a Kaydet
builder.Services.AddTransient<ILdapProtocolComplianceRule, LdapSigningNotEnforcedRule>();
builder.Services.AddTransient<ILdapProtocolComplianceRule, LdapChannelBindingNotEnforcedRule>();
builder.Services.AddTransient<ILdapProtocolComplianceRule, AnonymousLdapBindAllowedRule>();

// SMB Protokol Güvenliği Tabanlı Uyum Kurallarını DI'a Kaydet
builder.Services.AddTransient<ISmbProtocolComplianceRule, AnonymousSmbAccessAllowedRule>();

// DCSync Hakları Tabanlı Uyum Kurallarını DI'a Kaydet
builder.Services.AddTransient<IDcSyncComplianceRule, UnexpectedDcSyncRightsRule>();

// Domain Fonksiyonel Seviyesi Tabanlı Uyum Kurallarını DI'a Kaydet
builder.Services.AddTransient<IDomainFunctionalLevelComplianceRule, ObsoleteDomainFunctionalLevelRule>();

// Forest Seviyesi Özellik Tabanlı Uyum Kurallarını DI'a Kaydet
builder.Services.AddTransient<IForestComplianceRule, RecycleBinNotEnabledRule>();

// Trust İlişkisi Tabanlı Uyum Kurallarını DI'a Kaydet
builder.Services.AddTransient<ITrustComplianceRule, SidFilteringDisabledRule>();

// 4. CORS Politikası — sadece appsettings.json > AllowedOrigins içinde açıkça
// listelenen origin'lere izin verilir. Frontend zaten aynı origin'den (wwwroot)
// serve edildiğinden varsayılan (boş liste) durumda CORS'a gerek yoktur.
string[] allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? Array.Empty<string>();
if (allowedOrigins.Length > 0)
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowFrontend", policy =>
        {
            policy.WithOrigins(allowedOrigins)
                  .WithMethods("GET", "POST")
                  .AllowAnyHeader();
        });
    });
}

// 5. Reverse Proxy Arkasında Barındırma (Hosting) - Kestrel (ASP.NET Core'un yerleşik web
// sunucusu) production'da doğrudan internete/ağa açılmaz; önünde gerçek TLS sertifikasını
// taşıyan bir reverse proxy (IIS, nginx vb.) bulunur, TLS orada sonlandırılır ve istek
// Kestrel'e düz HTTP olarak iletilir. Bu ara katman (middleware) olmadan Kestrel, proxy'den
// gelen isteğin ASLINDA HTTPS olduğunu bilemez - X-Forwarded-Proto/X-Forwarded-For
// başlıklarını (proxy'nin orijinal isteğin şemasını/istemci IP'sini ilettiği standart HTTP
// başlıkları) okuyup HttpContext'i buna göre günceller; aksi halde UseHttpsRedirection/
// UseHsts ve "Secure" cookie/HSTS mantığı proxy arkasında hep "HTTP geldi" sanıp yanlış
// davranır. KnownProxies/KnownNetworks varsayılanı sadece localhost'u (127.0.0.1) güvenilir
// proxy sayar - reverse proxy başka bir sunucuda çalışıyorsa bu IP'nin/ağın burada açıkça
// eklenmesi gerekir (aksi halde spoofing'e karşı güvenlik gereği başlıklar yok sayılır).
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
});

// 6. Login Uç Noktası İçin Rate Limiting (Brute-force koruması)
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("login", opt =>
    {
        opt.PermitLimit = 5;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 0;
    });
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

var app = builder.Build();

// UseForwardedHeaders, pipeline'daki İLK ara katman olmalı - kendisinden sonraki her şey
// (UseHttpsRedirection, UseHsts, kimlik doğrulama) isteğin gerçek şemasını/IP'sini bu
// güncellemeden sonra görmeli.
app.UseForwardedHeaders();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}
else
{
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseDefaultFiles();
app.UseStaticFiles();

if (allowedOrigins.Length > 0)
{
    app.UseCors("AllowFrontend");
}

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
