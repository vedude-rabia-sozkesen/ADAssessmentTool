using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using ADAssessment.Core;
using ADAssessment.Infrastructure.Configuration;
using ADAssessment.Infrastructure.Ldap;
using ADAssessment.Infrastructure.Logging;
using ADAssessment.WebAPI.Controllers;

var builder = WebApplication.CreateBuilder(args);

// 1. Controller ve API Hizmetlerini Ekle
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddOpenApi();

// 2. JWT Bearer Kimlik Doğrulama Servisini Yapılandır
var key = Encoding.ASCII.GetBytes(AuthController.SecretKey);
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

// 3. Zero Trust & Infrastructure Servislerini DI Konteynerine Kaydet
builder.Services.AddSingleton<ISecretResolver, EnvironmentSecretResolver>();
builder.Services.AddSingleton<IAuditLogger, AuditLogger>();
builder.Services.AddSingleton<JsonRuleRepository>();

// Active Directory Data Extractor Servisi
builder.Services.AddScoped<LdapDataExtractor>(sp =>
{
    var secretResolver = sp.GetRequiredService<ISecretResolver>();
    var options = secretResolver.ResolveLdapOptions();
    return new LdapDataExtractor(options);
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

// 4. CORS Politikası (Frontend Erişimi İçin)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyHeader()
              .AllowAnyMethod();
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseCors("AllowFrontend");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
