 using System.Text;
 using AuthService;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using UserDataService.UserService;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using System.Runtime.Serialization.Formatters.Binary;

var builder = WebApplication.CreateBuilder(args);
//string mySecret = Environment.GetEnvironmentVariable("Secret") ?? "none";
//string myIssuer = Environment.GetEnvironmentVariable("Issuer") ?? "none";
var EndPoint = "https://localhost:8201/";
var httpClientHandler = new HttpClientHandler();
httpClientHandler.ServerCertificateCustomValidationCallback =
(message, cert, chain, sslPolicyErrors) => { return true; };
IAuthMethodInfo authMethod =
new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
// Initialize settings. You can also set proxies, custom delegates etc.

var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
{
Namespace = "",
MyHttpClientProviderFunc = handler
=> new HttpClient(httpClientHandler) {
BaseAddress = new Uri(EndPoint)
}
};
IVaultClient vaultClient = new VaultClient(vaultClientSettings);
Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2
.ReadSecretAsync(path: "scrt",
mountPoint: "secret");
var Issuer = kv2Secret.Data.Data["Issuer"];
var Secret = kv2Secret.Data.Data["Secret"];



builder.Services
.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
.AddJwtBearer(options =>
{
options.TokenValidationParameters = new TokenValidationParameters()
{
ValidateIssuer = true,
ValidateAudience = true,
ValidateLifetime = true,
ValidateIssuerSigningKey = true,
ValidIssuer = Issuer.ToString(),
ValidAudience = "http://localhost",
IssuerSigningKey =
new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Secret.ToString()))
};
});


// Add services to the container.
builder.Services.Configure<DatabaseSettings>(
    builder.Configuration.GetSection("UserDatabase"));
builder.Services.AddControllers();
builder.Services.AddSingleton<userService>();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
