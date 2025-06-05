using APIContagem;
using Groffe.AspNetCore.ApiKeyChecking;
using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

var headerApiKeyChecking = builder.Configuration["ApiKeyChecking:Header"];
var valueApiKeyChecking = builder.Configuration["ApiKeyChecking:Key"];
bool useApiKeyChecking = (!String.IsNullOrWhiteSpace(headerApiKeyChecking) &&
    !String.IsNullOrWhiteSpace(valueApiKeyChecking));
if (useApiKeyChecking)
    builder.Services.ConfigureApiKeyChecking(headerApiKeyChecking!, valueApiKeyChecking!);

builder.Services.AddControllers();
builder.Services.AddOpenApi();

builder.Services.AddSingleton<Contador>();

builder.Services.AddCors();

var app = builder.Build();

app.MapOpenApi();
app.MapScalarApiReference(options =>
{
    options.Title = "API de Contagem";
    options.Theme = ScalarTheme.BluePlanet;
    options.DarkMode = true;
});

app.UseAuthorization();

app.MapControllers();

app.Run();