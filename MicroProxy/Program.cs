using MicroProxy.Models;
using Microsoft.AspNetCore.ResponseCompression;
using System.IO.Compression;
using static MicroProxy.Models.Configuracao;
using static MicroProxy.Models.Site;
using Microsoft.AspNetCore.Server.Kestrel.Https;

#if !DEBUG
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Net;
#else
using Microsoft.AspNetCore.Server.Kestrel.Core;
#endif

Configuracao configuracao = new();
string[]? codecConteudo = configuracao.CompressionResponse?.Split(',', StringSplitOptions.TrimEntries);

bool https = true;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = configuracao.MinutosValidadeCookie == 0 ? TimeSpan.MaxValue : TimeSpan.FromDays(configuracao.MinutosValidadeCookie);
    options.Cookie.Name = NOME_COOKIE;
    options.Cookie.IsEssential = true;
});
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(builder =>
    {
        builder.WithOrigins(configuracao.AllowOrigins).WithHeaders(configuracao.AllowHeaders).WithMethods(configuracao.AllowMethods);
        if (!configuracao.AllowOrigins.Contains("*")) { builder.AllowCredentials(); }
    });
});

#if !DEBUG
string[]? mensagensLog = null;
https = false;

foreach (string ipStr in configuracao.Ips)
{
    builder.WebHost.ConfigureKestrel((context, serverOptions) =>
    {
        var ipPorta = IpPortaRegex().Match(ipStr);

        if (ipPorta.Success)
        {
            IPAddress ip = IPAddress.Parse(ipPorta.Groups["ipv4"].Success ? ipPorta.Groups["ipv4"].Value : ipPorta.Groups["ipv6"].Value);
            var portaHttp = configuracao.PortaHttpRedirect;
            ushort porta = ushort.Parse(ipPorta.Groups["porta"].Success ? ipPorta.Groups["porta"].Value : "80");

            if (!https)
            {
                if (string.IsNullOrEmpty(configuracao.CertificadoPrivado) || portaHttp != 0)
                {
                    if (string.IsNullOrEmpty(configuracao.CertificadoPrivado) && (ipPorta.Groups["porta"].Success || portaHttp == 0)) { portaHttp = porta; }
                    serverOptions.Listen(ip, portaHttp);
                }
            }

            if (!string.IsNullOrEmpty(configuracao.CertificadoPrivado))
            {
                if (!https && configuracao.SolicitarCertificadoCliente)
                {
                    serverOptions.ConfigureHttpsDefaults(options =>
                    {
                        options.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                        options.AllowAnyClientCertificate();
                    });
                }

                https = true;
                if (porta == 80 && !ipPorta.Groups["porta"].Success) { porta = 443; }

                X509Certificate2? certificado = null;
                string pathArquivoCertificado = ProcessarPath(configuracao.CertificadoPrivado);
                bool certificadoArquivo = File.Exists(pathArquivoCertificado);
                string certificadoPrivado = configuracao.CertificadoPrivado;
                string? chave = ProcessarPath(configuracao.CertificadoPrivadoChave ?? "");
                string? senha = configuracao.CertificadoPrivadoSenha;

                if (certificadoArquivo) { certificado = new(pathArquivoCertificado, senha); }
                else
                {
                    using X509Store x509StoreUsuario = new(StoreLocation.CurrentUser);
                    using X509Store x509StorePC = new(StoreLocation.LocalMachine);

                    x509StoreUsuario.Open(OpenFlags.ReadOnly);
                    x509StorePC.Open(OpenFlags.ReadOnly);

                    var certificados = x509StoreUsuario.Certificates.Union(x509StorePC.Certificates)
                        .Where(c => c.Extensions.Any(e => e is X509EnhancedKeyUsageExtension ekue && ekue.EnhancedKeyUsages["1.3.6.1.5.5.7.3.1"] != null))
                        .OrderByDescending(c => c.NotAfter).ThenByDescending(c => c.NotBefore);

                    try { certificado = certificados.FirstOrDefault(c => c.Subject == certificadoPrivado) ?? certificados.First(c => c.Subject.Contains(certificadoPrivado)); }
                    catch (InvalidOperationException ex) { var e = ex; throw new($"Arquivo ou caminho de certificado \"{certificadoPrivado}\" inválido!", e); }

                    if (mensagensLog == null)
                    {
                        mensagensLog = [.. certificados.Select(c =>  $"{(c.Subject == certificado.Subject ? "(" : "")}Path/Destinatário " +
                                    $"\"{c.Subject}\" - Valido de {c.NotBefore} até {c.NotAfter}{(c.Subject == certificado.Subject ? ")" : "")}")];
                        ExibirLog(mensagensLog, "Certificados de validação de servidor disponíveis:", "; ");
                    }

                    x509StoreUsuario.Close();
                    x509StorePC.Close();
                }

                if (!certificado.HasPrivateKey && chave != null) { certificado = certificado.CopyWithPrivateKey(Utils.CreateRsaFromPem(chave, senha)); }

                serverOptions.Listen(ip, porta, listenOptions => listenOptions.UseHttps(certificado));
            }
        }
    });
}
#else
if (configuracao.SolicitarCertificadoCliente)
{
    builder.Services.Configure<KestrelServerOptions>(options => options.ConfigureHttpsDefaults(options =>
    {
        options.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        options.AllowAnyClientCertificate();
    }));
}
#endif

if (codecConteudo != null && string.Join(',', codecConteudo).Length > 0)
{
    CompressionLevel compressionLevel = (CompressionLevel)(codecConteudo.Length > 1 ? int.Parse(codecConteudo[1]) : 0);

    switch (codecConteudo[0].ToLower())
    {
        case "gzip":
            builder.Services.Configure<GzipCompressionProviderOptions>(optc => optc.Level = compressionLevel);
            builder.Services.AddResponseCompression(option =>
            {
                option.Providers.Add<GzipCompressionProvider>();
                option.EnableForHttps = https;
            });
            break;

        case "brotli":
        case "br":
            builder.Services.Configure<BrotliCompressionProviderOptions>(optc => optc.Level = compressionLevel);
            builder.Services.AddResponseCompression(option =>
            {
                option.Providers.Add<BrotliCompressionProvider>();
                option.EnableForHttps = https;
            });
            break;
    }
}

var app = builder.Build();
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();

lifetime.ApplicationStopping.Register(OnShutdown);

// Configure the HTTP request pipeline.
if (https) { app.UseHttpsRedirection(); }

if (codecConteudo != null && string.Join(',', codecConteudo).Length > 0) { app.UseResponseCompression(); }

app.UseSession();
app.UseCors();
app.Use(async (context, next) => { try { configuracao = new(); } catch { } await next.ProcessarRequisicao(context, configuracao); });

configuracao.Sites.First().ExibirVariaveisDisponiveis();

foreach (var site in configuracao.Sites.Where(s => s.ExePath != null && s.ExePath != "" && s.AutoExec).DistinctBy(s => s.BindUrls)
    .DistinctBy(s => ProcessarPath(s.ExePath!) + ProcessarPath(s.ExePathDiretorio ?? "") + s.ExeArgumentos + s.AutoFechar.ToString() + s.JanelaVisivel.ToString()))
{ site.InicializarExecutavel(); }

await app.RunAsync();

#if !DEBUG
internal partial class Program
{
    [GeneratedRegex(@"(?:(?:(?<ipv4>(?:\d{1,3}\.){3}\d{1,3}))|(?:(?:\[(?=[^]]+\]:))?(?<ipv6>(?:(?:\w{1,4}:){7}\w{1,4})|(?:(?:\w{1,4}:){1,6}:(?:\w{1,4})?)|(?:(?:\w{1,4})?:(?::\w{1,4}){1,6})|(?:::))(?:(?<=\[[^]]+)\](?=:))?))(?::(?<porta>\d{1,5}))?")]
    private static partial Regex IpPortaRegex();
}
#endif