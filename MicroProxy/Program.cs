using MicroProxy.Models;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using static MicroProxy.Models.Configuracao;
using static MicroProxy.Models.Site;

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

https = false;

var urls = Environment.GetEnvironmentVariable("ASPNETCORE_URLS")?.Split(';').OrderBy(u => u.StartsWith("https", StringComparison.OrdinalIgnoreCase)).ToArray() ?? configuracao.Ips;
List<(TcpListener listener, X509Certificate2? certificado)> tcpListeners = [];
bool fonteUrlsConfig = urls == configuracao.Ips;
var certificadoStr = fonteUrlsConfig ? configuracao.CertificadoPrivado : null;
List<string> mensagens = [];
List<Task> tarefasListeners = [];

foreach (string url in urls)
{
    var ipPorta = IpPortaRegex().Match(url);
    Uri? uri = fonteUrlsConfig ? null : new Uri(url);

    if (uri != null && string.IsNullOrEmpty(certificadoStr) && uri.Scheme.Equals("https")) { certificadoStr = uri.Host; }

    IPAddress ip = fonteUrlsConfig ? IPAddress.Parse(ipPorta.Groups["ipv4"].Success ? ipPorta.Groups["ipv4"].Value : ipPorta.Groups["ipv6"].Value) : IPAddress.Loopback;
    var portaHttp = fonteUrlsConfig ? configuracao.PortaHttp : 0;
    ushort porta = ushort.Parse(uri == null ? (ipPorta.Groups["porta"].Success ? ipPorta.Groups["porta"].Value : "80") : uri.Port.ToString());

    if (!https)
    {
        if (string.IsNullOrEmpty(certificadoStr) || portaHttp != 0)
        {
            if (string.IsNullOrEmpty(certificadoStr) && (ipPorta.Groups["porta"].Success || portaHttp == 0)) { portaHttp = porta; }
            tcpListeners.Add((new TcpListener(ip, portaHttp), null));
            tcpListeners.Last().listener.Start();
            mensagens.Add($"HTTP listener em {ip}:{portaHttp}");
        }
    }

    if (!string.IsNullOrEmpty(certificadoStr))
    {
        if (porta == 80 && !ipPorta.Groups["porta"].Success) { porta = 443; }
        X509Certificate2? certificado = Utils.ObterCertificado(certificadoStr, configuracao.CertificadoPrivadoSenha, configuracao.CertificadoPrivadoChave
            , Utils.CertificadoEKUOID.Servidor, !https);
        https = true;
        tcpListeners.Add((new TcpListener(ip, porta), certificado));
        tcpListeners.Last().listener.Start();
        mensagens.Add($"HTTPS listener em {ip}:{porta}");
    }
}

foreach (var mensagem in mensagens) { ExibirLog(mensagem); }

foreach (var (listener, certificado) in tcpListeners)
{
    tarefasListeners.Add(Task.Run(async () =>
    {
        while (true)
        {
            using var client = await listener.AcceptTcpClientAsync();
            using var clientStream = client.GetStream();
            using var sslStream = new SslStream(clientStream, false);
            using var streamEmUso = certificado == null ? (Stream)clientStream : sslStream;

            if (certificado != null && streamEmUso is SslStream ssl) { await ssl.AuthenticateAsServerAsync(certificado, false, SslProtocols.Tls12 | SslProtocols.Tls13, true); }

            HttpContextFromListener http = new(streamEmUso);
            http.Request.EnableBuffering();
            using var reader = new StreamReader(http.Request.Body);
            Console.WriteLine(reader.ReadToEnd());
            var resp = "HTTP/1.1 501 Not Implemented\r\n\r\n";
            var respBytes = Encoding.ASCII.GetBytes(resp);
            await streamEmUso.WriteAsync(respBytes);
        }
    }));
}

await Task.WhenAll(tarefasListeners);

/*if (!builder.Environment.IsDevelopment())
{
    foreach (string ipStr in configuracao.Ips)
    {
        builder.WebHost.ConfigureKestrel((context, serverOptions) =>
        {
            var ipPorta = IpPortaRegex().Match(ipStr);

            if (ipPorta.Success)
            {
                IPAddress ip = IPAddress.Parse(ipPorta.Groups["ipv4"].Success ? ipPorta.Groups["ipv4"].Value : ipPorta.Groups["ipv6"].Value);
                var portaHttp = configuracao.PortaHttp;
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
                    https = true;
                    if (porta == 80 && !ipPorta.Groups["porta"].Success) { porta = 443; }
                    X509Certificate2? certificado = Utils.ObterCertificado(configuracao.CertificadoPrivado, configuracao.CertificadoPrivadoSenha, configuracao.CertificadoPrivadoChave
                        , Utils.CertificadoEKUOID.Servidor);
                    serverOptions.Listen(ip, porta, listenOptions => listenOptions.UseHttps(certificado));
                }
            }
        });
    }
}*/

if (configuracao.SolicitarCertificadoCliente && (https || builder.Environment.IsDevelopment()))
{
    builder.Services.Configure<KestrelServerOptions>(options => options.ConfigureHttpsDefaults(options =>
    {
        options.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        options.AllowAnyClientCertificate();
    }));
}

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
if (https && configuracao.RedirectPortaHttp) { app.UseHttpsRedirection(); }
if (codecConteudo != null && string.Join(',', codecConteudo).Length > 0) { app.UseResponseCompression(); }

app.UseSession();
app.UseCors();
//app.Use(async (context, next) => { try { configuracao = new(); } catch { } await next.ProcessarRequisicaoAsync(context, configuracao); });

configuracao.Sites.First().ExibirVariaveisDisponiveis();

foreach (var site in configuracao.Sites.Where(s => s.ExePath != null && s.ExePath != "" && s.AutoExec).DistinctBy(s => s.BindUrls)
    .DistinctBy(s => ProcessarPath(s.ExePath!) + ProcessarPath(s.ExePathDiretorio ?? "") + s.ExeArgumentos + s.AutoFechar.ToString() + s.JanelaVisivel.ToString()))
{ site.InicializarExecutavel(); }

await app.RunAsync();

internal partial class Program
{
    [GeneratedRegex(@"(?:(?:(?<ipv4>(?:\d{1,3}\.){3}\d{1,3}))|(?:(?:\[(?=[^]]+\]:))?(?<ipv6>(?:(?:\w{1,4}:){7}\w{1,4})|(?:(?:\w{1,4}:){1,6}:(?:\w{1,4})?)|(?:(?:\w{1,4})?:(?::\w{1,4}){1,6})|(?:::))(?:(?<=\[[^]]+)\](?=:))?))(?::(?<porta>\d{1,5}))?")]
    private static partial Regex IpPortaRegex();
}