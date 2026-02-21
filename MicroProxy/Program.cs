using MicroProxy.Models;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using static MicroProxy.Models.Configuracao;
using static MicroProxy.Models.Site;

Configuracao configuracao = new();
string[]? codecConteudo = configuracao.CompressionResponse?.Split(',', StringSplitOptions.TrimEntries);

bool https = true;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSingleton<IHttpContextFromListenerAccessor, HttpContextFromListenerAccessor>();
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
            mensagens.Add($"HTTP listener em {ip}:{portaHttp}\n");
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
        mensagens.Add($"HTTPS listener em {ip}:{porta}\n");
    }
}

var app = builder.Build();
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(OnShutdown);
foreach (var mensagem in mensagens) { ExibirLog(mensagem); }
configuracao.Sites.First().ExibirVariaveisDisponiveis();
foreach (var site in configuracao.Sites.Where(s => s.ExePath != null && s.ExePath != "" && s.AutoExec).DistinctBy(s => s.BindUrls)
    .DistinctBy(s => ProcessarPath(s.ExePath!) + ProcessarPath(s.ExePathDiretorio ?? "") + s.ExeArgumentos + s.AutoFechar.ToString() + s.JanelaVisivel.ToString()))
{ site.InicializarExecutavel(); }

foreach (var (listener, certificado) in tcpListeners)
{
    tarefasListeners.Add(Task.Run(async () =>
    {
        while (!app.Lifetime.ApplicationStopping.IsCancellationRequested)
        {
            try
            {
                using var client = await listener.AcceptTcpClientAsync(app.Lifetime.ApplicationStopping);
                using var clientStream = client.GetStream();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(1));

                while (true)
                {
                    if (clientStream.DataAvailable)
                    {
                        using var sslStream = new SslStream(clientStream, false, (sender, cert, chain, errors) => true);
                        using var streamEmUso = certificado == null ? (Stream)clientStream : sslStream;

                        if (certificado != null)
                        { await sslStream.AuthenticateAsServerAsync(certificado, configuracao.SolicitarCertificadoCliente, SslProtocols.Tls12 | SslProtocols.Tls13, false); }

                        using var scope = app.Services.CreateScope();
                        using HttpContextFromListener context = new(streamEmUso, clientStream);
                        var accessor = (HttpContextFromListenerAccessor)scope.ServiceProvider.GetRequiredService<IHttpContextFromListenerAccessor>();
                        accessor.HttpContext = context;
                        try { configuracao = new(); } catch { }
                        await context.ProcessarRequisicaoAsync(configuracao);
                        break;
                    }

                    await Task.Delay(1, cts.Token);
                }
            }
            catch (Exception ex)
            {
                List<string> erros = [];
                var e = ex;

                while (e != null)
                {
                    erros.Add($"[{e.GetType().FullName}] {e.Message}");
                    if (!string.IsNullOrEmpty(e.StackTrace)) { erros.Add(e.StackTrace.Replace(" at ", "\nat ")); }
                    e = e.InnerException;
                }

                if (erros.Count > 0) { ExibirLog(erros, level: LogLevel.Error); }
            }
        }
    }));
}

await Task.WhenAny(tarefasListeners);
await app.StopAsync();

internal partial class Program
{
    [GeneratedRegex(@"(?:(?:(?<ipv4>(?:\d{1,3}\.){3}\d{1,3}))|(?:(?:\[(?=[^]]+\]:))?(?<ipv6>(?:(?:\w{1,4}:){7}\w{1,4})|(?:(?:\w{1,4}:){1,6}:(?:\w{1,4})?)|(?:(?:\w{1,4})?:(?::\w{1,4}){1,6})|(?:::))(?:(?<=\[[^]]+)\](?=:))?))(?::(?<porta>\d{1,5}))?")]
    private static partial Regex IpPortaRegex();
}