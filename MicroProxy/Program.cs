using MicroProxy.Extensions;
using MicroProxy.Models;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using static MicroProxy.Helpers.CriptografiaHelper;
using static MicroProxy.Helpers.FuncoesHelper;
using static MicroProxy.Models.Configuracao;
using static MicroProxy.Models.Site;

Configuracao configuracao = new();
string[]? codecConteudo = configuracao.CompressionResponse?.Split(',', StringSplitOptions.TrimEntries);

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

var urls = Environment.GetEnvironmentVariable("ASPNETCORE_URLS")?.Split(';').OrderBy(u => u.StartsWith("https", StringComparison.OrdinalIgnoreCase)).ToArray() ?? configuracao.Ips;
List<(TcpListener listener, X509Certificate2? certificado)> tcpListeners = [];
bool fonteUrlsConfig = urls == configuracao.Ips;
var certificadoStr = fonteUrlsConfig ? configuracao.CertificadoPrivado : null;
List<string> mensagens = [];
List<Task> tarefasListeners = [];
List<IPAddress> enderecosIp = [];
bool https = false;

foreach (string url in urls)
{
    var ipPorta = IpPortaRegex().Match(url);
    Uri? uri = fonteUrlsConfig ? null : new Uri(url);

    if (uri != null && string.IsNullOrEmpty(certificadoStr) && uri.Scheme.Equals("https")) { certificadoStr = uri.Host; }

    IPAddress ip = fonteUrlsConfig ? IPAddress.Parse(ipPorta.Groups["ipv4"].Success ? ipPorta.Groups["ipv4"].Value : ipPorta.Groups["ipv6"].Value) : IPAddress.Loopback;
    var portaHttp = fonteUrlsConfig ? configuracao.PortaHttp : 0;
    ushort porta = ushort.Parse(uri == null ? (ipPorta.Groups["porta"].Success ? ipPorta.Groups["porta"].Value : "80") : uri.Port.ToString());

    if (!https || !enderecosIp.Contains(ip))
    {
        if (!enderecosIp.Contains(ip)) { enderecosIp.Add(ip); }

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
        X509Certificate2? certificado = ObterCertificado(certificadoStr, configuracao.CertificadoPrivadoSenha, configuracao.CertificadoPrivadoChave
            , UtilsHelper.CertificadoEKUOID.Servidor, !https);
        https = true;
        tcpListeners.Add((new TcpListener(ip, porta), certificado));
        tcpListeners.Last().listener.Start();
        mensagens.Add($"HTTPS listener em {ip}:{porta}\n");
    }
}

int tarefas = 0;
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
            var client = await listener.AcceptTcpClientAsync(app.Lifetime.ApplicationStopping);
            var clientStream = client.GetStream();
            if (clientStream.Socket.Poll(1000, SelectMode.SelectRead) && !clientStream.DataAvailable) { clientStream.Socket.Dispose(); continue; }
            try { configuracao = new(); } catch { }
            if (configuracao.BufferReq > 0) { clientStream.Socket.ReceiveBufferSize = configuracao.BufferReq; }
            if (configuracao.BufferResp > 0) { clientStream.Socket.SendBufferSize = configuracao.BufferResp; }
            clientStream.Socket.NoDelay = configuracao.SemDelay;
            _ = Task.Run(async () =>
            {
                using var ctsAbort = new CancellationTokenSource();
                using var ctsAbortLink = CancellationTokenSource.CreateLinkedTokenSource(app.Lifetime.ApplicationStopping, ctsAbort.Token);
                string url = "Destino inválido!";
                using var clientTask = client;
                await using var clientStreamTask = clientStream;
                bool httpContextStarted = false;
                IPEndPoint? ipRemoto = null;
                IPEndPoint? ipLocal = null;
                using Task? tarefaCheck = Task.Run(async () =>
                {
                    await Task.Delay(1000, ctsAbortLink.Token);
                    while (clientStream.Socket.Connected && !ctsAbortLink.IsCancellationRequested
                            && (!clientStream.Socket.Poll(1000, SelectMode.SelectRead) || clientStream.DataAvailable))
                    { await Task.Delay(1000, ctsAbortLink.Token); }
                    try { ctsAbort.Cancel(); } catch (ObjectDisposedException) { }
                });

                ++tarefas;

                try
                {
                    ipRemoto = (IPEndPoint)clientStreamTask.Socket.RemoteEndPoint!;
                    ipLocal = (IPEndPoint)clientStreamTask.Socket.LocalEndPoint!;
                    ExibirLog($"Cliente {ipRemoto} conectado a {ipLocal}... (Conexões ativas: {tarefas})");
                    using var sslStream = new SslStream(clientStreamTask, false, (sender, cert, chain, errors) => true);
                    using var streamEmUso = certificado == null ? (Stream)clientStreamTask : sslStream;

                    if (certificado != null)
                    { await sslStream.AuthenticateAsServerAsync(certificado, configuracao.SolicitarCertificadoCliente, SslProtocols.Tls12 | SslProtocols.Tls13, false); }

                    using var scope = app.Services.CreateScope();
                    using HttpContextFromListener context = new(streamEmUso, clientStreamTask, configuracao.CompressionResponse, ctsAbortLink.Token);
                    httpContextStarted = true;
                    var accessor = (HttpContextFromListenerAccessor)scope.ServiceProvider.GetRequiredService<IHttpContextFromListenerAccessor>();
                    accessor.HttpContext = context;
                    var uri = new Uri(context.Request.GetDisplayUrl());
                    url = uri.Authority;
                    ExibirLog($"URL de conexão solicitado: {url}");

                    await context.ProcessarRequisicaoAsync(configuracao);
                }
                catch (Exception ex)
                {
                    try
                    {
                        if (httpContextStarted || !ex.Contains([typeof(OperationCanceledException), typeof(TaskCanceledException)]))
                        {
                            List<string> erros = [];
                            var e = ex;

                            while (e != null)
                            {
                                erros.Add($"[{e.GetType().FullName}] {e.Message}");
                                if (!string.IsNullOrEmpty(e.StackTrace)) { erros.Add(e.StackTrace.Replace(" at ", "\nat ") + "\n"); }
                                e = e.InnerException;
                            }

                            if (erros.Count > 0) { ExibirLog(erros, null, LogLevel.Error); }
                        }
                    }
                    catch { }
                }

                --tarefas;

                try
                {
                    ExibirLog($"Cliente {ipRemoto} desconectado de {ipLocal}... (Conexões ativas: {tarefas})");
                    ExibirLog($"URL de conexão desconectada: {url}");
                }
                catch { }
                ctsAbort.Cancel();
                tarefaCheck?.Wait();
            });
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