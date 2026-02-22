using MicroProxy.Extensions;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using System.IO.Compression;
using System.Net;
using System.Net.Mime;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using static MicroProxy.Models.Configuracao;

namespace MicroProxy.Models
{
    public static partial class Utils
    {
        public readonly struct CertificadoEKUOID
        {
            public const string Cliente = "1.3.6.1.5.5.7.3.2";
            public const string Servidor = "1.3.6.1.5.5.7.3.1";

            public static string? ToString(string ekuoid)
            {
                foreach (var item in typeof(CertificadoEKUOID).GetFields())
                { if (item.GetRawConstantValue() is string valorItem && valorItem.Equals(ekuoid, StringComparison.OrdinalIgnoreCase)) { return item.Name; } }

                return null;
            }
        }
        private static string[] HeadersProibidos => ["Transfer-Encoding"];
        private static string[] HeadersProibidosReq => [];
        private static string[] HeadersProibidosResp => [];
        private static readonly Lock _lock = new();
        public static readonly HttpContextFromListenerAccessor HttpContextAccessor = new();
        private static ISession? Sessao => HttpContextAccessor.HttpContext?.Session;
        public static string? PathUrlAtual
        {
            get => Sessao?.GetObjectFromJson<string>(PATH_SITE_ATUAL);
            private set { if (value != null) Sessao?.SetObjectAsJson(PATH_SITE_ATUAL, value); else Sessao?.Remove(PATH_SITE_ATUAL); }
        }
        public static string? AbsolutePathUrlOrigemRedirect
        {
            get => Sessao?.GetObjectFromJson<string>(PATH_SITE_ORIGEM_REDIRECT);
            private set { if (value != null) Sessao?.SetObjectAsJson(PATH_SITE_ORIGEM_REDIRECT, value); else Sessao?.Remove(PATH_SITE_ORIGEM_REDIRECT); }
        }

        public static X509Certificate2 ObterCertificado(string path, string? senha = null, string? pathChave = null, string? ekuoid = null, bool exibirLog = false)
        {
            X509Certificate2? certificado = null;
            string pathArquivoCertificado = Site.ProcessarPath(path);
            bool certificadoArquivo = File.Exists(pathArquivoCertificado);
            string certificadoPrivado = path;
            string? chave = Site.ProcessarPath(pathChave ?? "");

            if (certificadoArquivo) { certificado = X509CertificateLoader.LoadPkcs12FromFile(pathArquivoCertificado, senha); }
            else
            {
                using X509Store x509StoreUsuario = new(StoreLocation.CurrentUser);
                using X509Store x509StorePC = new(StoreLocation.LocalMachine);

                x509StoreUsuario.Open(OpenFlags.ReadOnly);
                x509StorePC.Open(OpenFlags.ReadOnly);

                var agora = DateTime.Now;
                var certificados = x509StoreUsuario.Certificates.Union(x509StorePC.Certificates)
                    .Where(c => c.Extensions.Any(e => e is X509EnhancedKeyUsageExtension ekue && (ekuoid == null || ekue.EnhancedKeyUsages[ekuoid] != null)))
                    .OrderByDescending(c => c.NotAfter >= agora).ThenByDescending(c => c.NotBefore <= agora).ThenByDescending(c => c.NotAfter).ThenByDescending(c => c.NotBefore);

                try { certificado = certificados.FirstOrDefault(c => c.Subject == certificadoPrivado) ?? certificados.First(c => c.Subject.Contains(certificadoPrivado)); }
                catch (InvalidOperationException ex) { var e = ex; throw new($"Arquivo ou caminho de certificado \"{certificadoPrivado}\" inválido!", e); }

                if (exibirLog)
                {
                    string[] mensagensLog = [.. certificados.Select(c =>  $"{(c.Subject == certificado.Subject ? "(" : "")}Path/Destinatário " +
                                         $"\"{c.Subject}\" - Valido de {c.NotBefore} até {c.NotAfter}{(c.Subject == certificado.Subject ? ")" : "")}")];

                    Site.ExibirLog(mensagensLog, "Certificados de validação de servidor disponíveis:", "; ");
                }

                x509StoreUsuario.Close();
                x509StorePC.Close();
            }

            if (!certificado.HasPrivateKey && chave != null) { certificado = certificado.CopyWithPrivateKey(CreateRsaFromPem(chave, senha)); }

            return certificado;
        }

        public static async Task ProcessarRequisicaoAsync(this HttpContextFromListener context, Configuracao configuracao)
        {
            var request = context.Request;
            Uri urlAtual = new(request.GetDisplayUrl());
            Site? site = null;
            bool tratarUrl = !HttpMethods.IsGet(request.Method) || !Path.HasExtension(urlAtual.AbsolutePath) || configuracao.ExtensoesUrlNaoRecurso
                .Any(e => e == "*" || e.Trim('.').Equals(Path.GetExtension(urlAtual.AbsolutePath).Trim('.'), StringComparison.InvariantCultureIgnoreCase));

            try
            {
                string[] headersIpFw = ["X-Real-IP", "X-Forwarded-For"];
                var ipRemotoFw = Site.IpRemotoFw;

                if (configuracao.IpsBloqueados.Contains(ipRemotoFw))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await Task.FromResult<object?>(null);
                    return;
                }

                var pathUrlAtual = PathUrlAtual;
                var absolutePathUrlOrigemRedirect = AbsolutePathUrlOrigemRedirect;
                Uri urlDestino;
                Uri? melhorBind = null;
                string? pathUrlAnterior = pathUrlAtual;
                Site[] sites = [];

                while (sites.Length == 0 && (pathUrlAnterior?.Equals(pathUrlAtual, StringComparison.InvariantCultureIgnoreCase) ?? (pathUrlAnterior == pathUrlAtual)))
                {
                    if (pathUrlAtual != null && !CharReservadosUrlRegex().Replace(urlAtual.AbsolutePath, "/")
                            .StartsWith(CharReservadosUrlRegex().Replace(pathUrlAtual, "/"), StringComparison.InvariantCultureIgnoreCase)
                        && tratarUrl) { pathUrlAtual = null; }

                    sites = [.. configuracao.Sites.Where(s =>
                    {
                        if (s.BindUrls == null) { return true; }

                        return s.BindUrls.Any(b =>
                        {
                            string? url = b;

                            urlDestino = new(url, UriKind.Absolute);

                            const int iMin = 1;
                            int i = Math.Min(urlAtual.Segments.Length, urlDestino.Segments.Length) + 1;

                            while (--i >= iMin)
                            {
                                string partePathUrlAtual = pathUrlAtual ?? (i > 1 ? string.Join("", urlAtual.Segments[0..i]).TrimEnd('/') : pathUrlAnterior ?? "");
                                string pathUrlDestino = urlDestino.AbsolutePath.TrimEnd('/');

                                if (pathUrlAtual != null) { i = iMin; }
                                if ($"{urlDestino.Scheme}://{urlDestino.Authority}{pathUrlDestino}".Equals($"{urlAtual.Scheme}://{urlAtual.Authority}{partePathUrlAtual}", StringComparison.InvariantCultureIgnoreCase)
                                    || (!configuracao.Sites.Any(ss => ss.BindUrls != null
                                            && ss.BindUrls.Contains($"{urlAtual.Scheme}://{urlAtual.Authority}{partePathUrlAtual}", StringComparer.InvariantCultureIgnoreCase))
                                        && $"{urlDestino.Authority}{pathUrlDestino}".Equals($"{urlAtual.Authority}{partePathUrlAtual}", StringComparison.InvariantCultureIgnoreCase))
                                    || (!configuracao.Sites.Any(ss => ss.BindUrls != null
                                            && ss.BindUrls.Select(bu => new Uri(bu).Authority).Contains($"{urlAtual.Authority}{partePathUrlAtual}", StringComparer.InvariantCultureIgnoreCase))
                                        && $"{urlDestino.Host}{pathUrlDestino}".Equals($"{urlAtual.Host}{partePathUrlAtual}", StringComparison.InvariantCultureIgnoreCase))
                                    )
                                {
                                    if (melhorBind == null || pathUrlDestino.Length > melhorBind.AbsolutePath.Length
                                        || !CharReservadosUrlRegex().Replace(melhorBind.AbsolutePath, "/").StartsWith(CharReservadosUrlRegex().Replace(pathUrlDestino, "/"), StringComparison.InvariantCultureIgnoreCase))
                                    {
                                        melhorBind = urlDestino;
                                        if (pathUrlDestino != "" && pathUrlAnterior != pathUrlDestino) { pathUrlAtual = melhorBind.AbsolutePath; }
                                    }
                                    if (melhorBind != null && melhorBind.OriginalString.Equals(urlDestino.OriginalString, StringComparison.InvariantCultureIgnoreCase)){ return true; }
                                }
                            }

                            return false;
                        });
                    })];

                    if (pathUrlAnterior != null) { if (pathUrlAtual == null) { if (melhorBind != null) { pathUrlAtual = pathUrlAnterior; } else { pathUrlAnterior = null; } } }
                    else { break; }
                }

                site = sites.OrderByDescending(s => s.BindUrls == null)
                    .ThenByDescending(s => s.Methods.Contains(request.Method, StringComparer.InvariantCultureIgnoreCase))
                    .ThenBy(s => s.Methods.Length).ThenBy(s => string.Join(',', s.Methods))
                    .FirstOrDefault(s => s.BindUrls == null || s.BindUrls.Any(b => melhorBind != null && new Uri(b).OriginalString.Equals(melhorBind.OriginalString)));

                string pathUrlCliente = request.GetEncodedPathAndQuery();
                string[] methodsAceitos = [request.Method, "*"];

                if (site == null || !site.Methods.Any(m => methodsAceitos.Contains(m, StringComparer.InvariantCultureIgnoreCase)))
                {
                    if (urlAtual.AbsolutePath.TrimEnd('/') != "" && pathUrlAtual != null)
                    {
                        if (urlAtual.Segments.Length == 1)
                        {
                            pathUrlAtual = null;
                            absolutePathUrlOrigemRedirect = null;
                            context.Response.RedirectPreserveMethod("/");
                        }
                    }
                    else { if (site != null) { context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed; } }
                }

                if (site != null && context.Response.StatusCode == StatusCodes.Status200OK)
                {
                    do
                    {
                        string? pathUrlAtualTemp = pathUrlCliente;
                        string? pathUrlDestino = null;

                        urlDestino = new(site.UrlDestino);
                        site.PathAtualAdicional = urlDestino.AbsolutePath;

                        if (tratarUrl)
                        {
                            if (urlDestino.Segments.Length > 1)
                            {
                                pathUrlDestino = urlDestino.AbsolutePath;

                                if (pathUrlAtualTemp != "" && CharReservadosUrlRegex().Replace(pathUrlAtualTemp, "/")
                                    .StartsWith(CharReservadosUrlRegex().Replace(pathUrlDestino, "/"), StringComparison.InvariantCultureIgnoreCase))
                                {
                                    var charsReservadosUrl = CharReservadosUrlRegex().Matches(pathUrlAtualTemp).Where(m => m.Value != "").ToArray();

                                    pathUrlAtualTemp = ('/' + string.Join('/', pathUrlAtualTemp.TrimStart('/').Split('/')[(urlDestino.Segments.Length - 1)..]));

                                    if (pathUrlAtualTemp == "" || !CharReservadosUrlRegex().IsMatch(pathUrlAtualTemp))
                                    { foreach (var c in charsReservadosUrl) { pathUrlAtualTemp += pathUrlCliente[pathUrlCliente.IndexOf(c.Value)..]; } }
                                }
                            }

                            if (pathUrlAtual != null && !CharReservadosUrlRegex().Replace(pathUrlAtualTemp, "/")
                                    .StartsWith(CharReservadosUrlRegex().Replace(pathUrlAtual, "/"), StringComparison.InvariantCultureIgnoreCase))
                            { pathUrlAtualTemp = $"{pathUrlAtual}{pathUrlAtualTemp}"; }
                            else if (!pathUrlAtualTemp.StartsWith('/')) { pathUrlAtualTemp = '/' + pathUrlAtualTemp; }
                        }

                        if (pathUrlAtualTemp != pathUrlCliente) { absolutePathUrlOrigemRedirect = pathUrlCliente; context.Response.RedirectPreserveMethod(pathUrlAtualTemp); }
                        else
                        {
                            site.UrlDestino = $"{urlDestino.Scheme}://{urlDestino.Authority}";

                            if (tratarUrl)
                            {
                                pathUrlAtualTemp = request.Path;

                                if (pathUrlDestino != null)
                                {
                                    if ((pathUrlAnterior?.Equals(pathUrlAtual, StringComparison.InvariantCultureIgnoreCase) ?? pathUrlAnterior == pathUrlAtual)
                                        && ((absolutePathUrlOrigemRedirect == null
                                             && CharReservadosUrlRegex().Replace(pathUrlCliente, "/").StartsWith(CharReservadosUrlRegex().Replace(pathUrlDestino, "/"), StringComparison.InvariantCultureIgnoreCase))
                                            || (absolutePathUrlOrigemRedirect != null
                                                && (CharReservadosUrlRegex().Replace(pathUrlAtualTemp, "/").StartsWith(CharReservadosUrlRegex().Replace(absolutePathUrlOrigemRedirect, "/"), StringComparison.InvariantCultureIgnoreCase)
                                                    || CharReservadosUrlRegex().Replace(absolutePathUrlOrigemRedirect, "/").StartsWith(CharReservadosUrlRegex().Replace(pathUrlDestino, "/"), StringComparison.InvariantCultureIgnoreCase)))))
                                    { pathUrlDestino = $"{pathUrlDestino.TrimEnd('/')}{pathUrlCliente}"; }
                                    else { pathUrlDestino = null; }
                                }
                                else if (pathUrlAtual != null && pathUrlAnterior != null
                                        && (absolutePathUrlOrigemRedirect == null
                                            || CharReservadosUrlRegex().Replace(absolutePathUrlOrigemRedirect, "/").StartsWith(CharReservadosUrlRegex().Replace(pathUrlAtual, "/"), StringComparison.InvariantCultureIgnoreCase)))
                                { pathUrlDestino = $"{pathUrlAtual}{pathUrlCliente}"; }
                            }
                        }

                        if (context.Response.StatusCode == StatusCodes.Status200OK)
                        {
                            site.InicializarExecutavel();
                            pathUrlDestino ??= site.PathAtualSubstituto.TrimEnd('/') + pathUrlCliente;

                            if (HttpMethods.IsConnect(request.Method))
                            {
                                var partes = site.UrlDestino.Split(':');
                                var host = partes[1].TrimStart('/');
                                var porta = partes.Length == 3 && int.TryParse(partes[2], out var p) ? p : 443;

                                try
                                {
                                    using var serverTcp = new TcpClient(host, porta);

                                    context.Response.Headers.Connection = "close";
                                    await using var serverStream = serverTcp.GetStream();
                                    var pump1 = context.Response.Body.BaseStream.CopyToAsync(site.BufferResp, [serverStream], context.RequestAborted);
                                    var pump2 = serverStream.CopyToAsync(site.BufferResp, [context.Response.Body.BaseStream], context.RequestAborted);

                                    var response =
                                        $"{context.Request.Protocol} {context.Response.StatusCode} {HttpStatusCode.OK}\r\n\r\n";
                                    await context.Response.Body.BaseStream.WriteAsync(Encoding.UTF8.GetBytes(response));
                                    await Task.WhenAny(pump1, pump2);
                                }
                                catch { context.Response.StatusCode = StatusCodes.Status502BadGateway; }
                            }
                            else if (HttpMethods.IsOptions(request.Method))
                            {
                                context.Response.StatusCode = (int)HttpStatusCode.NoContent;
                                var response =
                                    $"{context.Request.Protocol} {context.Response.StatusCode} {HttpStatusCode.NoContent}\r\n" +
                                    $"Access-Control-Allow-Origin: {string.Join(',', configuracao.AllowOrigins)}\r\n" +
                                    $"Access-Control-Allow-Methods: {string.Join(',', site.Methods)}\r\n" +
                                    $"Access-Control-Allow-Headers: {string.Join(',', configuracao.AllowHeaders)}\r\n" +
                                    "\r\n";
                                await context.Response.Body.BaseStream.WriteAsync(Encoding.UTF8.GetBytes(response));
                            }
                            else
                            {
                                if (tratarUrl && pathUrlAtual != null && melhorBind != null && melhorBind.Segments.Length > 1
                                    && pathUrlDestino.StartsWith(melhorBind.AbsolutePath))
                                { pathUrlDestino = '/' + string.Join('/', pathUrlDestino.TrimStart('/').Split('/')[(melhorBind.Segments.Length - 1)..]); }

                                site.UrlDestino = $"{site.UrlDestino.TrimEnd('/')}{pathUrlDestino}";
                                urlDestino = new(site.UrlDestino);

                                string pathAbsolutoUrlAtual = request.Path.Value!;

                                if (HttpMethods.IsGet(request.Method) && Path.HasExtension(pathAbsolutoUrlAtual)
                                    && configuracao.ArquivosEstaticos != null && configuracao.ArquivosEstaticos != "")
                                {
                                    string pathDiretorioArquivo = Site.ProcessarPath(configuracao.ArquivosEstaticos.ProcessarStringSubstituicao(site));

                                    site.RespBody = await context.Response.SendFileAsync(site, pathDiretorioArquivo, pathAbsolutoUrlAtual.TrimStart('/'), context.RequestAborted);
                                }

                                if (!context.Response.HasStarted)
                                {
                                    List<string> propsHeaders = [];
                                    using HttpRequestMessage requestMessage = new(HttpMethod.Parse(request.Method), site.UrlDestino);
                                    Dictionary<string, StringValues> headersReq = request.Headers
                                            .Where(hr => !HeadersProibidos.Union(HeadersProibidosReq).Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase)))
                                        .ToDictionary();

                                    if (request.Body.CanRead && string.IsNullOrEmpty(site.ReqBody))
                                    {
                                        request.EnableBuffering();
                                        using var streamReader = new StreamReader(request.Body);

                                        site.ReqBody = await streamReader.ReadToEndAsync(context.RequestAborted);
                                    }

                                    if (!string.IsNullOrEmpty(site.ReqBody))
                                    {
                                        requestMessage.Content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes(site.ReqBody)));

                                        foreach (var item in requestMessage.Content.Headers.GetType().GetProperties()) { propsHeaders.Add(item.Name); }
                                    }

                                    headersReq = site.ProcessarHeaders(headersReq, site.RequestHeadersAdicionais);

                                    foreach (var header in headersReq.Where(h => h.Value.Count != 0))
                                    {
                                        string[] valores = [];

                                        foreach (var valor in header.Value)
                                        {
                                            var valorTemp = valor;

                                            if (valorTemp != null) { valorTemp = CookieMicroproxyRegex().Replace(valorTemp, ""); valores = [.. valores.Append(valorTemp)]; }
                                        }

                                        requestMessage.Headers.TryAddWithoutValidation(header.Key, valores);

                                        if (requestMessage.Content != null && propsHeaders.Contains(header.Key.Replace("-", "")))
                                        { requestMessage.Content.Headers.TryAddWithoutValidation(header.Key, valores); }
                                    }

                                    if (ipRemotoFw != null && ipRemotoFw.Length > 0 && ipRemotoFw != Site.IpLocal)
                                    {
                                        foreach (var header in headersIpFw.Where(h => !requestMessage.Headers.TryGetValues(h, out _)).Reverse())
                                        { requestMessage.Headers.TryAddWithoutValidation(header, ipRemotoFw); }
                                    }

                                    site.ReqHeaders = JsonConvert.SerializeObject(requestMessage.Headers.NonValidated.OrderBy(h => h.Key).ToDictionary(), Formatting.None, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });

                                    using HttpClientHandler clientHandler = new() { AllowAutoRedirect = false, UseProxy = site.UsarProxy };

                                    if (site.IgnorarCertificadoDestino)
                                    {
                                        clientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                                        clientHandler.ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErros) => true;
                                    }

                                    if (context.Connection.ClientCertificate != null)
                                    {
                                        var certificado = ObterCertificado(context.Connection.ClientCertificate.Subject);

                                        clientHandler.ClientCertificates.Add(certificado);
                                        clientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                                        clientHandler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                                    }

                                    try
                                    {
                                        using HttpClient httpClient = new(clientHandler);
                                        if (site.SegundosTempoMax > 0) { httpClient.Timeout = TimeSpan.FromSeconds(site.SegundosTempoMax); }
                                        using HttpResponseMessage response = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
                                        using HttpContent content = response.Content;
                                        Dictionary<string, string[]> headersResposta = response.Headers.Union(response.Content.Headers).ToDictionary(h => h.Key, h => h.Value.ToArray())
                                                .Where(hr => !HeadersProibidos.Union(HeadersProibidosResp).Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase))).ToDictionary();

                                        context.Response.StatusCode = (int)response.StatusCode;

                                        if (site.UrlsDestinos.Length <= 1 || context.Response.StatusCode < (int)HttpStatusCode.BadRequest)
                                        {
                                            site.RespHeadersPreAjuste = JsonConvert.SerializeObject(headersResposta.OrderBy(h => h.Key).ToDictionary(), Formatting.None, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });
                                            headersResposta = site.ProcessarHeaders(headersResposta, site.ResponseHeadersAdicionais);

                                            foreach (var header in headersResposta.Where(h => h.Value.Length != 0))
                                            { if (!context.Response.Headers.TryAdd(header.Key, header.Value)) { context.Response.Headers.Append(header.Key, header.Value); } }

                                            if (context.Response.Headers.Location.Count == 0)
                                            {
                                                absolutePathUrlOrigemRedirect = null;

                                                using MemoryStream memoryStream = new();
                                                await using Stream streamContentResp = await content.ReadAsStreamAsync(context.RequestAborted);

                                                await streamContentResp.CopyToAsync(site.BufferResp, [memoryStream, context.Response.Body], context.RequestAborted);
                                                site.RespBody = await site.BodyAsStringAsync(memoryStream, content.Headers.ContentType?.MediaType
                                                    , content.Headers.ContentEncoding.FirstOrDefault(), context.RequestAborted);
                                            }
                                            else
                                            {
                                                if (absolutePathUrlOrigemRedirect == null) { absolutePathUrlOrigemRedirect = pathAbsolutoUrlAtual; }
                                                else
                                                {
                                                    if (CharReservadosUrlRegex().Replace(pathAbsolutoUrlAtual, "/")
                                                            .StartsWith(CharReservadosUrlRegex().Replace(absolutePathUrlOrigemRedirect, "/")))
                                                    {
                                                        if (pathUrlAtual != null && CharReservadosUrlRegex().Replace(absolutePathUrlOrigemRedirect, "/")
                                                                .StartsWith(CharReservadosUrlRegex().Replace(pathUrlAtual, "/")))
                                                        { pathUrlAtual = null; }
                                                    }

                                                    absolutePathUrlOrigemRedirect = null;
                                                }
                                            }
                                        }
                                    }
                                    catch (Exception ex)
                                    {
                                        if (!context.Response.HasStarted) { context.Response.StatusCode = (int)HttpStatusCode.InternalServerError; }

                                        if (site.UrlsDestinos.Length <= 1 || context.Response.HasStarted)
                                        { throw new Exception(context.Response.HasStarted ? "A requisição foi encerrada." : "Nenhuma alternativa de conexão respondeu.", ex); }
                                    }
                                }
                            }
                        }
                    } while (site.UrlsDestinos.Length > 1 && context.Response.StatusCode >= (int)HttpStatusCode.BadRequest);
                }

                PathUrlAtual = pathUrlAtual;
                AbsolutePathUrlOrigemRedirect = absolutePathUrlOrigemRedirect;
            }
            catch (Exception ex)
            {
                site ??= new();
                site.Exception = new("A requisição foi encerrada prematuramente.", ex);

                if (!context.Response.HasStarted)
                {
                    context.Response.StatusCode = StatusCodes.Status500InternalServerError;

                    if (configuracao.TratamentoErroInterno != null && configuracao.TratamentoErroInterno != "")
                    {
                        string pathArquivo = Site.ProcessarPath(configuracao.TratamentoErroInterno.ProcessarStringSubstituicao(site));
                        string[] partesPath = CharSeparadorDiretorioUrlRegex().Split(pathArquivo);

                        site.RespBody = await context.Response
                            .SendFileAsync(site, string.Join(Path.DirectorySeparatorChar, partesPath[0..(partesPath.Length - 1)]),
                                Path.GetFileName(configuracao.TratamentoErroInterno), context.RequestAborted);
                    }

                    if (!context.Response.HasStarted)
                    {
                        context.Response.Headers.ContentType = MediaTypeNames.Text.Html;
                        await context.Response.WriteAsync($"<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>Erro {context.Response.StatusCode}</title></head>" +
                            $"<body><h1>Erro {context.Response.StatusCode}</h1>{site.ExceptionMensagem?.ReplaceLineEndings("<br>")}</body></html>", context.RequestAborted);
                    }
                }
            }

            site ??= new();

            lock (_lock)
            {
                if (HttpMethods.IsConnect(context.Request.Method)) { site.UrlDestino = site.AuthorityDestino; }

                foreach (var log in configuracao.Logs ?? [])
                {
                    if (tratarUrl || !log.Value.IgnorarArquivosEstaticos)
                    {
                        string pathLog = Site.ProcessarPath(Site.CharsInvalidosPathArquivoRegex().Replace(log.Value.Path.ProcessarStringSubstituicao(site), "_"));
                        string nomeArquivo = Site.CharsInvalidosPathArquivoRegex().Replace(log.Key.ProcessarStringSubstituicao(site), "_").Trim('/', '\\').Replace("/", "_").Replace(@"\", "_");

                        if (pathLog != "")
                        {
                            string mensagem = log.Value.Mensagem.ProcessarStringSubstituicao(site);
                            string[] tratamentosRegex = log.Value.TratamentoRegex ?? [];
                            int qtdTratamentos = tratamentosRegex.Length;

                            if (!Directory.Exists(pathLog)) { Directory.CreateDirectory(pathLog); }

                            for (int i = 1; i < qtdTratamentos; i += 2)
                            {
                                Regex tratamentoRegex = new(tratamentosRegex[i - 1], RegexOptions.Multiline | RegexOptions.IgnoreCase);

                                mensagem = tratamentoRegex.Replace(mensagem, tratamentosRegex[i]);
                            }

                            if (mensagem != "") { File.AppendAllText($"{pathLog}/{nomeArquivo}", mensagem); }
                        }
                    }
                }
            }

            if (site.Exception != null)
            {
                throw new Exception(site.Exception.Contains([typeof(OperationCanceledException), typeof(TaskCanceledException), typeof(SocketException)])
                    ? "A requisição foi cancelada." : "Erro inesperado.", site.Exception);
            }
        }

        private static void RedirectPreserveMethod(this HttpResponseFromListener response, string novoDestino, bool permanent = false, string? method = null)
        {
            method ??= response.HttpContext.Request.Method;

            if (HttpMethods.IsGet(method)) { response.Redirect(novoDestino); }
            else
            {
                response.Headers.Location = novoDestino;
                response.StatusCode = permanent ? StatusCodes.Status308PermanentRedirect : StatusCodes.Status307TemporaryRedirect;
            }
        }

        public static async Task<string?> SendFileAsync(this HttpResponseFromListener httpResponse, Site site, string? pathDiretorio, string? pathArquivo, CancellationToken cancellationToken = default)
        {
            if (pathDiretorio != null && pathDiretorio != "" && pathArquivo != null && pathArquivo != "")
            {
                pathDiretorio = Site.ProcessarPath(pathDiretorio.ProcessarStringSubstituicao(site));
                pathArquivo = pathArquivo.ProcessarStringSubstituicao(site);
                var arquivo = new PhysicalFileProvider(pathDiretorio).GetFileInfo(pathArquivo);

                if (arquivo.Exists)
                {
                    var provedor = new FileExtensionContentTypeProvider();
                    using var conteudoResposta = arquivo.CreateReadStream();
                    var headersResposta = site.ProcessarHeaders(httpResponse.Headers.ToDictionary(), site.ResponseHeadersAdicionais);

                    foreach (var header in headersResposta.Where(h => h.Value.ToString().Length != 0))
                    {
                        string[] valores = header.Value!;

                        if (!httpResponse.Headers.TryAdd(header.Key, valores)) { httpResponse.Headers.Append(header.Key, valores); }
                    }
                    ;

                    httpResponse.ContentLength = arquivo.Length;

                    if (provedor.TryGetContentType(pathArquivo, out string? tipoConteudo)) { httpResponse.ContentType = tipoConteudo; }

                    await httpResponse.SendFileAsync(arquivo, cancellationToken);
                    site.RespBody = await site.BodyAsStringAsync(conteudoResposta, tipoConteudo, cancellationToken: cancellationToken);

                    return site.RespBody;
                }
            }

            return null;
        }

        public static async Task<string> BodyAsStringAsync(this Site site, Stream conteudoResposta, string? tipoConteudo = null, string? codecConteudo = null, CancellationToken cancellationToken = default)
        {
            site.RespBody = $"Dado[{tipoConteudo}]";

            if (tipoConteudo == null
                || tipoConteudo.StartsWith("text", StringComparison.InvariantCultureIgnoreCase)
                || tipoConteudo.StartsWith("application", StringComparison.InvariantCultureIgnoreCase))
            {
                conteudoResposta.Seek(0, SeekOrigin.Begin);

                if (codecConteudo != null)
                {
                    switch (codecConteudo.ToLower())
                    {
                        case "gzip":
                            conteudoResposta = new GZipStream(conteudoResposta, CompressionMode.Decompress);
                            break;

                        case "deflate":
                            conteudoResposta = new DeflateStream(conteudoResposta, CompressionMode.Decompress);
                            break;

                        case "brotli":
                        case "br":
                            conteudoResposta = new BrotliStream(conteudoResposta, CompressionMode.Decompress);
                            break;

                        case "zstd":
                            conteudoResposta = new ZLibStream(conteudoResposta, CompressionMode.Decompress);
                            break;
                    }
                }

                site.RespBody = (await new StreamReader(conteudoResposta).ReadToEndAsync(cancellationToken)).ProcessarStringSubstituicao(site);
            }

            return site.RespBody;
        }

        public static Dictionary<string, string?> ColetarDicionarioVariaveis<T>(this string valor, T obj)
        {
            Dictionary<string, string?> dic = [];
            var variaveis = VariavelRegex().Matches(valor).DistinctBy(v => v.Value).ToArray();

            if (variaveis.Length > 0)
            {
                foreach (var variavel in variaveis)
                {
                    string nomeVariavel = variavel.Groups[1].Value;
                    var valorVariavel = (obj?.GetType().GetProperty(nomeVariavel)?.GetValue(obj)
                        ?? obj?.GetType().GetField(nomeVariavel)?.GetValue(obj))?.ToString();

                    dic.Add(variavel.Value, valorVariavel);
                }
            }

            return dic;
        }

        public static string ProcessarStringSubstituicao<T>(this string valor, T obj, bool tratarRegex = false) => valor.ProcessarStringSubstituicao(obj, null, tratarRegex);

        public static string ProcessarStringSubstituicao<T>(this string valor, T obj, Dictionary<string, string?>? dicVariaveis, bool tratarRegex = false)
        {
            if (obj != null)
            {
                if (tratarRegex) { valor = CharExpRegex().Replace(valor, ""); }

                var variaveis = dicVariaveis ?? valor.ColetarDicionarioVariaveis(obj);

                foreach (var variavel in variaveis)
                { if (variavel.Value != null) { valor = valor.Replace(variavel.Key, variavel.Value, StringComparison.InvariantCultureIgnoreCase); } }
            }

            return valor;
        }

        public static async Task CopyToAsync(this Stream fonte, int tambuffer, Stream[] destinos, CancellationToken cancellationToken = default)
        {
            byte[] buffer = new byte[tambuffer];
            int bytesRead;

            if (tambuffer <= 0)
            {
                using MemoryStream memoryStream = new();
                await fonte.CopyToAsync(memoryStream, cancellationToken);
                foreach (var destino in destinos) { await destino.WriteAsync(memoryStream.ToArray(), cancellationToken); }
            }
            else
            {
                while ((bytesRead = await fonte.ReadAsync(buffer, cancellationToken)) > 0)
                { foreach (var destino in destinos) { await destino.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken); } }
            }
        }
        public static RSA CreateRsaFromPem(string pathKey, string? senha = null)
        {
            // Remove the PEM header and footer
            RSA rsa = RSA.Create();
            string conteudoChave = File.ReadAllText(pathKey);

            try
            {
                if (senha != null) { rsa.ImportFromEncryptedPem(conteudoChave, senha); }
                else { rsa.ImportFromPem(conteudoChave); }
            }
            catch (ArgumentException ex)
            {
                byte[] chaveFonte = Convert.FromBase64String(ElemsKeyCertRegex().Replace(conteudoChave, ""));

                try
                {
                    if (senha != null) { rsa.ImportEncryptedPkcs8PrivateKey(senha, chaveFonte, out _); }
                    else { rsa.ImportPkcs8PrivateKey(chaveFonte, out _); }
                }
                catch (ArgumentException ex2)
                {
                    try { rsa.ImportRSAPrivateKey(chaveFonte, out _); }
                    catch (ArgumentException ex3) { throw new ArgumentException(ex3.Message, new ArgumentException(ex2.Message, ex)); }
                }
            }

            if (OperatingSystem.IsWindows())
            {
                CspParameters cspParameters = new()
                {
                    KeyContainerName = pathKey,
                    Flags = CspProviderFlags.UseNonExportableKey,
                };

                RSACryptoServiceProvider rsaPersistente = new(cspParameters);

                rsaPersistente.ImportParameters(rsa.ExportParameters(true));
                rsa.Dispose();
                rsa = rsaPersistente;
            }

            return rsa;
        }

        [GeneratedRegex($"(?<=(?:^|(?:; *))){NOME_COOKIE}[^;]+(?:(?:; *)|(?: *$))")]
        private static partial Regex CookieMicroproxyRegex();

        [GeneratedRegex(@"##([^#]+)##")]
        private static partial Regex VariavelRegex();

        [GeneratedRegex(@"(?:\?:)|(?:(?<=[^\w])\?)|(?:\?$)|(?:\\\w)|(?:\<\w+\>)|(?:[()<>\\\^\$])")]
        private static partial Regex CharExpRegex();

        [GeneratedRegex(@"\?|#|(?:(?<!/)$)")]
        private static partial Regex CharReservadosUrlRegex();

        [GeneratedRegex(@"/|\\")]
        private static partial Regex CharSeparadorDiretorioUrlRegex();

        [GeneratedRegex(@"(?:-{5}[\w ]+-{5})|[\r\n]")]
        private static partial Regex ElemsKeyCertRegex();
    }
}
