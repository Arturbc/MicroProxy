using MicroProxy.Extensions;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using System.Net;
using System.Net.Mime;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using static MicroProxy.Helpers.FuncoesHelper;
using static MicroProxy.Helpers.HttpHelper;
using static MicroProxy.Models.Configuracao;

namespace MicroProxy.Models
{
    public static partial class UtilsHelper
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
        private static string[] HeadersProibidos => [];
        private static string[] HeadersProibidosReq => [];
        private static string[] HeadersProibidosResp => ["transfer-encoding", "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization", "te", "trailer", "upgrade"];
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

        public static async Task ProcessarRequisicaoAsync(this HttpContextFromListener context, Configuracao configuracao, Func<Task> checkAbort)
        {
            List<Task> tarefasAsync = [];
            var request = context.Request;
            var response = context.Response;
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
                    response.StatusCode = StatusCodes.Status403Forbidden;
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
                            response.RedirectPreserveMethod("/");
                        }
                    }
                    else { if (site != null) { response.StatusCode = StatusCodes.Status405MethodNotAllowed; } }
                }

                if (site != null && response.StatusCode == StatusCodes.Status200OK)
                {
                    do
                    {
                        string? pathUrlAtualTemp = pathUrlCliente;
                        string? pathUrlDestino = null;

                        urlDestino = new(site.UrlDestino);
                        ExibirLog($"URL de destino: {Site.ExibirUrlAjustada(HttpMethods.IsConnect(request.Method) ? urlDestino.Authority : urlDestino.OriginalString)}");
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

                        if (pathUrlAtualTemp != pathUrlCliente) { absolutePathUrlOrigemRedirect = pathUrlCliente; response.RedirectPreserveMethod(pathUrlAtualTemp); }
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

                        if (response.StatusCode == StatusCodes.Status200OK)
                        {
                            site.InicializarExecutavel();
                            pathUrlDestino ??= site.PathAtualSubstituto.TrimEnd('/') + pathUrlCliente;
                            context.Request.Timeout = site.SegundosTempoMax;
                            context.Response.Timeout = site.SegundosTempoMax;

                            if (HttpMethods.IsOptions(request.Method))
                            {
                                var tipoSite = site.GetType();
                                response.StatusCode = (int)HttpStatusCode.NoContent;
                                response.Headers.Append("Access-Control-Allow-Headers", configuracao.AllowHeaders);
                                response.Headers.Append("Access-Control-Allow-Methods", configuracao.AllowMethods);
                                response.Headers.Append("Access-Control-Allow-Origin", configuracao.AllowOrigins);
                            }
                            else
                            {
                                string pathAbsolutoUrlAtual = request.Path.Value!;
                                string pathDiretorioArquivo = "";

                                if (HttpMethods.IsGet(request.Method) && Path.HasExtension(pathAbsolutoUrlAtual)
                                    && configuracao.ArquivosEstaticos != null && configuracao.ArquivosEstaticos != "")
                                {
                                    pathDiretorioArquivo = ProcessarPath(configuracao.ArquivosEstaticos.ProcessarStringSubstituicao(site));

                                    try { site.RespBody = await response.SendFileAsync(pathDiretorioArquivo, pathAbsolutoUrlAtual.TrimStart('/'), context.RequestAborted); }
                                    catch (Exception ex) when (ex.Contains([typeof(DirectoryNotFoundException), typeof(FileNotFoundException)])) { pathDiretorioArquivo = ""; }
                                }

                                if (pathDiretorioArquivo == "")
                                {
                                    var tcpClient = await ConnectionPool.GetConnectionAsync(urlDestino.Host, urlDestino.Port, context.RequestAborted);
                                    tcpClient.NoDelay = site.SemDelay;
                                    tcpClient.ReceiveTimeout = (int)TimeSpan.FromSeconds(site.SegundosTempoMax).TotalMilliseconds;
                                    tcpClient.SendTimeout = (int)TimeSpan.FromSeconds(site.SegundosTempoMax).TotalMilliseconds;
                                    if (site.BufferReq > 0) { tcpClient.ReceiveBufferSize = site.BufferReq; }
                                    if (site.BufferResp > 0) { tcpClient.SendBufferSize = site.BufferResp; }
                                    var serverStream = tcpClient.GetStream();
                                    var serverSslStream = new SslStream(serverStream);
                                    using var memory = new MemoryStream();
                                    var destinoHttps = urlDestino.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
                                    var serverStreamEmUso = destinoHttps ? (Stream)serverSslStream : serverStream;

                                    if (destinoHttps)
                                    {
                                        var sslClientAuth = new SslClientAuthenticationOptions();
                                        if (request.Body.BaseStream is SslStream sslStream && sslStream.RemoteCertificate != null) { sslClientAuth.ClientCertificates = [sslStream.RemoteCertificate]; }
                                        if (site.IgnorarCertificadoDestino) { sslClientAuth.RemoteCertificateValidationCallback = (sender, cert, chain, errors) => true; }
                                        await serverSslStream.AuthenticateAsClientAsync(sslClientAuth, context.RequestAborted);
                                    }

                                    try
                                    {
                                        if (HttpMethods.IsConnect(request.Method))
                                        {
                                            response.Headers.Connection = "close";
                                            await response.CompleteAsync();
                                            tarefasAsync.Add(request.Body.BaseStream.CopyToAsync(serverStreamEmUso, context.RequestAborted));
                                            tarefasAsync.Add(serverStreamEmUso.CopyToAsync(response.Body.BaseStream, context.RequestAborted));
                                            await Task.WhenAny(tarefasAsync);
                                        }
                                        else
                                        {
                                            if (tratarUrl && pathUrlAtual != null && melhorBind != null && melhorBind.Segments.Length > 1
                                            && pathUrlDestino.StartsWith(melhorBind.AbsolutePath))
                                            { pathUrlDestino = '/' + string.Join('/', pathUrlDestino.TrimStart('/').Split('/')[(melhorBind.Segments.Length - 1)..]); }

                                            site.UrlDestino = $"{site.UrlDestino.TrimEnd('/')}{pathUrlDestino}";
                                            urlDestino = new(site.UrlDestino);

                                            if (!response.HasStarted)
                                            {
                                                Dictionary<string, StringValues> headersReq = request.Headers.Where(hr => !HeadersProibidos.Union(HeadersProibidosReq)
                                                        .Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase))).ToDictionary();

                                                headersReq = site.ProcessarHeaders(headersReq, site.RequestHeadersAdicionais);
                                                site.ReqHeaders = JsonConvert.SerializeObject(headersReq.OrderBy(h => h.Key).ToDictionary(), Formatting.None, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });
                                                var cabecalho = MontarCabecalhoPacote(request.Protocol, site.PathAndQueryAtual, request.Method, headersReq);

                                                if (request.Body.CanRead) { request.EnableBuffering(); if (request.Body.CanSeek) { request.Body.Seek(0, SeekOrigin.Begin); } }

                                                try
                                                {
                                                    await serverStreamEmUso.WriteAsync(Encoding.UTF8.GetBytes(cabecalho));
                                                    if (request.Body.CanRead) { await request.Body.CopyToAsync(site.BufferReq, [serverStreamEmUso, memory], context.RequestAborted); }
                                                    if (serverStreamEmUso.CanWrite) { await serverStreamEmUso.FlushAsync(context.RequestAborted); }
                                                }
                                                catch (Exception ex) { site.Exception = ex; }
                                                await memory.FlushAsync(context.RequestAborted);
                                                memory.Seek(0, SeekOrigin.Begin);
                                                using StreamReader readerReq = new(memory);
                                                site.ReqBody = await readerReq.ReadToEndAsync();

                                                if (site.Exception != null) { throw new("Falha durante a requisição", site.Exception); }

                                                memory.Seek(0, SeekOrigin.Begin);
                                                memory.SetLength(0);

                                                var serverResponse = new HttpResponseFromListener(serverStreamEmUso, serverStream, context, true);
                                                Dictionary<string, StringValues> headersResposta = serverResponse.Headers.ToDictionary(h => h.Key, h => h.Value)
                                                        .Where(hr => !HeadersProibidos.Union(HeadersProibidosResp).Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase)))
                                                        .ToDictionary();

                                                response.StatusCode = serverResponse.StatusCode;

                                                if (site.UrlsDestinos.Length <= 1 || response.StatusCode < (int)HttpStatusCode.BadRequest)
                                                {
                                                    site.RespHeadersPreAjuste = JsonConvert.SerializeObject(headersResposta.OrderBy(h => h.Key).ToDictionary(),
                                                        Formatting.None, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });
                                                    headersResposta = site.ProcessarHeaders(headersResposta, site.ResponseHeadersAdicionais);

                                                    foreach (var header in headersResposta.Where(h => h.Value.Count != 0))
                                                    { if (!response.Headers.TryAdd(header.Key, header.Value)) { response.Headers.Append(header.Key, header.Value); } }

                                                    if (response.Headers.Location.Count == 0)
                                                    {
                                                        absolutePathUrlOrigemRedirect = null;

                                                        try
                                                        {
                                                            if (response.Body.CanWrite)
                                                            {
                                                                var tarefaCheck = checkAbort();
                                                                await serverResponse.Body.CopyToAsync(site.BufferResp, [response.Body, memory], context.RequestAborted);
                                                                tarefaCheck.Dispose();
                                                            }
                                                        }
                                                        catch (Exception ex) { site.Exception = ex; }

                                                        await memory.FlushAsync(context.RequestAborted);
                                                        memory.Seek(0, SeekOrigin.Begin);
                                                        using StreamReader readerResp = new(memory);
                                                        site.RespBody = await readerResp.ReadToEndAsync();

                                                        if (site.Exception != null)
                                                        {
                                                            if (!response.HasStarted) { response.StatusCode = (int)HttpStatusCode.InternalServerError; }

                                                            if (site.UrlsDestinos.Length <= 1 || response.HasStarted)
                                                            { throw new Exception(response.HasStarted ? "A requisição foi encerrada." : "Nenhuma alternativa de conexão respondeu.", site.Exception); }
                                                        }
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
                                        }
                                        await response.CompleteAsync();
                                        if (tarefasAsync.Count != 0) { await Task.WhenAny(tarefasAsync); }
                                    }
                                    catch (Exception ex)
                                    {
                                        response.StatusCode = StatusCodes.Status502BadGateway;
                                        throw new Exception(null, ex);
                                    }
                                }
                            }
                        }
                    } while (site.UrlsDestinos.Length > 1 && response.StatusCode >= (int)HttpStatusCode.BadRequest);
                }

                PathUrlAtual = pathUrlAtual;
                AbsolutePathUrlOrigemRedirect = absolutePathUrlOrigemRedirect;
            }
            catch (Exception ex)
            {
                site ??= new();
                site.Exception = new("A requisição foi encerrada prematuramente.", ex);

                if (!response.HasStarted)
                {
                    if (response.StatusCode < StatusCodes.Status500InternalServerError) { response.StatusCode = StatusCodes.Status500InternalServerError; }

                    if (configuracao.TratamentoErroInterno != null && configuracao.TratamentoErroInterno != "")
                    {
                        string pathArquivo = ProcessarPath(configuracao.TratamentoErroInterno.ProcessarStringSubstituicao(site));
                        string[] partesPath = CharSeparadorDiretorioUrlRegex().Split(pathArquivo);

                        site.RespBody = await response
                            .SendFileAsync(string.Join(Path.DirectorySeparatorChar, partesPath[0..(partesPath.Length - 1)]),
                                Path.GetFileName(configuracao.TratamentoErroInterno), context.RequestAborted);
                    }

                    if (!response.HasStarted)
                    {
                        response.Headers.ContentType = MediaTypeNames.Text.Html;
                        await response.WriteAsync($"<!DOCTYPE html><html><head><meta charset=\"utf-8\" /><title>Erro {response.StatusCode}</title></head>" +
                            $"<body><h1>Erro {response.StatusCode}</h1>{site.ExceptionMensagem?.ReplaceLineEndings("<br>")}</body></html>", context.RequestAborted);
                    }
                }
            }

            await response.CompleteAsync();
            site ??= new();

            lock (_lock)
            {
                if (HttpMethods.IsConnect(context.Request.Method)) { site.UrlDestino = site.AuthorityDestino; }

                foreach (var log in configuracao.Logs ?? [])
                {
                    if (tratarUrl || !log.Value.IgnorarArquivosEstaticos)
                    {
                        string pathLog = ProcessarPath(Site.CharsInvalidosPathArquivoRegex().Replace(log.Value.Path.ProcessarStringSubstituicao(site), "_"));
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

        public static async Task CopyToAsync(this Stream fonte, int tambuffer, Stream[] destinos, CancellationToken cancellationToken = default)
        {
            if (tambuffer == 0)
            {
                using MemoryStream memoryStream = new();
                await fonte.CopyToAsync(memoryStream, cancellationToken);
                foreach (var destino in destinos) { await destino.WriteAsync(memoryStream.ToArray(), cancellationToken); }
            }
            else
            {
                int bytesRead;
                byte[] buffer = new byte[tambuffer];

                while ((bytesRead = await fonte.ReadAsync(buffer, cancellationToken)) > 0)
                { foreach (var destino in destinos) { await destino.WriteAsync(buffer.AsMemory(0, bytesRead), cancellationToken); } Array.Clear(buffer); }
            }
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
    }
}
