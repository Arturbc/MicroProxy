using MicroProxy.Extensions;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using System.Net;
using System.Text.RegularExpressions;
using static MicroProxy.Models.Configuracao;

namespace MicroProxy.Models
{
    public static partial class Utils
    {
        private static string[] HeadersProibidos => ["Transfer-Encoding"];
        private static string[] HeadersProibidosReq => [];
        private static string[] HeadersProibidosResp => [];
        private static readonly object _lock = new();
        public static readonly HttpContextAccessor HttpContextAccessor = new();
        private static ISession? Sessao => HttpContextAccessor.HttpContext?.Session;
        private static Dictionary<Uri, string> CookiesSites
        {
            get
            {
                var dic = Sessao?.GetObjectFromJson<Dictionary<Uri, string>>(COOKIE_SITE);

                if (dic == null)
                {
                    dic = [];
                    CookiesSites = dic;
                }

                return dic;
            }
            set => Sessao?.SetObjectAsJson(COOKIE_SITE, value);
        }
        private static string? PathUrlAtual
        {
            get => Sessao?.GetObjectFromJson<string>(PATH_SITE_ATUAL);
            set { if (value != null) Sessao?.SetObjectAsJson(PATH_SITE_ATUAL, value); else Sessao?.Remove(PATH_SITE_ATUAL); }
        }
        private static string? PathUrlRedirectOrigem
        {
            get => Sessao?.GetObjectFromJson<string>(PATH_SITE_REDIRECT_ORIGEM);
            set { if (value != null) Sessao?.SetObjectAsJson(PATH_SITE_REDIRECT_ORIGEM, value); else Sessao?.Remove(PATH_SITE_REDIRECT_ORIGEM); }
        }

        public static async Task ProcessarRequisicao(this RequestDelegate next, HttpContext context, Configuracao configuracao)
        {
            HttpRequest request = context.Request;
            Uri urlAtual = new(request.GetDisplayUrl());
            Site? site = null;

            try
            {
                var cookiesSites = CookiesSites;
                Uri urlAlvo;
                Uri? melhorBind = null;
                string? pathUrlAnterior = PathUrlAtual;
                Site[] sites = [];

                while (sites.Length == 0 && pathUrlAnterior == PathUrlAtual)
                {
                    if (PathUrlAtual != null && !(urlAtual.AbsolutePath.TrimEnd('/') + '/').StartsWith(PathUrlAtual + '/')
                        && !Path.HasExtension(urlAtual.AbsolutePath))
                    {
                        PathUrlAtual = null;
                    }

                    sites = [.. configuracao.Sites.Where(s =>
                    {
                        if (s.BindUrls == null || s.BindUrls.Length == 0) return true;

                        return s.BindUrls.Any(b =>
                        {
                            string? url = b;

                            urlAlvo = new(url, UriKind.Absolute);

                            const int iMin = 1;
                            int i = Math.Min(urlAtual.Segments.Length, urlAlvo.Segments.Length) + 1;

                            while(--i >= iMin)
                            {
                                string partePathUrlAtual = PathUrlAtual ?? (i > 1 ? string.Join("", urlAtual.Segments[0..i]).TrimEnd('/') : pathUrlAnterior ?? "");
                                string pathUrlAlvo = urlAlvo.AbsolutePath.TrimEnd('/');

                                if (PathUrlAtual != null)
                                {
                                    i = iMin;
                                }

                                if($"{urlAlvo.Scheme}://{urlAlvo.Authority}{pathUrlAlvo}" == $"{urlAtual.Scheme}://{urlAtual.Authority}{partePathUrlAtual}"
                                    || (!configuracao.Sites.Any(ss => ss.BindUrls != null
                                            && ss.BindUrls.Contains($"{urlAtual.Scheme}://{urlAtual.Authority}{partePathUrlAtual}"))
                                        && $"{urlAlvo.Authority}{pathUrlAlvo}" == $"{urlAtual.Authority}{partePathUrlAtual}")
                                    || (!configuracao.Sites.Any(ss => ss.BindUrls != null
                                            && ss.BindUrls.Select(bu => new Uri(bu).Authority).Contains($"{urlAtual.Authority}{partePathUrlAtual}"))
                                        && $"{urlAlvo.Host}{pathUrlAlvo}" == $"{urlAtual.Host}{partePathUrlAtual}")
                                    )
                                {
                                    if (melhorBind == null || pathUrlAlvo.Length > melhorBind.AbsolutePath.Length
                                        || !(melhorBind.AbsolutePath.TrimEnd('/') + '/').StartsWith(pathUrlAlvo + '/'))
                                    {
                                        melhorBind = urlAlvo;

                                        if (pathUrlAlvo != "" && pathUrlAnterior != pathUrlAlvo)
                                        {
                                            PathUrlAtual = melhorBind.AbsolutePath;
                                        }
                                    }

                                    if (melhorBind != null && melhorBind == urlAlvo) return true;
                                }
                            }

                            return false;
                        });
                    })];

                    if (pathUrlAnterior != null)
                    {
                        if (PathUrlAtual == null)
                        {
                            if (melhorBind != null)
                            {
                                PathUrlAtual = pathUrlAnterior;
                            }
                            else
                            {
                                pathUrlAnterior = null;
                            }
                        }
                    }
                    else
                    {
                        break;
                    }
                }

                site = sites.OrderByDescending(s => s.BindUrls == null)
                    .ThenByDescending(s => s.Methods.Contains(request.Method)).ThenBy(s => s.Methods.Length)
                    .ThenBy(s => string.Join(',', s.Methods))
                    .FirstOrDefault(s => s.BindUrls == null || s.BindUrls.Any(b => new Uri(b) == melhorBind));

                string pathUrlAtual = request.GetEncodedPathAndQuery();
                string[] methodsAceitos = [request.Method, "*"];

                if (site == null || !site.Methods.Any(m => methodsAceitos.Contains(m)))
                {
                    if (urlAtual.AbsolutePath.TrimEnd('/') != "" && PathUrlAtual != null)
                    {
                        if (urlAtual.Segments.Length == 1)
                        {
                            PathUrlAtual = null;
                            PathUrlRedirectOrigem = null;
                            context.Response.RedirectPreserveMethod("/", true);
                        }
                    }
                    else
                    {
                        await next(context);

                        if (site != null)
                        {
                            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                        }
                    }
                }

                if (site != null && context.Response.StatusCode == StatusCodes.Status200OK)
                {
                    string? pathUrlAtualTemp = pathUrlAtual;
                    string? pathUrlAlvo = null;

                    urlAlvo = new(site.UrlAlvo);

                    if (!Path.HasExtension(pathUrlAtual))
                    {
                        if (urlAlvo.Segments.Length > 1)
                        {
                            pathUrlAlvo = urlAlvo.AbsolutePath.TrimEnd('/');

                            if ((pathUrlAtualTemp + '/').StartsWith(pathUrlAlvo + '/'))
                            {
                                pathUrlAtualTemp = '/' + string.Join('/', pathUrlAtualTemp.TrimStart('/').Split('/')[(urlAlvo.Segments.Length - 1)..]).TrimEnd('/');
                            }
                        }

                        if (PathUrlAtual != null && !(pathUrlAtualTemp + '/').StartsWith(PathUrlAtual + '/'))
                        {
                            pathUrlAtualTemp = $"{PathUrlAtual}{pathUrlAtualTemp}".TrimEnd('/');
                        }
                    }

                    if (pathUrlAtualTemp != pathUrlAtual)
                    {
                        PathUrlRedirectOrigem = pathUrlAtual;
                        context.Response.RedirectPreserveMethod(pathUrlAtualTemp, true);
                    }
                    else
                    {
                        site.UrlAlvo = $"{urlAlvo.Scheme}://{urlAlvo.Authority}";

                        if (pathUrlAlvo != null)
                        {
                            pathUrlAtualTemp = pathUrlAlvo;

                            if (!(pathUrlAtual + '/').StartsWith(pathUrlAtualTemp + '/'))
                            {
                                string[] pathsUrlAlvo = pathUrlAtualTemp.TrimStart('/').Split('/');

                                for (int i = pathsUrlAlvo.Length - 1; i > 0 && pathUrlAtualTemp != null; i--)
                                {
                                    string pathTeste = '/' + string.Join('/', pathsUrlAlvo[0..i]) + '/';

                                    if ((pathUrlAtual + '/').StartsWith(pathTeste))
                                    {
                                        pathUrlAtualTemp = null;
                                    }
                                }
                            }

                            if (pathUrlAtualTemp != null && pathUrlAnterior != null
                                && (PathUrlRedirectOrigem == null || (pathUrlAtualTemp + '/').StartsWith(PathUrlRedirectOrigem + '/')))
                            {
                                pathUrlAtual = pathUrlAtualTemp + pathUrlAtual;
                            }
                        }
                    }

                    if (context.Response.StatusCode == StatusCodes.Status200OK)
                    {
                        site.InicializarExecutavel();

                        if (!Path.HasExtension(pathUrlAtual) && PathUrlAtual != null && melhorBind != null && melhorBind.Segments.Length > 1
                            && pathUrlAtual.StartsWith(melhorBind.AbsolutePath.TrimEnd('/')))
                        {
                            pathUrlAtual = ('/' + string.Join('/', pathUrlAtual.TrimStart('/').Split('/')[(melhorBind.Segments.Length - 1)..])).TrimEnd('/');
                        }

                        site.UrlAlvo = $"{site.UrlAlvo}{pathUrlAtual}";
                        site.IpLocal = (context.Connection.LocalIpAddress ?? IPAddress.Loopback).ToString();
                        site.IpRemoto = (context.Connection.RemoteIpAddress ?? IPAddress.Loopback).ToString();

                        string pathAbsolutoUrlAtual = new Uri(site.UrlAlvo).AbsolutePath.TrimEnd('/');
                        string[] headersIpFw = ["X-Real-IP", "X-Forwarded-For"];
                        string[] ipsRemotosSemFw = [site.IpLocal, IPAddress.Loopback.ToString(), IPAddress.IPv6Loopback.ToString()];

                        foreach (string header in headersIpFw)
                        {
                            if (!string.IsNullOrEmpty(request.Headers[header]))
                            {
                                site.IpRemotoFw = request.Headers[header]!;

                                break;
                            }
                        }

                        if (request.Method == HttpMethods.Get && Path.HasExtension(pathAbsolutoUrlAtual)
                            && ((configuracao.ArquivosEstaticos != null && configuracao.ArquivosEstaticos != "")
                                || (site.ArquivosEstaticos != null && site.ArquivosEstaticos != "")))
                        {
                            string pathDiretorioArquivo = Site.ProcessarPath($"{configuracao.ArquivosEstaticos}" +
                                $"{site.ArquivosEstaticos}".ProcessarStringSubstituicao(site));
                            string pathArquivoEstatico = pathDiretorioArquivo + pathAbsolutoUrlAtual;
                            var arquivo = new PhysicalFileProvider(pathDiretorioArquivo).GetFileInfo(pathAbsolutoUrlAtual.TrimStart(['/', '\\']));

                            if (arquivo.Exists)
                            {
                                var provedor = new FileExtensionContentTypeProvider();
                                using var conteudoResposta = arquivo.CreateReadStream();
                                var headersResposta = site.ProcessarHeaders(context.Response.Headers.ToDictionary(), site.ResponseHeadersAdicionais);

                                foreach (var header in headersResposta.Where(h => h.Value.ToString().Length != 0))
                                {
                                    string[] valores = header.Value!;

                                    if (!context.Response.Headers.TryAdd(header.Key, valores))
                                    {
                                        context.Response.Headers.Append(header.Key, valores);
                                    }
                                };

                                context.Response.ContentLength = arquivo.Length;

                                if (provedor.TryGetContentType(pathArquivoEstatico, out string? tipoConteudo))
                                {
                                    context.Response.ContentType = tipoConteudo;
                                }

                                await context.Response.SendFileAsync(arquivo);
                                await context.Response.CompleteAsync();
                                conteudoResposta.Seek(0, SeekOrigin.Begin);
                                site.RespBody = await new StreamReader(conteudoResposta).ReadToEndAsync();
                            }
                        }

                        if (!context.Response.HasStarted)
                        {
                            string[] propsHeaders = [];
                            CookieContainer cookieContainer = new();

                            if (cookiesSites.TryGetValue(urlAlvo, out var cookie))
                            {
                                cookieContainer.SetCookies(urlAlvo, cookie);
                            }

                            HttpClientHandler clientHandler = new() { CookieContainer = cookieContainer, AllowAutoRedirect = false };

                            if (site.IgnorarCertificadoAlvo)
                            {
                                clientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                                clientHandler.ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErros) => true;
                            }

                            HttpClient httpClient = new(clientHandler);
                            Dictionary<string, StringValues> headersReq = request.Headers
                                    .Where(hr => !HeadersProibidos.Union(HeadersProibidosReq).Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase)))
                                .ToDictionary();
                            using HttpRequestMessage requestMessage = new(HttpMethod.Parse(request.Method), site.UrlAlvo);

                            if (request.Method != HttpMethods.Get)
                            {
                                request.EnableBuffering();
                                requestMessage.Content = new StreamContent(request.Body);

                                foreach (var item in requestMessage.Content.Headers.GetType().GetProperties())
                                {
                                    propsHeaders = [.. propsHeaders.Append(item.Name)];
                                };
                            }

                            headersReq = site.ProcessarHeaders(headersReq, site.RequestHeadersAdicionais);

                            foreach (var header in headersReq.Where(h => h.Value.Count != 0))
                            {
                                string[] valores = [];

                                foreach (var valor in header.Value)
                                {
                                    var valorTemp = valor;

                                    if (valorTemp != null)
                                    {
                                        valorTemp = urlAtual.ProcessarPathsHeader(valorTemp, urlAlvo);

                                        if (valorTemp == valor)
                                        {
                                            valorTemp = CookieMicroproxyRegex().Replace(valorTemp, "");
                                        }
                                    }

                                    valores = [.. valores.Append(valorTemp)];
                                }

                                requestMessage.Headers.TryAddWithoutValidation(header.Key, valores);

                                if (requestMessage.Content != null && propsHeaders.Contains(header.Key.Replace("-", "")))
                                {
                                    requestMessage.Content.Headers.TryAddWithoutValidation(header.Key, valores);
                                }
                            };

                            string ipRemoto = site.IpRemotoFw ?? site.IpRemoto;

                            if (ipRemoto != null && ipRemoto.Length > 0 && ipRemoto != site.IpLocal)
                            {
                                foreach (var header in headersIpFw.Where(h => !requestMessage.Headers.TryGetValues(h, out _)).Reverse())
                                {
                                    requestMessage.Headers.TryAddWithoutValidation(header, ipRemoto);
                                }
                            }

                            site.ReqHeaders = JsonConvert.SerializeObject(requestMessage.Headers.NonValidated.OrderBy(h => h.Key).ToDictionary(), Formatting.None, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });

                            using HttpResponseMessage response = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead);
                            using HttpContent content = response.Content;
                            Dictionary<string, string[]> headersResposta = response.Headers
                                        .Union(response.Content.Headers).ToDictionary(h => h.Key, h => h.Value.ToArray())
                                    .Where(hr => !HeadersProibidos.Union(HeadersProibidosResp).Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase)))
                                .ToDictionary();

                            context.Response.StatusCode = (int)response.StatusCode;
                            headersResposta = site.ProcessarHeaders(headersResposta, site.ResponseHeadersAdicionais);
                            site.RespHeadersPreAjuste = JsonConvert.SerializeObject(headersResposta.OrderBy(h => h.Key).ToDictionary(), Formatting.None, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });

                            if (PathUrlRedirectOrigem != null && context.Response.StatusCode >= StatusCodes.Status300MultipleChoices && context.Response.StatusCode < StatusCodes.Status400BadRequest)
                            {
                                PathUrlRedirectOrigem = response.Headers.Location!.IsAbsoluteUri ? response.Headers.Location.AbsolutePath : response.Headers.Location.OriginalString;
                            }

                            foreach (var header in headersResposta.Where(h => h.Value.Length != 0))
                            {
                                string[] valores = [];

                                foreach (var valor in header.Value)
                                {
                                    if (valor != null)
                                    {
                                        valores = [.. valores.Append(urlAtual.ProcessarPathsHeader(valor, urlAlvo))];
                                    }
                                }

                                if (!context.Response.Headers.TryAdd(header.Key, valores))
                                {
                                    context.Response.Headers.Append(header.Key, valores);
                                }
                            };

                            if (request.Method != HttpMethods.Get)
                            {
                                request.Body.Seek(0, SeekOrigin.Begin);
                                site.ReqBody = await new StreamReader(request.Body).ReadToEndAsync();
                            }

                            if (!cookiesSites.TryAdd(urlAlvo, cookieContainer.GetCookieHeader(urlAlvo)))
                            {
                                cookiesSites[urlAlvo] = cookieContainer.GetCookieHeader(urlAlvo);
                            }

                            CookiesSites = cookiesSites;

                            if (context.Response.StatusCode < StatusCodes.Status300MultipleChoices || context.Response.StatusCode >= StatusCodes.Status400BadRequest)
                            {
                                using MemoryStream memoryStream = new();
                                using Stream streamContentResp = await content.ReadAsStreamAsync();

                                memoryStream.Seek(0, SeekOrigin.Begin);
                                await streamContentResp.CopyToAsync(site.BufferResp, [memoryStream, context.Response.Body]);
                                await context.Response.CompleteAsync();
                                memoryStream.Seek(0, SeekOrigin.Begin);
                                site.RespBody = await new StreamReader(memoryStream).ReadToEndAsync();
                            }
                            else if (context.Response.StatusCode < StatusCodes.Status400BadRequest && PathUrlRedirectOrigem == null)
                            {
                                PathUrlAtual = null;
                            }

                            PathUrlRedirectOrigem = null;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                site ??= new();
                site.Exception = new(null, ex);
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            }

            site ??= new();

            lock (_lock)
            {
                foreach (var log in configuracao.Logs ?? [])
                {
                    string pathLog = Site.ProcessarPath(Site.PathInvalidCharsRegex().Replace(log.Value.Path.ProcessarStringSubstituicao(site), "_"));
                    string nomeArquivo = Site.PathInvalidCharsRegex().Replace(log.Key.ProcessarStringSubstituicao(site), "_").Trim('/').Trim('\\').Replace("/", "_").Replace(@"\", "_");

                    if (pathLog != "")
                    {
                        string mensagem = log.Value.Mensagem.ProcessarStringSubstituicao(site);
                        string[] tratamentosRegex = log.Value.TratamentoRegex ?? [];
                        int qtdTratamentos = tratamentosRegex.Length;

                        if (!Directory.Exists(pathLog))
                        {
                            Directory.CreateDirectory(pathLog);
                        }

                        for (int i = 1; i < qtdTratamentos; i += 2)
                        {
                            Regex tratamentoRegex = new(tratamentosRegex[i - 1], RegexOptions.Multiline | RegexOptions.IgnoreCase);

                            mensagem = tratamentoRegex.Replace(mensagem, tratamentosRegex[i]);
                        }

                        if (mensagem != "") File.AppendAllText($"{pathLog}/{nomeArquivo}", mensagem);
                    }
                }
            }

            if (site.Exception != null)
            {
                throw site.Exception;
            }
        }

        private static string ProcessarPathsHeader(this Uri urlAtual, string valor, Uri urlAlvo)
        {
            if ((valor.StartsWith("http") || valor.StartsWith('/'))
                && Uri.TryCreate((valor.StartsWith('/') ? $"{urlAlvo.Scheme}://{urlAlvo.Authority}" : "") + valor
                    , UriKind.Absolute, out Uri? hSite) && !Path.HasExtension(hSite.AbsolutePath)
                && (PathUrlRedirectOrigem == null || !(hSite.AbsolutePath.TrimEnd('/') + '/').StartsWith(PathUrlRedirectOrigem + '/')))
            {
                string hSitePath = hSite.AbsolutePath.TrimEnd('/');
                string pathTemp = urlAtual.AbsoluteUri;

                if (hSitePath.EndsWith(pathTemp + '/') && !hSitePath.StartsWith(pathTemp + '/'))
                {
                    valor = valor.Replace($"{hSitePath}", $"{urlAtual.AbsoluteUri}");
                }
                else if (PathUrlAtual != null && hSitePath != "")
                {
                    string novoSitePath = hSitePath;

                    if (!(novoSitePath + '/').StartsWith(PathUrlAtual + '/'))
                    {
                        novoSitePath = PathUrlAtual + novoSitePath;
                    }
                    else if (urlAlvo != null)
                    {
                        novoSitePath = ('/' + string.Join('/', hSite.Segments[(urlAlvo.Segments.Length)..])).TrimEnd('/');
                    }

                    valor = valor.Replace($"{hSitePath}", $"{novoSitePath}");
                }
            }

            return valor;
        }

        private static void RedirectPreserveMethod(this HttpResponse response, string novoDestino, bool permanent = false, string? method = null)
        {
            method ??= response.HttpContext.Request.Method;

            if (method == HttpMethods.Get)
            {
                response.Redirect(novoDestino);
            }
            else
            {
                response.Headers.Location = novoDestino;
                response.StatusCode = permanent ? StatusCodes.Status308PermanentRedirect : StatusCodes.Status307TemporaryRedirect;
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
                if (tratarRegex)
                {
                    valor = CharExpRegex().Replace(valor, "");
                }

                var variaveis = dicVariaveis ?? valor.ColetarDicionarioVariaveis(obj);

                foreach (var variavel in variaveis)
                {
                    if (variavel.Value != null)
                    {
                        valor = valor.Replace(variavel.Key, variavel.Value);
                    }
                }
            }

            return valor;
        }

        public static async Task CopyToAsync(this Stream fonte, int tambuffer, Stream[] destinos)
        {
            byte[] buffer = new byte[tambuffer];
            int bytesRead;

            if (tambuffer <= 0)
            {
                using MemoryStream memoryStream = new();

                await fonte.CopyToAsync(memoryStream);

                foreach (var destino in destinos)
                {
                    await destino.WriteAsync(memoryStream.ToArray());
                }
            }
            else
            {
                while ((bytesRead = await fonte.ReadAsync(buffer)) > 0)
                {
                    foreach (var destino in destinos)
                    {
                        await destino.WriteAsync(buffer.AsMemory(0, bytesRead));
                    }
                }
            }
        }

        [GeneratedRegex($"(?<=(?:^|(?:; *))){NOME_COOKIE}[^;]+(?:(?:; *)|(?: *$))")]
        private static partial Regex CookieMicroproxyRegex();

        [GeneratedRegex(@"##([^#]+)##")]
        private static partial Regex VariavelRegex();

        [GeneratedRegex(@"(?:\?:)|(?:(?<=[^\w])\?)|(?:\?$)|(?:\\\w)|(?:\<\w+\>)|(?:[()<>\\\^\$])")]
        private static partial Regex CharExpRegex();
    }
}
