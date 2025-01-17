using MicroProxy.Extensions;
using Microsoft.AspNetCore.Http.Extensions;
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
            get => Sessao?.GetObjectFromJson<string>(PATH_SITE);
            set { if (value != null) Sessao?.SetObjectAsJson(PATH_SITE, value); else Sessao?.Remove(PATH_SITE); }
        }

        public static async Task ProcessarRequisicao(this RequestDelegate next, HttpContext context, Configuracao configuracao)
        {
            HttpRequest request = context.Request;
            Uri urlAtual = new(request.GetDisplayUrl());
            Site? site = null;
            Uri? melhorBind = null;

            try
            {
                var cookiesSites = CookiesSites;
                Uri urlAlvo;
                Site[] sites = [.. configuracao.Sites.Where(s =>
                {
                    if (s.BindUrls == null || s.BindUrls.Length == 0) return true;

                    return s.BindUrls.Any(b =>
                    {
                        string? url = b;

                        urlAlvo = new(url, UriKind.Absolute);

                        if($"{urlAlvo.Scheme}://{urlAlvo.Authority}" == $"{urlAtual.Scheme}://{urlAtual.Authority}{PathUrlAtual}"
                            || (!configuracao.Sites.Any(ss => ss.BindUrls != null
                                    && ss.BindUrls.Contains($"{urlAtual.Scheme}://{urlAtual.Authority}{PathUrlAtual}"))
                                && urlAlvo.Authority == $"{urlAtual.Authority}{PathUrlAtual}")
                            || (!configuracao.Sites.Any(ss => ss.BindUrls != null
                                    && ss.BindUrls.Select(bu => new Uri(bu).Authority).Contains($"{urlAtual.Authority}{PathUrlAtual}"))
                                && urlAlvo.Host == $"{urlAtual.Host}{PathUrlAtual}")
                            )
                        {
                            if ((melhorBind == null || urlAtual.AbsolutePath.Length - urlAlvo.AbsolutePath.Length < melhorBind.AbsolutePath.Length - urlAlvo.AbsolutePath.Length)
                                && urlAtual.PathAndQuery.StartsWith(urlAlvo.PathAndQuery))
                            {
                                melhorBind = urlAlvo;
                            }

                            if (melhorBind != null && melhorBind == urlAlvo) return true;
                        }

                        return false;
                    });
                })];

                site = sites.OrderByDescending(s => s.Methods.Contains(request.Method)).ThenBy(s => s.Methods.Length)
                    .ThenBy(s => string.Join(',', s.Methods))
                    .FirstOrDefault();

                string pathUrlAtual = request.GetEncodedPathAndQuery();
                string[] methodsAceitos = [request.Method, "*"];

                if (site == null || !site.Methods.Any(m => methodsAceitos.Contains(m)))
                {
                    if (urlAtual.AbsolutePath != "/" && PathUrlAtual != null)
                    {
                        var paths = urlAtual.AbsolutePath.Trim('/').Split('/');

                        if (paths.Length == 1)
                        {
                            PathUrlAtual = null;
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
                    urlAlvo = new(site.UrlAlvo);

                    if (melhorBind != null && melhorBind.AbsolutePath != "/")
                    {
                        var paths = melhorBind.AbsolutePath.Trim('/').Split('/');

                        if (PathUrlAtual == null || paths.Length == 1)
                        {
                            PathUrlAtual = $"/{paths[0]}";
                        }

                        if (!pathUrlAtual.StartsWith(PathUrlAtual))
                        {
                            context.Response.RedirectPreserveMethod(PathUrlAtual + pathUrlAtual, true);
                        }
                    }

                    if (context.Response.StatusCode == StatusCodes.Status200OK)
                    {
                        if (PathUrlAtual != null)
                        {
                            pathUrlAtual = '/' + string.Join('/', pathUrlAtual.TrimStart('/').Split('/')[1..]);
                        }

                        string[] headersIpFw = ["X-Real-IP", "X-Forwarded-For"];

                        site.IpLocal = (context.Connection.LocalIpAddress ?? IPAddress.Loopback).ToString();
                        site.IpRemoto = (context.Connection.RemoteIpAddress ?? IPAddress.Loopback).ToString();

                        string[] ipsRemotosSemFw = [site.IpLocal, IPAddress.Loopback.ToString(), IPAddress.IPv6Loopback.ToString()];
                        string[] propsHeaders = [];
                        CookieContainer cookieContainer = new();

                        if (cookiesSites.TryGetValue(urlAlvo, out var cookie))
                        {
                            cookieContainer.SetCookies(urlAlvo, cookie);
                        }

                        HttpClientHandler clientHandler = new() { CookieContainer = cookieContainer, AllowAutoRedirect = false };

                        site.InicializarExecutavel();

                        foreach (string header in headersIpFw)
                        {
                            if (!string.IsNullOrEmpty(request.Headers[header]))
                            {
                                site.IpRemotoFw = request.Headers[header]!;

                                break;
                            }
                        }

                        if (site.IgnorarCertificadoAlvo)
                        {
                            clientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                            clientHandler.ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErros) => true;
                        }

                        site.UrlAlvo = $"{site.UrlAlvo}{pathUrlAtual}";

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
                                    Regex cookieProxy = CookieMicroproxyRegex();
                                    valorTemp = cookieProxy.Replace(valorTemp, "");
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

                        site.ReqHeaders = JsonConvert.SerializeObject(requestMessage.Headers.NonValidated.OrderBy(h => h.Key).ToDictionary(), Formatting.None, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }); ;

                        using HttpResponseMessage response = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
                        using HttpContent content = response.Content;
                        Dictionary<string, string[]> headersResposta = response.Headers
                                    .Union(response.Content.Headers).ToDictionary(h => h.Key, h => h.Value.ToArray())
                                .Where(hr => !HeadersProibidos.Union(HeadersProibidosResp).Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase)))
                            .ToDictionary();

                        headersResposta = site.ProcessarHeaders(headersResposta, site.ResponseHeadersAdicionais);
                        site.RespHeadersPreAjuste = JsonConvert.SerializeObject(headersResposta.OrderBy(h => h.Key).ToDictionary(), Formatting.None, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore }); ;

                        foreach (var header in headersResposta.Where(h => h.Value.Length != 0))
                        {
                            string[] valores = header.Value;

                            if (!context.Response.Headers.TryAdd(header.Key, valores))
                            {
                                context.Response.Headers.Append(header.Key, valores);
                            }
                        };

                        context.Response.StatusCode = (int)response.StatusCode;

                        if (!cookiesSites.TryAdd(urlAlvo, cookieContainer.GetCookieHeader(urlAlvo)))
                        {
                            cookiesSites[urlAlvo] = cookieContainer.GetCookieHeader(urlAlvo);
                        }

                        CookiesSites = cookiesSites;

                        if (request.Method != HttpMethods.Get)
                        {
                            request.Body.Seek(0, SeekOrigin.Begin);
                            site.ReqBody = await new StreamReader(request.Body).ReadToEndAsync();
                        }

                        if (context.Response.StatusCode < 300 || context.Response.StatusCode >= 400)
                        {
                            using MemoryStream memoryStream = new();
                            using Stream streamContentResp = await content.ReadAsStreamAsync();

                            memoryStream.Seek(0, SeekOrigin.Begin);
                            await streamContentResp.CopyToAsync(site.BufferResp, [memoryStream, context.Response.Body]);
                            memoryStream.Seek(0, SeekOrigin.Begin);
                            site.RespBody = await new StreamReader(memoryStream).ReadToEndAsync();
                        }

                        await context.Response.CompleteAsync();
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
