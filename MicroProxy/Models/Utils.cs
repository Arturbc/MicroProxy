using MicroProxy.Extensions;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Primitives;
using System.Net;
using System.Text.RegularExpressions;
using static MicroProxy.Models.Configuracao;

namespace MicroProxy.Models
{
    public static partial class Utils
    {
        static string[] HeadersProibidos => ["Transfer-Encoding"];
        static string[] HeadersProibidosReq => [];
        static string[] HeadersProibidosResp => [];
        static readonly HttpContextAccessor _httpContextAccessor = new();
        static ISession? Sessao => _httpContextAccessor.HttpContext?.Session;
        static Dictionary<Uri, string> CookiesSites
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
        static Dictionary<string, string> PathUrls
        {
            get
            {
                var dic = Sessao?.GetObjectFromJson<Dictionary<string, string>>(COOKIE_PATH_URLS);

                if (dic == null)
                {
                    dic = [];
                    PathUrls = dic;
                }

                return dic;
            }
            set => Sessao?.SetObjectAsJson(COOKIE_PATH_URLS, value);
        }
        public static async Task ProcessarRequisicao(this RequestDelegate next, HttpContext context, Configuracao configuracao)
        {
            var cookiesSites = CookiesSites;
            var pathUrls = PathUrls;
            string urlRedirect = "";
            HttpRequest request = context.Request;
            Uri urlAtual = new(request.GetDisplayUrl());
            Uri urlAlvo;
            Site[] sites = [.. configuracao.Sites.Where(s =>
        {
            string? url = s.BindUrl;

            if (url != null && !url.StartsWith("http", StringComparison.InvariantCultureIgnoreCase))
            {
                url = $"http://{url}";
            }

            if (url == null || !Uri.IsWellFormedUriString(url, UriKind.RelativeOrAbsolute))
            {
                return true;
            }

            urlAlvo = new(url);

            return urlAlvo.Authority == urlAtual.Authority || (!configuracao.Sites.Any(ss => ss.BindUrl == urlAtual.Authority) && urlAlvo.Host == urlAtual.Host);
        })];
            string pathUrlAlvo = "";
            Site? site = sites.FirstOrDefault(s =>
            {
                string? url = s.BindUrl;

                if (url != null && !url.StartsWith("http", StringComparison.InvariantCultureIgnoreCase))
                {
                    url = $"http://{url}";
                }

                if (url == null || !Uri.IsWellFormedUriString(url, UriKind.RelativeOrAbsolute))
                {
                    return true;
                }

                urlAlvo = new(url);

                pathUrlAlvo = urlAlvo.AbsolutePath.TrimEnd('/');

                return request.Path.StartsWithSegments(pathUrlAlvo);
            });

            string pathUrlAtual = request.GetEncodedPathAndQuery();

            if (site == null)
            {
                if (pathUrls.TryGetValue(urlAtual.Host, out var path) && sites.Length != 0)
                {
                    urlRedirect = $"{path}{pathUrlAtual}";
                    context.Response.RedirectPreserveMethod(urlRedirect, true);
                }
                else
                {
                    await next(context);
                }

                return;
            }

            urlAlvo = new(site.UrlAlvo);
            site.UrlAtual = urlAtual.AbsoluteUri;
            site.ReqMethodAtual = request.Method;

            if (pathUrlAlvo != "")
            {
                if (pathUrls.ContainsKey(urlAtual.Host))
                {
                    pathUrls.Remove(urlAtual.Host);
                }

                pathUrls.Add(urlAtual.Host, pathUrlAlvo);
                PathUrls = pathUrls;

                Regex pathUrlAlvoRegex = new($@"^{pathUrlAlvo}(?=([/?]|$))", RegexOptions.IgnoreCase);

                pathUrlAtual = pathUrlAlvoRegex.Replace(pathUrlAtual, "", 1);
            }

            string[] headersIpFw = ["X-Real-IP", "X-Forwarded-For"];
            string ipRemoto = (context.Connection.RemoteIpAddress ?? IPAddress.Loopback).ToString();
            string ipLocal = (context.Connection.LocalIpAddress ?? IPAddress.Loopback).ToString();
            string[] ipsRemotosSemFw = [ipLocal, IPAddress.Loopback.ToString(), IPAddress.IPv6Loopback.ToString()];
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
                    ipRemoto = request.Headers[header]!;

                    break;
                }
            }

            if (site.IgnorarCertificadoAlvo)
            {
                clientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                clientHandler.ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErros) => true;
            }

            HttpClient httpClient = new(clientHandler);
            Dictionary<string, StringValues> headersReq = request.Headers
                    .Where(hr => !HeadersProibidos.Union(HeadersProibidosReq).Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase)))
                .ToDictionary();
            using HttpRequestMessage requestMessage = new(HttpMethod.Parse(request.Method),
                $"{site.UrlAlvo}{pathUrlAtual}");

            if (request.Method != HttpMethods.Get)
            {
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

            if (ipRemoto != null && ipRemoto.Length > 0 && ipRemoto != ipLocal)
            {
                foreach (var header in headersIpFw.Where(h => !requestMessage.Headers.TryGetValues(h, out _)).Reverse())
                {
                    requestMessage.Headers.TryAddWithoutValidation(header, ipRemoto);
                }
            }

            using HttpResponseMessage response = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
            using HttpContent content = response.Content;
            Dictionary<string, string[]> headersResposta = response.Headers
                        .Union(response.Content.Headers).ToDictionary(h => h.Key, h => h.Value.ToArray())
                    .Where(hr => !HeadersProibidos.Union(HeadersProibidosResp).Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase)))
                .ToDictionary();

            headersResposta = site.ProcessarHeaders(headersResposta, site.ResponseHeadersAdicionais);

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

            if (context.Response.StatusCode >= 300 && context.Response.StatusCode < 400) return;

            await content.CopyToAsync(context.Response.Body).ConfigureAwait(false);
            await context.Response.CompleteAsync();
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

        public static Dictionary<string, StringValues> ProcessarHeaders(this Site site, Dictionary<string, StringValues> headersOriginais, Dictionary<string, string[]>? headersAdicionais)
            => site.ProcessarHeaders(headersOriginais.ToDictionary(h => h.Key, h => (string[])h.Value.Where(v => v != null).ToArray()!), headersAdicionais).ToDictionary(h => h.Key, h => new StringValues(h.Value));

        public static Dictionary<string, string[]> ProcessarHeaders(this Site site, Dictionary<string, string[]> headersOriginais, Dictionary<string, string[]>? headersAdicionais)
        {
            if (headersAdicionais != null)
            {
                string[] keysCoringa = ["", "*"];
                headersAdicionais = headersAdicionais.Where(v => v.Value.Length > 0).ToDictionary();

                foreach (var header in headersOriginais.Where(h => headersAdicionais.Any(ha => FlagKeySubstRegex().Replace(ha.Key, "") == h.Key || keysCoringa.Contains(ha.Key))))
                {
                    string[] valores = [];
                    var listaHeaders = headersAdicionais.Where(h => h.Key == header.Key || h.Key == "").ToDictionary();
                    var listaHeadersSubstitutos = headersAdicionais.Where(h => (FlagKeySubstRegex().Replace(h.Key, "") == header.Key && h.Key != header.Key) || h.Key == "*")
                        .ToDictionary(h => FlagKeySubstRegex().Replace(h.Key, ""), h => h.Value.Select(v => v.ProcessarStringSubstituicao(site)).ToArray());

                    if (listaHeaders.Where(l => l.Key != "").Count() < listaHeadersSubstitutos.Where(l => l.Key != "").Count())
                    {
                        if (listaHeadersSubstitutos.TryGetValue(header.Key, out var headerValores))
                        {
                            headersOriginais[header.Key] = headerValores;
                        }
                    }
                    else
                    {
                        foreach (var valor in header.Value)
                        {
                            string valorTemp = valor.ProcessarStringSubstituicao(site);

                            foreach (var headerAdicional in listaHeaders)
                            {
                                bool substituirValores = false;
                                valores = [];

                                if (listaHeadersSubstitutos.TryGetValue(headerAdicional.Key, out var headerAdicionalSubs))
                                {
                                    substituirValores = true;

                                    foreach (var valoresHeader in headerAdicional.Value)
                                    {
                                        Regex substRegex = new(valoresHeader.ProcessarStringSubstituicao(site));
                                        var valido = substRegex.IsMatch(valorTemp);

                                        if (valido)
                                        {
                                            string valorSubstitudo = headerAdicionalSubs.OrderBy(v => Math.Abs(v.Length - valorTemp.Length)).First();

                                            valorTemp = substRegex.Replace(valorTemp, valorSubstitudo);
                                            break;
                                        }
                                    }
                                }
                                else
                                {
                                    valorTemp = valorTemp.ProcessarStringSubstituicao(site, true);
                                }

                                valores = [.. valores.Append(valorTemp)];
                                headersOriginais[header.Key] = substituirValores ? valores : [.. headersOriginais[header.Key].Union(valores)];
                            }
                        }
                    }
                }

                foreach (var header in headersAdicionais.Where(h => !keysCoringa.Contains(h.Key) && !FlagKeySubstRegex().IsMatch(h.Key) && !headersOriginais.ContainsKey(h.Key)))
                {
                    string[] valores = [];

                    foreach (var valor in header.Value)
                    {
                        valores = [.. valores.Append(valor.ProcessarStringSubstituicao(site))];
                    }

                    headersOriginais.Add(header.Key, valores);
                }
            }

            return headersOriginais;
        }

        [GeneratedRegex($"(?<=(?:^|(?:; *))){NOME_COOKIE}[^;]+(?:(?:; *)|(?: *$))")]
        private static partial Regex CookieMicroproxyRegex();

        [GeneratedRegex(@"##([^#]+)##")]
        private static partial Regex VariavelRegex();

        [GeneratedRegex(@"(?:\?:)|(?:(?<=[^\w])\?)|(?:\?$)|(?:\\\w)|(?:\<\w+\>)|(?:[()<>\\\^\$])")]
        private static partial Regex CharExpRegex();

        [GeneratedRegex(@"\*([\w#-]+ *= *[\w#-]+(?=(?: *, *)|(?:$)))?$")]
        private static partial Regex FlagKeySubstRegex();

        [GeneratedRegex(@"(?:(?<=^[^a-zA-Z]):)|(?:(?<!^|(?:\w+:)|[\w.~])[\\/](?=\w))|[*?""<>|]")]
        public static partial Regex PathInvalidCharsRegex();
    }
}
