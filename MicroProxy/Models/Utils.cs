﻿using MicroProxy.Extensions;
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

        public static async Task ProcessarRequisicao(this RequestDelegate next, HttpContext context, Configuracao configuracao)
        {
            HttpRequest request = context.Request;
            Uri urlAtual = new(request.GetDisplayUrl());
            Site? site = null;

            if (request.Method != HttpMethods.Get) request.EnableBuffering();

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

                        return $"{urlAlvo.Scheme}://{urlAlvo.Authority}" == $"{urlAtual.Scheme}://{urlAtual.Authority}"
                            || (!configuracao.Sites.Any(ss => ss.BindUrls != null
                                    && ss.BindUrls.Contains($"{urlAtual.Scheme}://{urlAtual.Authority}"))
                                && urlAlvo.Authority == urlAtual.Authority)
                            || (!configuracao.Sites.Any(ss => ss.BindUrls != null
                                    && ss.BindUrls.Select(bu => new Uri(bu).Authority).Contains($"{urlAtual.Authority}"))
                                && urlAlvo.Host == urlAtual.Host);
                    });
                })];
                string pathUrlAlvo = "";

                site = sites.OrderByDescending(s => s.Methods.Contains(request.Method)).ThenBy(s => s.Methods.Length)
                    .ThenBy(s => string.Join(',', s.Methods)).FirstOrDefault(s =>
                    {
                        if (s.BindUrls == null || s.BindUrls.Length == 0) return true;

                        return s.BindUrls.Any(b =>
                        {
                            string? url = b;

                            urlAlvo = new(url);
                            pathUrlAlvo = urlAlvo.AbsolutePath.TrimEnd('/');

                            return request.Path.StartsWithSegments(pathUrlAlvo);
                        });
                    });

                string pathUrlAtual = request.GetEncodedPathAndQuery();
                string[] methodsAceitos = [request.Method, "*"];

                if (site == null || !site.Methods.Any(m => methodsAceitos.Contains(m)))
                {
                    if (sites.Length != 0 && pathUrlAlvo != "")
                    {
                        string urlRedirect = $"{pathUrlAlvo}{pathUrlAtual}";

                        context.Response.RedirectPreserveMethod(urlRedirect, true);
                    }
                    else
                    {
                        await next(context);

                        if (site != null)
                        {
                            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                        }
                    }

                    return;
                }

                urlAlvo = new(site.UrlAlvo);
                pathUrlAlvo += urlAlvo.AbsolutePath.TrimEnd('/');
                site.UrlAtual = urlAtual.AbsoluteUri;
                site.ReqMethodAtual = request.Method;

                if (pathUrlAlvo != "")
                {
                    Regex pathRegex = new($"^{pathUrlAlvo}");

                    pathUrlAtual = pathRegex.Replace(pathUrlAtual, "");

                    if (pathUrlAtual != request.GetEncodedPathAndQuery())
                    {
                        context.Response.RedirectPreserveMethod(pathUrlAtual, true);

                        return;
                    }
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

                if (request.Method != HttpMethods.Get)
                {
                    request.Body.Seek(0, SeekOrigin.Begin);
                    site.ReqBody = new StreamReader(request.Body).ReadToEnd();
                }
            }
            catch (Exception ex)
            {
                site ??= new()
                {
                    Exception = new(null, ex),
                    UrlAtual = urlAtual.AbsoluteUri,
                    ReqMethodAtual = request.Method,
                };

                if (request.Method != HttpMethods.Get)
                {
                    request.Body.Seek(0, SeekOrigin.Begin);
                    site.ReqBody = new StreamReader(request.Body).ReadToEnd();
                }
            }

            foreach (var log in configuracao.Logs ?? [])
            {
                string pathLog = Site.ProcessarPath(Site.PathInvalidCharsRegex().Replace(log.Value.Path.ProcessarStringSubstituicao(site), "_"));
                string nomeArquivo = Site.PathInvalidCharsRegex().Replace(log.Key.ProcessarStringSubstituicao(site), "_").Replace("/", "_").Replace(@"\", "_");

                if (pathLog != "")
                {
                    if (!Directory.Exists(pathLog))
                    {
                        Directory.CreateDirectory(pathLog);
                    }

                    File.AppendAllText($@"{pathLog}\{nomeArquivo}", log.Value.Mensagem.ProcessarStringSubstituicao(site));
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

        [GeneratedRegex($"(?<=(?:^|(?:; *))){NOME_COOKIE}[^;]+(?:(?:; *)|(?: *$))")]
        private static partial Regex CookieMicroproxyRegex();

        [GeneratedRegex(@"##([^#]+)##")]
        private static partial Regex VariavelRegex();

        [GeneratedRegex(@"(?:\?:)|(?:(?<=[^\w])\?)|(?:\?$)|(?:\\\w)|(?:\<\w+\>)|(?:[()<>\\\^\$])")]
        private static partial Regex CharExpRegex();
    }
}
