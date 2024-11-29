using MicroProxy.Extensions;
using MicroProxy.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json.Linq;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Text.RegularExpressions;

internal static class Program
{
    const string NOME_COOKIE = "Microproxy";
    const string COOKIE_COOKIE = "cookieSite";
    const string COOKIE_PATH_URLS = "pathUrls";
    static string[] HeadersProibidos => ["Transfer-Encoding"];
    static Process[] Executaveis = [];
    static readonly HttpContextAccessor _httpContextAccessor = new();
    static ISession? Sessao => _httpContextAccessor.HttpContext?.Session;
    static CookieContainer CookieContainer
    {
        get
        {
            var container = Sessao?.GetObjectFromJson<CookieContainer>(COOKIE_COOKIE);

            if (container == null)
            {
                container = new();
                CookieContainer = container;
            }

            return container;
        }
        set => Sessao?.SetObjectAsJson(COOKIE_COOKIE, value);
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

    private static void Main(string[] args)
    {
        Configuracao configuracao = new();
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.MaxValue;
            options.Cookie.Name = NOME_COOKIE;
            options.Cookie.IsEssential = true;
        });
        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(builder =>
            {
                builder.WithOrigins(configuracao.AllowOrigins)
                    .WithHeaders(configuracao.AllowHeaders)
                    .WithMethods(configuracao.AllowMethods);

                if (!configuracao.AllowOrigins.Contains("*"))
                {
                    builder.AllowCredentials();
                }
            });
        });

#if !DEBUG
        builder.WebHost.ConfigureKestrel((context, serverOptions) =>
        {
            string ipStr = configuracao.Ip ?? IPAddress.Loopback.ToString();
            int porta;
            IPAddress ip = IPAddress.Parse(ipStr);

            if (configuracao.CertificadoPrivado != null && configuracao.CertificadoPrivado != "")
            {
                porta = int.Parse(configuracao.Porta ?? "443");
                serverOptions.Listen(ip, porta, listenOptions =>
                {
                    listenOptions.UseHttps(configuracao.CertificadoPrivado, configuracao.CertificadoPrivadoSenha);
                });
            }
            
            if (string.IsNullOrEmpty(configuracao.CertificadoPrivado) || !string.IsNullOrEmpty(configuracao.PortaHttpRedirect))
            {
                porta = int.Parse(configuracao.PortaHttpRedirect ?? configuracao.Porta ?? "80");
                serverOptions.Listen(ip, porta);
            }
        });
#endif

        var app = builder.Build();
        var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
        lifetime.ApplicationStopping.Register(OnShutdown);

        // Configure the HTTP request pipeline.

        if (!string.IsNullOrEmpty(configuracao.PortaHttpRedirect) && !string.IsNullOrEmpty(configuracao.CertificadoPrivado))
        {
            app.UseHttpsRedirection();
        }

        app.UseSession();
        app.UseCors();
        app.Use(async (context, next) =>
        {
            configuracao = new();
            await next.ProcessarRequisicao(context, configuracao);
        });

        app.Run();

        static void OnShutdown()
        {
            foreach (var exec in Executaveis)
            {
                if (!exec.HasExited)
                {
                    exec.Close();
                }
            }
        }
    }
    private static async Task ProcessarRequisicao(this RequestDelegate next, HttpContext context, Configuracao configuracao)
    {
        var cookieContainer = CookieContainer;
        var pathUrls = PathUrls;
        string urlRedirect = "";
        HttpRequest request = context.Request;
        Uri urlAtual = new(request.GetDisplayUrl());
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

            Uri urlAlvo = new(url);

            return !urlAlvo.IsWellFormedOriginalString() || urlAlvo.Host == urlAtual.Host;
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

            Uri urlAlvo = new(url);

            pathUrlAlvo = urlAlvo.AbsolutePath.TrimEnd('/');

            return !urlAlvo.IsWellFormedOriginalString() || request.Path.StartsWithSegments(pathUrlAlvo);
        });

        string pathUrlAtual = request.GetEncodedPathAndQuery();

        if (site == null)
        {
            if (pathUrls.TryGetValue(urlAtual.Host, out var path) && sites.Length != 0)
            {
                urlRedirect = $"{path}{pathUrlAtual}";
                pathUrlAlvo = path;
                site = sites.First(s => s.BindUrl == $"{urlAtual.Host}{path}");
            }
            else
            {
                await next(context);
                return;
            }
        }

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
        HttpClientHandler clientHandler = new() { CookieContainer = cookieContainer };

        if (!string.IsNullOrEmpty(site.ExePath))
        {
            string nomeProcesso = Path.GetFileNameWithoutExtension(site.ExePath);
            var exec = Executaveis.FirstOrDefault(e => e.ProcessName == nomeProcesso);

            exec ??= Process.GetProcessesByName(nomeProcesso).FirstOrDefault(p => p.Id != Environment.ProcessId);

            if (exec != null)
            {
                if (!exec.Responding)
                {
                    if (!exec.HasExited)
                    {
                        exec.Kill();
                    }

                    exec = null;
                }
            }

            if (exec == null)
            {
                string exeName = Path.GetFileName(site.ExePath);
                string pathExe = string.IsNullOrEmpty(site.ExePathDiretorio) ?
                    Path.GetFullPath(site.ExePath).Replace(@$"\{exeName}", "") : Path.GetFullPath(site.ExePathDiretorio);
                ProcessStartInfo info = new() { WorkingDirectory = pathExe, FileName = exeName, CreateNoWindow = site.JanelaSeparada };

                exec = Process.Start(info);

                if (!site.JanelaSeparada)
                {
                    Executaveis = [.. Executaveis.Where(e => !e.HasExited).Append(exec)];
                }
            }
        }

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
                .Where(hr => !HeadersProibidos.Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase)))
            .Union(site.RequestHeadersAdicionais?.ToDictionary(rha => rha.Key, rha => new StringValues(rha.Value)) ?? []).ToDictionary();
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

        foreach (var header in headersReq.Where(h => h.Value.Count != 0))
        {
            string?[] valor = [.. header.Value];

            if (header.Key.Equals("Host", StringComparison.CurrentCultureIgnoreCase)) valor = [new Uri(site.UrlAlvo).Host];
            else if (header.Key.Equals("Referer", StringComparison.CurrentCultureIgnoreCase))
                valor = [requestMessage.RequestUri!.OriginalString.Replace(requestMessage.RequestUri!.PathAndQuery, "/")];
            else if (header.Key.Equals("Origin", StringComparison.CurrentCultureIgnoreCase))
                valor = [requestMessage.RequestUri!.OriginalString.Replace(requestMessage.RequestUri!.PathAndQuery, "")];

            requestMessage.Headers.TryAddWithoutValidation(header.Key, valor);

            if (requestMessage.Content != null && propsHeaders.Contains(header.Key.Replace("-", "")))
            {
                requestMessage.Content.Headers.TryAddWithoutValidation(header.Key, valor);
            }
        };

        if (ipRemoto != null && ipRemoto != "" && ipRemoto != ipLocal)
        {
            foreach (var header in headersIpFw.Where(h => !requestMessage.Headers.TryGetValues(h, out _)).Reverse())
            {
                requestMessage.Headers.TryAddWithoutValidation(header, ipRemoto);
            }
        }

        using HttpResponseMessage response = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);

        CookieContainer = cookieContainer;

        using HttpContent content = response.Content;
        Dictionary<string, string[]> headersResposta = response.Headers
                    .Union(response.Content.Headers).ToDictionary(h => h.Key, h => h.Value.ToArray())
                    .Union(site.ResponseHeadersAdicionais ?? [])
                .Where(hr => !HeadersProibidos.Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase)))
            .ToDictionary();

        foreach (var item in headersResposta)
        {
            StringValues valores = new(item.Value);

            if (!context.Response.Headers.TryAdd(item.Key, valores))
            {
                context.Response.Headers.Append(item.Key, valores);
            }
        };

        if (requestMessage.RequestUri!.PathAndQuery != pathUrlAtual || urlRedirect != "")
        {
            string novoDestino = $"{pathUrlAlvo}{requestMessage.RequestUri!.PathAndQuery}";

            if (requestMessage.Method.Method == HttpMethods.Get)
            {
                context.Response.Redirect(novoDestino);
            }
            else
            {
                context.Response.Headers.Location = novoDestino;
                context.Response.StatusCode = StatusCodes.Status308PermanentRedirect;
            }

            return;
        }

        await next(context);
        context.Response.StatusCode = (int)response.StatusCode;

        if (context.Response.StatusCode < 300 || context.Response.StatusCode >= 400)
        {
            await content.CopyToAsync(context.Response.Body).ConfigureAwait(false);
        }

        await context.Response.CompleteAsync();
    }
}