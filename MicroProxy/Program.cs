using MicroProxy.Extensions;
using MicroProxy.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Primitives;
using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

internal static partial class Program
{
    const string NOME_COOKIE = "Microproxy";
    const string COOKIE_SITE = "cookieSite";
    const string COOKIE_PATH_URLS = "pathUrls";
    static Configuracao Configuracao = new();
    static string[] HeadersProibidos => ["Transfer-Encoding"];
    static string[] HeadersProibidosReq => [];
    static string[] HeadersProibidosResp => [];
    static Process[] Executaveis = [];
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

    private static void Main(string[] args)
    {
        bool https = true;
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromDays(Configuracao.MinutosValidadeCookie);
            options.Cookie.Name = NOME_COOKIE;
            options.Cookie.IsEssential = true;
        });
        builder.Services.AddCors(options =>
        {
            options.AddDefaultPolicy(builder =>
            {
                builder.WithOrigins(Configuracao.AllowOrigins)
                    .WithHeaders(Configuracao.AllowHeaders)
                    .WithMethods(Configuracao.AllowMethods);

                if (!Configuracao.AllowOrigins.Contains("*"))
                {
                    builder.AllowCredentials();
                }
            });
        });

#if !DEBUG
        https = false;

        foreach (string ipStr in Configuracao.Ips)
        {
            builder.WebHost.ConfigureKestrel((context, serverOptions) =>
            {
                var ipPorta = IpPortaRegex().Match(ipStr);

                if (ipPorta.Success)
                {
                    IPAddress ip = IPAddress.Parse(ipPorta.Groups["ipv4"].Success ? ipPorta.Groups["ipv4"].Value : ipPorta.Groups["ipv6"].Value);
                    var portaHttp = Configuracao.PortaHttpRedirect;
                    ushort porta = ushort.Parse(ipPorta.Groups["porta"].Success ? ipPorta.Groups["porta"].Value : "80");

                    if (!https)
                    {
                        if (string.IsNullOrEmpty(Configuracao.CertificadoPrivado) || portaHttp != 0)
                        {
                            if (string.IsNullOrEmpty(Configuracao.CertificadoPrivado) && (ipPorta.Groups["porta"].Success || portaHttp == 0))
                            {
                                portaHttp = porta;
                            }

                            serverOptions.Listen(ip, portaHttp);
                        }
                    }

                    if (Configuracao.CertificadoPrivado != null && Configuracao.CertificadoPrivado != "")
                    {
                        https = true;

                        if (porta == 80)
                        {
                            porta = 443;
                        }

                        serverOptions.Listen(ip, porta, listenOptions =>
                        {
                            listenOptions.UseHttps(Configuracao.CertificadoPrivado, Configuracao.CertificadoPrivadoSenha);
                        });
                    }
                }
            });
        }
#endif

        var app = builder.Build();
        var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
        lifetime.ApplicationStopping.Register(OnShutdown);

        // Configure the HTTP request pipeline.

        if (https)
        {
            app.UseHttpsRedirection();
        }

        app.UseSession();
        app.UseCors();
        app.Use(async (context, next) =>
        {
            Configuracao = new();
            await next.ProcessarRequisicao(context, Configuracao);
        });

        foreach (var site in Configuracao.Sites.Where(s => s.ExePath != null && s.ExePath != "" && s.AutoExec).DistinctBy(s => s.BindUrl)
            .DistinctBy(s => ProcessarPath(s.ExePath!) + ProcessarPath(s.ExePathDiretorio ?? "") + s.ExeArgumentos + s.JanelaSeparada.ToString()))
        {
            InicializarExecutavel(site);
        }

        app.Run();

        static void OnShutdown()
        {
            foreach (var exec in Executaveis.Where(e => !e.StartInfo.CreateNoWindow || !e.Responding))
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

            urlAlvo = new(url);

            pathUrlAlvo = urlAlvo.AbsolutePath.TrimEnd('/');

            return !urlAlvo.IsWellFormedOriginalString() || request.Path.StartsWithSegments(pathUrlAlvo);
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

        HttpClientHandler clientHandler = new() { CookieContainer = cookieContainer };

        InicializarExecutavel(site);

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
            string[] valores = [];

            foreach (var valor in header.Value)
            {
                var valorTemp = valor;

                if (valorTemp != null)
                {
                    Regex cookieProxy = CookieMicroproxyRegex();
                    valorTemp = cookieProxy.Replace(valorTemp.Replace(urlAtual.Host, urlAlvo.Host), "");
                }

                valores = [.. valores.Append(valorTemp)];
            }

            requestMessage.Headers.TryAddWithoutValidation(header.Key, valores);

            if (requestMessage.Content != null && propsHeaders.Contains(header.Key.Replace("-", "")))
            {
                requestMessage.Content.Headers.TryAddWithoutValidation(header.Key, valores);
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
        using HttpContent content = response.Content;
        Dictionary<string, string[]> headersResposta = response.Headers
                    .Union(response.Content.Headers).ToDictionary(h => h.Key, h => h.Value.ToArray())
                    .Union(site.ResponseHeadersAdicionais ?? [])
                .Where(hr => !HeadersProibidos.Union(HeadersProibidosResp).Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase)))
            .ToDictionary();

        foreach (var item in headersResposta)
        {
            StringValues valores = new(item.Value);

            if (!context.Response.Headers.TryAdd(item.Key, valores))
            {
                context.Response.Headers.Append(item.Key, valores);
            }
        };

        if (!cookiesSites.TryAdd(urlAlvo, cookieContainer.GetCookieHeader(urlAlvo)))
        {
            cookiesSites[urlAlvo] = cookieContainer.GetCookieHeader(urlAlvo);
        }

        CookiesSites = cookiesSites;

        if (requestMessage.RequestUri!.PathAndQuery != pathUrlAtual)
        {
            string novoDestino = $"{pathUrlAlvo}{requestMessage.RequestUri!.PathAndQuery}";

            context.Response.RedirectPreserveMethod(novoDestino, true, requestMessage.Method.Method);

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

    private static void InicializarExecutavel(Site site)
    {
        if (!string.IsNullOrEmpty(site.ExePath))
        {
            string exePath = ProcessarPath(site.ExePath);
            string exePathDiretorio = ProcessarPath(site.ExePathDiretorio ?? "");
            string nomeProcesso = Path.GetFileNameWithoutExtension(exePath);
            string exeName = Path.GetFileName(exePath);
            string pathExe = string.IsNullOrEmpty(exePathDiretorio) ?
                exePath.Replace(@$"\{exeName}", "") : exePathDiretorio;
            bool consulta(Process e) => e.ProcessName == nomeProcesso && e.StartInfo.FileName == exePath
                && e.StartInfo.WorkingDirectory == pathExe && e.StartInfo.Arguments == site.ExeArgumentos
                && e.StartInfo.CreateNoWindow == !site.JanelaSeparada;


            var exec = Executaveis.FirstOrDefault(consulta);

            exec ??= Process.GetProcesses().Where(consulta).FirstOrDefault(p => p.Id != Environment.ProcessId);

            if (exec != null)
            {
                Executaveis = [.. Executaveis.Where(e => !e.HasExited).Append(exec)];

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
                ProcessStartInfo info = new() { FileName = exePath, WorkingDirectory = pathExe, Arguments = site.ExeArgumentos, CreateNoWindow = !site.JanelaSeparada };

                exec = Process.Start(info);
                Executaveis = [.. Executaveis.Where(e => !e.HasExited).Append(exec)];
            }
        }
    }

    private static string ProcessarPath(string path)
    {
        if (path.Trim() != "")
        {
            path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
        }

        return path;
    }

    [GeneratedRegex($"(?<=(^|(; *))){NOME_COOKIE}[^;]+; *")]
    private static partial Regex CookieMicroproxyRegex();
    [GeneratedRegex(@"(?:(?:(?<ipv4>(?:\d{1,3}\.){3}\d{1,3}))|(?:(?:\[(?=[^]]+\]:))?(?<ipv6>(?:(?:\w{1,4}:){7}\w{1,4})|(?:(?:\w{1,4}:){1,6}:(?:\w{1,4})?)|(?:(?:\w{1,4})?:(?::\w{1,4}){1,6})|(?:::))(?:(?<=\[[^]]+)\](?=:))?))(?::(?<porta>\d{1,5}))?")]
    private static partial Regex IpPortaRegex();
}