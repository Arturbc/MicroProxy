using MicroProxy.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Primitives;
using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

internal static class Program
{
    static string[] HeadersProibidos => ["Transfer-Encoding"];
    static readonly CookieContainer CookieContainer = new();
    static Process[] Executaveis = [];
    private static void Main(string[] args)
    {
        Configuracao configuracao = new();
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
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
        Site site = sites.First(s =>
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

            pathUrlAlvo = urlAlvo.AbsolutePath;

            return !urlAlvo.IsWellFormedOriginalString() || request.Path.StartsWithSegments(urlAlvo.AbsolutePath.TrimEnd('/'));
        });
        string[] headersIpFw = ["X-Real-IP", "X-Forwarded-For"];
        string ipRemoto = (context.Connection.RemoteIpAddress ?? IPAddress.Loopback).ToString();
        string ipLocal = (context.Connection.LocalIpAddress ?? IPAddress.Loopback).ToString();
        string[] ipsRemotosSemFw = [ipLocal, IPAddress.Loopback.ToString(), IPAddress.IPv6Loopback.ToString()];
        string[] propsHeaders = [];
        HttpClientHandler clientHandler = new() { CookieContainer = CookieContainer };

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
                ProcessStartInfo info = new() { WorkingDirectory = pathExe, FileName = exeName };

                exec = Process.Start(info);
                Executaveis = [.. Executaveis.Where(e => !e.HasExited).Append(exec)];
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

        string pathUrlAtual = request.GetEncodedPathAndQuery();

        if (pathUrlAlvo != "")
        {
            Regex pathUrlAlvoRegex = new($"^{pathUrlAlvo}", RegexOptions.IgnoreCase);

            pathUrlAtual = pathUrlAlvoRegex.Replace(pathUrlAtual, "", 1);
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

        foreach (var header in headersReq)
        {
            string?[] valor = !header.Key.Equals("Host", StringComparison.CurrentCultureIgnoreCase) ? [.. header.Value] : [urlAtual.Host];

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

        await next(context);
        context.Response.StatusCode = (int)response.StatusCode;

        if (context.Response.StatusCode < 300 || context.Response.StatusCode >= 400)
        {
            await content.CopyToAsync(context.Response.Body).ConfigureAwait(false);
        }

        await context.Response.CompleteAsync();
    }
}