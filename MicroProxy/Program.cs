using MicroProxy.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Primitives;
using System.Net;

internal static class Program
{
    static string[] HeadersProibidos => ["Transfer-Encoding"];
    static readonly CookieContainer CookieContainer = new();
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
            
            if (configuracao.CertificadoPrivado == null || string.IsNullOrEmpty(configuracao.PortaHttpRedirect))
            {
                porta = int.Parse(configuracao.PortaHttpRedirect ?? configuracao.Porta ?? "80");
                serverOptions.Listen(ip, porta);
            }
        });
#endif

        var app = builder.Build();

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
    }
    private static async Task ProcessarRequisicao(this RequestDelegate next, HttpContext context, Configuracao configuracao)
    {
        string[] headersIpFw = ["X-Real-IP", "X-Forwarded-For"];
        string ipRemoto = (context.Connection.RemoteIpAddress ?? IPAddress.Loopback).ToString();
        string ipLocal = (context.Connection.LocalIpAddress ?? IPAddress.Loopback).ToString();
        string[] ipsRemotosSemFw = [ipLocal, IPAddress.Loopback.ToString(), IPAddress.IPv6Loopback.ToString()];
        HttpRequest request = context.Request;
        string hostAlvo = new Uri(request.GetDisplayUrl()).Host;
        Site site = configuracao.Sites.First(s => s.BindUrl == hostAlvo || string.IsNullOrEmpty(s.BindUrl));
        string[] propsHeaders = [];
        HttpClientHandler clientHandler = new() { CookieContainer = CookieContainer };

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
            .Union(site.RequestHeadersAdicionais?.ToDictionary(rha => rha.Key, rha => new StringValues (rha.Value)) ?? []).ToDictionary();
        using HttpRequestMessage requestMessage = new(HttpMethod.Parse(request.Method), $"{site.UrlAlvo}{request.GetEncodedPathAndQuery()}");

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
            string?[] valor = !header.Key.Equals("Host", StringComparison.CurrentCultureIgnoreCase) ? [.. header.Value] : [hostAlvo];

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