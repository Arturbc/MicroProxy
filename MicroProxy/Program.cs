using MicroProxy.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Primitives;
using System.Net;

internal static class Program
{
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
            int porta = 80;
            IPAddress ip = IPAddress.Parse(ipStr);

            if (configuracao.CertificadoPrivado != null && configuracao.CertificadoPrivadoSenha != null)
            {
                porta = int.Parse(configuracao.Porta ?? "443");
                serverOptions.Listen(ip, porta, listenOptions =>
                {
                    listenOptions.UseHttps(configuracao.CertificadoPrivado, configuracao.CertificadoPrivadoSenha);
                });
            }
            else
            {
                porta = int.Parse(configuracao.Porta ?? porta.ToString());
                serverOptions.Listen(ip, porta);
            }
        });
#endif

        var app = builder.Build();

        // Configure the HTTP request pipeline.

        if (configuracao.CertificadoPrivado != null)
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
        string[] headersProibidos = ["Transfer-Encoding"];
        string[] propsHeaders = [];
        HttpClientHandler clientHandler = new() { CookieContainer = CookieContainer };

        if (configuracao.IgnorarCertificadoAlvo)
        {
            clientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
            clientHandler.ServerCertificateCustomValidationCallback = (httpRequestMessage, cert, cetChain, policyErros) => true;
        }

        HttpClient httpClient = new(clientHandler);
        var request = context.Request;
        var hostAlvo = new Uri(request.GetDisplayUrl()).Host;
        var headersReq = request.Headers;
        using HttpRequestMessage requestMessage = new(HttpMethod.Parse(request.Method), $"{configuracao.UrlAlvo}{request.GetEncodedPathAndQuery()}");

        if (request.Method != HttpMethods.Get)
        {
            requestMessage.Content = new StreamContent(request.Body);

            foreach (var item in requestMessage.Content.Headers.GetType().GetProperties())
            {
                propsHeaders = [.. propsHeaders.Append(item.Name)];
            };
        }

        foreach (var item in headersReq.Where(hr => !headersProibidos.Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase))))
        {
            var valor = !item.Key.Equals("Host", StringComparison.CurrentCultureIgnoreCase) ? item.Value.ToArray() : [hostAlvo];

            requestMessage.Headers.TryAddWithoutValidation(item.Key, valor);

            if (requestMessage.Content != null && propsHeaders.Contains(item.Key.Replace("-", "")))
            {
                requestMessage.Content.Headers.TryAddWithoutValidation(item.Key, valor);
            }
        };

        using var response = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        using var content = response.Content;

        var headersResposta = response.Headers
            .Union(response.Content.Headers).ToDictionary(h => h.Key, h => h.Value.ToArray())
            .Union(configuracao.ResponseHeadersAdicionais).ToDictionary();

        foreach (var item in headersResposta.Where(hr => !headersProibidos.Any(hp => hr.Key.Equals(hp, StringComparison.CurrentCultureIgnoreCase))))
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