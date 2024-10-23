using MicroProxy.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Primitives;
using System.Linq;
using System.Net;
using System.Net.Mime;
using System.Text;
using System.Text.RegularExpressions;

internal static partial class Program
{
    static readonly CookieContainer CookieContainer = new();
    private static void Main(string[] args)
    {
        Configuracao configuracao = new();
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.


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

        app.Use(async (context, next) =>
        {
            await next.ProcessarRequisicao(context, configuracao);
        });

        app.Run();
    }
    private static async Task ProcessarRequisicao(this RequestDelegate next, HttpContext context, Configuracao configuracao)
    {
        HttpClientHandler clientHandler = new() { CookieContainer = CookieContainer };
        HttpClient httpClient = new(clientHandler);
        string body;
        var request = context.Request;
        var headersReq = request.Headers;
        string hostAlvo = new Uri(request.GetDisplayUrl()).Host;
        HttpRequestMessage requestMessage = new(HttpMethod.Parse(request.Method), $"{configuracao.UrlAlvo}{request.GetEncodedPathAndQuery()}");

        foreach (var item in headersReq)
        {
            var valor = !item.Key.Equals("Host", StringComparison.CurrentCultureIgnoreCase) ? item.Value.ToArray() : [hostAlvo];

            request.Headers.TryAdd(item.Key, valor);
        };

        if (request.Method != HttpMethods.Get)
        {
            request.EnableBuffering();
            body = await new StreamReader(request.Body).ReadToEndAsync();
            requestMessage.Content = new StringContent(body, Encoding.UTF8, MediaTypeNameRegex().Match(headersReq.ContentType.ToString()).Value);
        }

        using var response = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        using var content = response.Content;
        
        var headersResposta = response.Headers
            .Union(response.Content.Headers).ToDictionary(h => h.Key, h => h.Value.ToArray())
            .Union(configuracao.ResponseHeadersAdicionais).ToDictionary();

        foreach (var item in headersResposta.Where(k => !k.Key.Equals("Transfer-Encoding", StringComparison.CurrentCultureIgnoreCase)))
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

    [GeneratedRegex("[^;]+")]
    private static partial Regex MediaTypeNameRegex();
}