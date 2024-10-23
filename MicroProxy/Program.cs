using MicroProxy.Models;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Primitives;
using System.Net;
using System.Net.Mime;
using System.Text;

internal static class Program
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

        foreach (var chave in headersReq.Keys)
        {
            var valor = !chave.Equals("Host", StringComparison.CurrentCultureIgnoreCase) ? headersReq[chave].ToArray<string>() : [hostAlvo];

            request.Headers.TryAdd(chave, valor);
        };

        if (request.Method != HttpMethods.Get)
        {
            request.EnableBuffering();
            body = await new StreamReader(request.Body).ReadToEndAsync();
            requestMessage.Content = new StringContent(body, Encoding.UTF8, headersReq.ContentType.ToString());
        }

        using var response = await httpClient.SendAsync(requestMessage, HttpCompletionOption.ResponseHeadersRead).ConfigureAwait(false);
        using var content = response.Content;
        
        var headersResposta = response.Headers.Union(response.Content.Headers).ToDictionary();

        foreach (var chave in headersResposta.Keys.Where(k => !k.Equals("Transfer-Encoding", StringComparison.CurrentCultureIgnoreCase)))
        {
            StringValues valores = new(headersResposta[chave].ToArray());

            if (!context.Response.Headers.TryAdd(chave, valores))
            {
                context.Response.Headers.Append(chave, valores);
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