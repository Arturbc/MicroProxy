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
        var request = context.Request;
        var headersReq = request.Headers;
        string hostAlvo = new Uri(request.GetDisplayUrl()).Host;
        HttpClient httpClient = new(clientHandler);
        string body;
        HttpRequestMessage requestMessage = new(HttpMethod.Parse(request.Method), $"{configuracao.UrlAlvo}{request.GetEncodedPathAndQuery()}");

        foreach (var chave in headersReq.Keys)
        {
            var valor = !chave.Equals("Host", StringComparison.CurrentCultureIgnoreCase) ? headersReq[chave].ToArray<string>() : [hostAlvo];

            httpClient.DefaultRequestHeaders.TryAddWithoutValidation(chave, valor);
        };

        if (request.Method != HttpMethods.Get)
        {
            request.EnableBuffering();
            body = await new StreamReader(request.Body).ReadToEndAsync();
            requestMessage.Content = new StringContent(body, Encoding.UTF8, MediaTypeNames.Application.Json);
        }

        var response = await httpClient.SendAsync(requestMessage);
        var headersResposta = response.Headers.ToDictionary();

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
            var conteudo = await response.Content.ReadAsByteArrayAsync();

            context.Response.OnStarting(() => context.Response.BodyWriter.WriteAsync(conteudo).AsTask());
            await context.Response.StartAsync();
        }

        await context.Response.CompleteAsync();
    }
}