using MicroProxy.Models;
using static MicroProxy.Models.Configuracao;
using static MicroProxy.Models.Site;

#if !DEBUG
using System.Text.RegularExpressions;
using System.Net;
#endif

internal partial class Program
{
    private static void Main(string[] args)
    {
        Configuracao configuracao = new();

        bool https = true;
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromDays(configuracao.MinutosValidadeCookie);
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
        https = false;

        foreach (string ipStr in configuracao.Ips)
        {
            builder.WebHost.ConfigureKestrel((context, serverOptions) =>
            {
                var ipPorta = IpPortaRegex().Match(ipStr);

                if (ipPorta.Success)
                {
                    IPAddress ip = IPAddress.Parse(ipPorta.Groups["ipv4"].Success ? ipPorta.Groups["ipv4"].Value : ipPorta.Groups["ipv6"].Value);
                    var portaHttp = configuracao.PortaHttpRedirect;
                    ushort porta = ushort.Parse(ipPorta.Groups["porta"].Success ? ipPorta.Groups["porta"].Value : "80");

                    if (!https)
                    {
                        if (string.IsNullOrEmpty(configuracao.CertificadoPrivado) || portaHttp != 0)
                        {
                            if (string.IsNullOrEmpty(configuracao.CertificadoPrivado) && (ipPorta.Groups["porta"].Success || portaHttp == 0))
                            {
                                portaHttp = porta;
                            }

                            serverOptions.Listen(ip, portaHttp);
                        }
                    }

                    if (configuracao.CertificadoPrivado != null && configuracao.CertificadoPrivado != "")
                    {
                        https = true;

                        if (porta == 80)
                        {
                            porta = 443;
                        }

                        serverOptions.Listen(ip, porta, listenOptions =>
                        {
                            listenOptions.UseHttps(configuracao.CertificadoPrivado, configuracao.CertificadoPrivadoSenha);
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
            configuracao = new();
            await next.ProcessarRequisicao(context, configuracao);
        });

        configuracao.Sites.First().ExibirVariaveisDisponiveis();

        foreach (var site in configuracao.Sites.Where(s => s.ExePath != null && s.ExePath != "" && s.AutoExec).DistinctBy(s => s.BindUrls)
            .DistinctBy(s => ProcessarPath(s.ExePath!) + ProcessarPath(s.ExePathDiretorio ?? "") + s.ExeArgumentos + s.JanelaSeparada.ToString()))
        {
            site.InicializarExecutavel();
        }

        app.Run();
    }

#if !DEBUG
    [GeneratedRegex(@"(?:(?:(?<ipv4>(?:\d{1,3}\.){3}\d{1,3}))|(?:(?:\[(?=[^]]+\]:))?(?<ipv6>(?:(?:\w{1,4}:){7}\w{1,4})|(?:(?:\w{1,4}:){1,6}:(?:\w{1,4})?)|(?:(?:\w{1,4})?:(?::\w{1,4}){1,6})|(?:::))(?:(?<=\[[^]]+)\](?=:))?))(?::(?<porta>\d{1,5}))?")]
    private static partial Regex IpPortaRegex();
#endif
}