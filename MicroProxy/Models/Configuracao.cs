using MicroProxy.DTOs;
using MicroProxy.Helpers;
using Microsoft.Extensions.Hosting.WindowsServices;

namespace MicroProxy.Models
{
    public partial class Configuracao
    {
        public const int MAX_BUFFER_SSL = 65536;
        public const string NOME_COOKIE = "Microproxy";
        public const string COOKIE_SITE = "cookieSite";
        public const string PATH_SITE_ATUAL = "pathSiteAtual";
        public const string PATH_SITE_ORIGEM_REDIRECT = "pathSiteOrigemRedirect";
        private static bool AvisosExibidos = false;
        private ConexaoEscutaDTO[]? _conexoesEscuta;
        protected IConfigurationRoot ConfigurationRoot { get; set; } = null!;
        public Dictionary<string, Log>? Logs { get; protected set; }
        public uint MinutosValidadeCookie { get; protected set; }
        public ConexaoEscutaDTO[] ConexoesEscuta
        {
            get
            {
                List<ConexaoEscutaDTO> ce = [.. _conexoesEscuta ?? []];

                if (IP != null && !ce.Any(c => c.IP.Equals(IP)))
                {
                    ce.Add(new()
                    {
                        IP = IP,
                        CertificadoPrivado = CertificadoPrivado,
                        CertificadoPrivadoChave = CertificadoPrivadoChave,
                        CertificadoPrivadoSenha = CertificadoPrivadoSenha
                    });
                }

                return [.. ce];
            }

            protected set => _conexoesEscuta = [.. value.Where(c => IP == null || c.CertificadoPrivado != null || !c.IP.Equals(IP))];
        }
        public string[] IPs
        {
            get => [.. ConexoesEscuta.Select(c => c.IP).Distinct()];
            protected set
            {
                List<string> ips = [.. value];

                ips.RemoveAll(i => i == IP || ConexoesEscuta.Any(c => c.IP.Equals(i)));

                ConexoesEscuta = [.. ConexoesEscuta.Union(ips
                    .Select(v => new ConexaoEscutaDTO() { IP = v, CertificadoPrivado = CertificadoPrivado,
                        CertificadoPrivadoChave = CertificadoPrivadoChave,
                        CertificadoPrivadoSenha = CertificadoPrivadoSenha
                    }))];

                if (!string.IsNullOrEmpty(CertificadoPrivado))
                {
                    foreach (var conexaoEscuta in ConexoesEscuta.Where(c => string.IsNullOrEmpty(c.CertificadoPrivado)))
                    {
                        conexaoEscuta.CertificadoPrivado = CertificadoPrivado;
                        conexaoEscuta.CertificadoPrivadoChave = CertificadoPrivadoChave;
                        conexaoEscuta.CertificadoPrivadoSenha = CertificadoPrivadoSenha;
                    }
                }
            }
        }
        public string? IP { get; protected set; }
        public string[] IpsBloqueados { get; protected set; } = null!;
        public ushort PortaHttp { get; protected set; }
        public bool RedirectPortaHttp { get; protected set; }
        public bool SolicitarCertificadoCliente { get; protected set; }
        public string? CertificadoPrivado { get; protected set; }
        public string? CertificadoPrivadoChave { get; protected set; }
        public string? CertificadoPrivadoSenha { get; protected set; }
        public int BufferReq { get; protected set; }
        public int BufferResp { get; protected set; }
        public bool SemDelay { get; protected set; }
        public string? ArquivosEstaticos { get; protected set; }
        public string? CompressionResponse { get; protected set; }
        public string? TratamentoErroInterno { get; protected set; }
        public string[] ExtensoesUrlNaoRecurso { get; protected set; }
        public Site[] Sites { get; protected set; }
        public string[] AllowOrigins { get; protected set; }
        public string[] AllowHeaders { get; protected set; }
        public string[] AllowMethods { get; protected set; }

        static Configuracao() { if (WindowsServiceHelpers.IsWindowsService()) { Directory.SetCurrentDirectory(AppContext.BaseDirectory); } }

        public Configuracao()
        {
            var configurationBuilder0 = new ConfigurationBuilder();
            var path0 = Path.GetFullPath("appsettings.json");

            configurationBuilder0.AddJsonFile(path0, false);
            ConfigurationRoot = configurationBuilder0.Build();

            Logs = ConfigurationRoot.GetSection(nameof(Logs)).Get<Dictionary<string, Log>>();
            MinutosValidadeCookie = ConfigurationRoot.GetValue<uint>(nameof(MinutosValidadeCookie));
            SolicitarCertificadoCliente = ConfigurationRoot.GetValue<bool>(nameof(SolicitarCertificadoCliente));
            CertificadoPrivado = ConfigurationRoot.GetValue<string>(nameof(CertificadoPrivado))?.Trim();
            CertificadoPrivadoChave = ConfigurationRoot.GetValue<string>(nameof(CertificadoPrivadoChave))?.Trim();
            CertificadoPrivadoSenha = ConfigurationRoot.GetValue<string>(nameof(CertificadoPrivadoSenha));

            if (CertificadoPrivado == "") { CertificadoPrivado = null; }
            if (CertificadoPrivadoChave == "") { CertificadoPrivadoChave = null; }
            if (CertificadoPrivadoSenha == "") { CertificadoPrivadoSenha = null; }
            if (!string.IsNullOrEmpty(CertificadoPrivadoSenha))
            {
                var novosDados = FuncoesHelper.TratarDadosSensiveis(new Dictionary<string, string?>() { { nameof(CertificadoPrivadoSenha), CertificadoPrivadoSenha } },
                    !AvisosExibidos ? "autenticação do certificado" : "");

                if (!novosDados.TryGetValue(nameof(CertificadoPrivadoSenha), out var senhaDecifrada)) { senhaDecifrada = CertificadoPrivadoSenha; }

                CertificadoPrivadoSenha = senhaDecifrada;
            }

            IPs = ConfigurationRoot.GetSection(nameof(IPs)).Get<string[]>() ?? [];
            IP = ConfigurationRoot.GetValue<string>(nameof(IP));
            ConexoesEscuta = ConfigurationRoot.GetSection(nameof(ConexoesEscuta)).Get<ConexaoEscutaDTO[]>() ?? [];
            IpsBloqueados = ConfigurationRoot.GetSection(nameof(IpsBloqueados)).Get<string[]>() ?? [];
            PortaHttp = ConfigurationRoot.GetValue<ushort?>(nameof(PortaHttp)) ?? 0;
            RedirectPortaHttp = ConfigurationRoot.GetValue<bool>(nameof(RedirectPortaHttp));
            ArquivosEstaticos = ConfigurationRoot.GetValue<string>(nameof(ArquivosEstaticos));
            CompressionResponse = ConfigurationRoot.GetValue<string>(nameof(CompressionResponse));
            TratamentoErroInterno = ConfigurationRoot.GetValue<string>(nameof(TratamentoErroInterno));
            BufferReq = ConfigurationRoot.GetValue<int>(nameof(BufferReq));
            BufferResp = ConfigurationRoot.GetValue<int>(nameof(BufferResp));
            SemDelay = ConfigurationRoot.GetValue<bool>(nameof(SemDelay));
            ExtensoesUrlNaoRecurso = ConfigurationRoot.GetSection(nameof(ExtensoesUrlNaoRecurso)).Get<string[]>() ?? [];
            Sites = ConfigurationRoot.GetSection(nameof(Sites)).Get<Site[]>()!;
            AllowOrigins = ConfigurationRoot.GetSection($"Cors:{nameof(AllowOrigins)}").Get<string[]>() ?? [];
            AllowHeaders = ConfigurationRoot.GetSection($"Cors:{nameof(AllowHeaders)}").Get<string[]>() ?? [];
            AllowMethods = ConfigurationRoot.GetSection($"Cors:{nameof(AllowMethods)}").Get<string[]>() ?? [];

            if (AllowOrigins.Length == 0) AllowOrigins = ["*"];
            if (AllowHeaders.Length == 0) AllowHeaders = ["*"];
            if (AllowMethods.Length == 0) AllowMethods = ["*"];

            AvisosExibidos = true;
        }
    }
}
