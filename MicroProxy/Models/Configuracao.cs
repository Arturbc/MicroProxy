namespace MicroProxy.Models
{
    public partial class Configuracao
    {
        public const string NOME_COOKIE = "Microproxy";
        public const string COOKIE_SITE = "cookieSite";
        public const string PATH_SITE_ATUAL = "pathSiteAtual";
        public const string PATH_SITE_ORIGEM_REDIRECT = "pathSiteOrigemRedirect";
        protected IConfigurationRoot ConfigurationRoot { get; set; } = null!;
        public Dictionary<string, Log>? Logs { get; protected set; }
        public uint MinutosValidadeCookie { get; protected set; }
        public string[] Ips { get; protected set; } = null!;
        public string[] IpsBloqueados { get; protected set; } = null!;
        public ushort PortaHttp { get; protected set; }
        public bool RedirectPortaHttp { get; protected set; }
        public bool SolicitarCertificadoCliente { get; protected set; }
        public string? CertificadoPrivado { get; protected set; }
        public string? CertificadoPrivadoChave { get; protected set; }
        public string? CertificadoPrivadoSenha { get; protected set; }
        public string? ArquivosEstaticos { get; protected set; }
        public string? CompressionResponse { get; protected set; }
        public string? TratamentoErroInterno { get; protected set; }
        public string[] ExtensoesUrlNaoRecurso { get; protected set; }
        public Site[] Sites { get; protected set; }
        public string[] AllowOrigins { get; protected set; }
        public string[] AllowHeaders { get; protected set; }
        public string[] AllowMethods { get; protected set; }

        public Configuracao()
        {
            var configurationBuilder0 = new ConfigurationBuilder();
            var path0 = Path.GetFullPath("appsettings.json");

            configurationBuilder0.AddJsonFile(path0, false);
            ConfigurationRoot = configurationBuilder0.Build();

            Logs = ConfigurationRoot.GetSection(nameof(Logs)).Get<Dictionary<string, Log>>();
            MinutosValidadeCookie = ConfigurationRoot.GetValue<uint>(nameof(MinutosValidadeCookie));
            Ips = ConfigurationRoot.GetSection(nameof(Ips)).Get<string[]>() ?? [];
            IpsBloqueados = ConfigurationRoot.GetSection(nameof(IpsBloqueados)).Get<string[]>() ?? [];
            PortaHttp = ConfigurationRoot.GetValue<ushort?>(nameof(PortaHttp)) ?? 0;
            RedirectPortaHttp = ConfigurationRoot.GetValue<bool>(nameof(RedirectPortaHttp));
            SolicitarCertificadoCliente = ConfigurationRoot.GetValue<bool>(nameof(SolicitarCertificadoCliente));
            CertificadoPrivado = ConfigurationRoot.GetValue<string>(nameof(CertificadoPrivado))?.Trim();
            CertificadoPrivadoChave = ConfigurationRoot.GetValue<string>(nameof(CertificadoPrivadoChave))?.Trim();
            CertificadoPrivadoSenha = ConfigurationRoot.GetValue<string>(nameof(CertificadoPrivadoSenha));
            ArquivosEstaticos = ConfigurationRoot.GetValue<string>(nameof(ArquivosEstaticos));
            CompressionResponse = ConfigurationRoot.GetValue<string>(nameof(CompressionResponse));
            TratamentoErroInterno = ConfigurationRoot.GetValue<string>(nameof(TratamentoErroInterno));
            ExtensoesUrlNaoRecurso = ConfigurationRoot.GetSection(nameof(ExtensoesUrlNaoRecurso)).Get<string[]>() ?? [];
            Sites = ConfigurationRoot.GetSection(nameof(Sites)).Get<Site[]>()!;
            AllowOrigins = ConfigurationRoot.GetSection($"Cors:{nameof(AllowOrigins)}").Get<string[]>() ?? [];
            AllowHeaders = ConfigurationRoot.GetSection($"Cors:{nameof(AllowHeaders)}").Get<string[]>() ?? [];
            AllowMethods = ConfigurationRoot.GetSection($"Cors:{nameof(AllowMethods)}").Get<string[]>() ?? [];

            if (AllowOrigins.Length == 0) AllowOrigins = ["*"];
            if (AllowHeaders.Length == 0) AllowHeaders = ["*"];
            if (AllowMethods.Length == 0) AllowMethods = ["*"];
            if (CertificadoPrivadoChave == "") CertificadoPrivadoChave = null;
            if (CertificadoPrivadoSenha == "") CertificadoPrivadoSenha = null;
        }
    }
}
