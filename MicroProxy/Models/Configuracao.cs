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
        public ushort PortaHttpRedirect { get; protected set; }
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

            Logs = ConfigurationRoot.GetSection("Logs").Get<Dictionary<string, Log>>();
            MinutosValidadeCookie = ConfigurationRoot.GetValue<uint>("MinutosValidadeCookie");
            Ips = ConfigurationRoot.GetSection("IPs").Get<string[]>() ?? [];
            IpsBloqueados = ConfigurationRoot.GetSection("IPsBloqueados").Get<string[]>() ?? [];
            PortaHttpRedirect = ConfigurationRoot.GetValue<ushort?>("PortaHttpRedirect") ?? 0;
            SolicitarCertificadoCliente = ConfigurationRoot.GetValue<bool>("SolicitarCertificadoCliente");
            CertificadoPrivado = ConfigurationRoot.GetValue<string>("CertificadoPrivado")?.Trim();
            CertificadoPrivadoChave = ConfigurationRoot.GetValue<string>("CertificadoPrivadoChave")?.Trim();
            CertificadoPrivadoSenha = ConfigurationRoot.GetValue<string>("CertificadoPrivadoSenha");
            ArquivosEstaticos = ConfigurationRoot.GetValue<string>("ArquivosEstaticos");
            CompressionResponse = ConfigurationRoot.GetValue<string>("CompressionResponse");
            TratamentoErroInterno = ConfigurationRoot.GetValue<string>("TratamentoErroInterno");
            ExtensoesUrlNaoRecurso = ConfigurationRoot.GetSection("ExtensoesUrlNaoRecurso").Get<string[]>() ?? [];
            Sites = ConfigurationRoot.GetSection("Sites").Get<Site[]>()!;
            AllowOrigins = ConfigurationRoot.GetSection("Cors:AllowHosts").Get<string[]>() ?? [];
            AllowHeaders = ConfigurationRoot.GetSection("Cors:AllowHeaders").Get<string[]>() ?? [];
            AllowMethods = ConfigurationRoot.GetSection("Cors:AllowMethods").Get<string[]>() ?? [];

            if (AllowOrigins.Length == 0) AllowOrigins = ["*"];
            if (AllowHeaders.Length == 0) AllowHeaders = ["*"];
            if (AllowMethods.Length == 0) AllowMethods = ["*"];
            if (CertificadoPrivadoChave == "") CertificadoPrivadoChave = null;
            if (CertificadoPrivadoSenha == "") CertificadoPrivadoSenha = null;
        }
    }
}
