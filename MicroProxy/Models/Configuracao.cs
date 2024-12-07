namespace MicroProxy.Models
{
    public partial class Configuracao
    {
        public const string NOME_COOKIE = "Microproxy";
        public const string COOKIE_SITE = "cookieSite";
        const int TEMPO_SESSAO_MIN_PADRAO = 43200;
        protected IConfigurationRoot ConfigurationRoot { get; set; } = null!;
        public uint MinutosValidadeCookie { get; protected set; }
        public string[] Ips { get; protected set; } = null!;
        public ushort PortaHttpRedirect { get; protected set; }
        public string? CertificadoPrivado { get; protected set; }
        public string? CertificadoPrivadoSenha { get; protected set; }
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

            MinutosValidadeCookie = ConfigurationRoot.GetValue<uint>("MinutosValidadeCookie");
            Sites = ConfigurationRoot.GetSection("Sites").Get<Site[]>()!;
            CertificadoPrivado = ConfigurationRoot.GetValue<string>("CertificadoPrivado")?.Trim();
            CertificadoPrivadoSenha = ConfigurationRoot.GetValue<string>("CertificadoPrivadoSenha");
            PortaHttpRedirect = ConfigurationRoot.GetValue<ushort?>("PortaHttpRedirect") ?? 0;
            Ips = ConfigurationRoot.GetSection("IPs").Get<string[]>() ?? [];

            if (MinutosValidadeCookie == 0)
            {
                MinutosValidadeCookie = TEMPO_SESSAO_MIN_PADRAO;
            }

            AllowOrigins = ConfigurationRoot.GetSection("Cors:AllowHosts").Get<string[]>() ?? [];
            AllowHeaders = ConfigurationRoot.GetSection("Cors:AllowHeaders").Get<string[]>() ?? [];
            AllowMethods = ConfigurationRoot.GetSection("Cors:AllowMethods").Get<string[]>() ?? [];

            if (AllowOrigins.Length == 0) AllowOrigins = ["*"];
            if (AllowHeaders.Length == 0) AllowOrigins = ["*"];
            if (AllowMethods.Length == 0) AllowOrigins = ["*"];
        }
    }
}
