namespace MicroProxy.Models
{
    public partial class Configuracao
    {
        public const string NOME_COOKIE = "Microproxy";
        public const string COOKIE_SITE = "cookieSite";
        public const string PATH_SITE = "pathSite";
        protected IConfigurationRoot ConfigurationRoot { get; set; } = null!;
        public Dictionary<string, Log>? Logs { get; protected set; }
        public uint MinutosValidadeCookie { get; protected set; }
        public string[] Ips { get; protected set; } = null!;
        public ushort PortaHttpRedirect { get; protected set; }
        public string? CertificadoPrivado { get; protected set; }
        public string? CertificadoPrivadoChave { get; protected set; }
        public string? ArquivosEstaticos { get; protected set; }
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
            PortaHttpRedirect = ConfigurationRoot.GetValue<ushort?>("PortaHttpRedirect") ?? 0;
            CertificadoPrivado = ConfigurationRoot.GetValue<string>("CertificadoPrivado")?.Trim();
            CertificadoPrivadoChave = ConfigurationRoot.GetValue<string>("CertificadoPrivadoChave");
            ArquivosEstaticos = ConfigurationRoot.GetValue<string>("ArquivosEstaticos");
            Sites = ConfigurationRoot.GetSection("Sites").Get<Site[]>()!;
            AllowOrigins = ConfigurationRoot.GetSection("Cors:AllowHosts").Get<string[]>() ?? [];
            AllowHeaders = ConfigurationRoot.GetSection("Cors:AllowHeaders").Get<string[]>() ?? [];
            AllowMethods = ConfigurationRoot.GetSection("Cors:AllowMethods").Get<string[]>() ?? [];

            if (AllowOrigins.Length == 0) AllowOrigins = ["*"];
            if (AllowHeaders.Length == 0) AllowOrigins = ["*"];
            if (AllowMethods.Length == 0) AllowOrigins = ["*"];
        }
    }
}
