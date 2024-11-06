using System.Text.RegularExpressions;

namespace MicroProxy.Models
{
    public partial class Configuracao
    {
        protected IConfigurationRoot ConfigurationRoot { get; set; } = null!;
        public string? Ip { get; protected set; } = null!;
        public string? Porta { get; protected set; } = null!;
        public string? PortaHttpRedirect { get; protected set; } = null!;
        public string? CertificadoPrivado { get; set; }
        public string? CertificadoPrivadoSenha { get; set; }
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

            Sites = ConfigurationRoot.GetSection("Sites").Get<Site[]>()!;
            CertificadoPrivado = ConfigurationRoot.GetValue<string>("CertificadoPrivado");
            CertificadoPrivadoSenha = ConfigurationRoot.GetValue<string>("CertificadoPrivadoSenha");
            PortaHttpRedirect = ConfigurationRoot.GetValue<string>("PortaHttpRedirect");
            Ip = ConfigurationRoot.GetValue<string>("IP");

            if (Ip != null && Ip != "")
            {
                Porta = PortaIpRegex().Match(Ip).Value.TrimStart(':');
                Ip = PortaIpRegex().Replace(Ip, "");
            }

            if (Porta == "") Porta = null;
            if (string.IsNullOrEmpty(CertificadoPrivado) || PortaHttpRedirect == "") PortaHttpRedirect = null;

            AllowOrigins = ConfigurationRoot.GetSection("Cors:AllowHosts").Get<string[]>() ?? [];
            AllowHeaders = ConfigurationRoot.GetSection("Cors:AllowHeaders").Get<string[]>() ?? [];
            AllowMethods = ConfigurationRoot.GetSection("Cors:AllowMethods").Get<string[]>() ?? [];

            if (AllowOrigins.Length == 0) AllowOrigins = ["*"];
            if (AllowHeaders.Length == 0) AllowOrigins = ["*"];
            if (AllowMethods.Length == 0) AllowOrigins = ["*"];
        }

        [GeneratedRegex(@":\d{1,5}")]
        private static partial Regex PortaIpRegex();
    }
}
