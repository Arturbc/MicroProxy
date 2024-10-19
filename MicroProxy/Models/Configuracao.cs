using System.Text.RegularExpressions;

namespace MicroProxy.Models
{
    public partial class Configuracao
    {
        protected IConfigurationRoot ConfigurationRoot { get; set; } = null!;
        public string? Ip { get; protected set; } = null!;
        public string? Porta { get; protected set; } = null!;
        public string UrlAlvo { get; protected set; }

        public Configuracao()
        {
            var configurationBuilder0 = new ConfigurationBuilder();
            var path0 = Path.GetFullPath("appsettings.json");

            configurationBuilder0.AddJsonFile(path0, false);
            ConfigurationRoot = configurationBuilder0.Build();

            UrlAlvo = ConfigurationRoot.GetValue<string>("UrlAlvo")!.TrimEnd('/');
            Ip = ConfigurationRoot.GetValue<string>("IP");

            if ((Ip ?? "") != "")
            {
                Porta = PortaIpRegex().Match(Ip).Value.TrimStart(':');
                Ip = PortaIpRegex().Replace(Ip, "");
            }
        }

        [GeneratedRegex(@":\d{1,5}")]
        private static partial Regex PortaIpRegex();
    }
}
