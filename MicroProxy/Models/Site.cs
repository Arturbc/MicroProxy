namespace MicroProxy.Models
{
    public class Site
    {
        private string _urlAlvo = null!;
        public string? BindUrl { get; set; }
        public string UrlAlvo { get => _urlAlvo; set => _urlAlvo = value.TrimEnd('/'); }
        public bool IgnorarCertificadoAlvo { get; set; }
        public Dictionary<string, string[]>? RequestHeadersAdicionais { get; set; }
        public Dictionary<string, string[]>? ResponseHeadersAdicionais { get; set; }
        public string? ExePath { get; set; }
    }
}
