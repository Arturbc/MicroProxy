namespace MicroProxy.Models
{
    public class Site
    {
        private string? _bindAlvo = null;
        private string _urlAlvo = null!;
        public string? BindUrl { get => _bindAlvo; set => _bindAlvo = value?.TrimEnd('/'); }
        public string UrlAlvo { get => _urlAlvo; set => _urlAlvo = value.TrimEnd('/'); }
        public bool IgnorarCertificadoAlvo { get; set; }
        public Dictionary<string, string[]>? RequestHeadersAdicionais { get; set; }
        public Dictionary<string, string[]>? ResponseHeadersAdicionais { get; set; }
        public string? ExePath { get; set; }
        public string? ExePathDiretorio { get; set; }
    }
}
