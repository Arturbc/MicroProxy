using Microsoft.Extensions.Primitives;

namespace MicroProxy.Models
{
    public class Site
    {
        public string? BindUrl {  get; set; }
        public string UrlAlvo { get; set; } = null!;
        public bool IgnorarCertificadoAlvo { get; set; }
        public Dictionary<string, string[]>? RequestHeadersAdicionais { get; set; }
        public Dictionary<string, string[]>? ResponseHeadersAdicionais { get; set; }
    }
}
