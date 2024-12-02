namespace MicroProxy.Models
{
    public class Site
    {
        private string? _bindAlvo = null;
        private string _urlAlvo = null!;
        private string? _exePath;
        private string? _exeArgumentos = null!;
        private string? _exePathDiretorio = null!;
        public string UrlAtual = null!;
        public string AuthorityAtual => new Uri(UrlAtual).Authority;
        public string HostAtual => new Uri(UrlAtual).Host;
        public string SchemaAtual => new Uri(UrlAtual).Scheme;
        public string HostPortAtual => new Uri(UrlAtual).Port.ToString();
        public string PathAndQueryAtual => new Uri(UrlAtual).PathAndQuery;
        public string AuthorityAlvo => new Uri(_urlAlvo).Authority;
        public string HostAlvo => new Uri(_urlAlvo).Host;
        public string SchemaAlvo => new Uri(_urlAlvo).Scheme;
        public string HostPortAlvo => new Uri(_urlAlvo).Port.ToString();
        public string PathAndQueryAlvo => new Uri(_urlAlvo).PathAndQuery;

        public string? BindUrl { get => _bindAlvo; set => _bindAlvo = value?.TrimEnd('/'); }
        public string UrlAlvo { get => _urlAlvo; set => _urlAlvo = value.TrimEnd('/'); }
        public bool IgnorarCertificadoAlvo { get; set; }
        public Dictionary<string, string[]>? RequestHeadersAdicionais { get; set; }
        public Dictionary<string, string[]>? ResponseHeadersAdicionais { get; set; }
        public string? ExePath { get => _exePath; set => _exePath = value != null ? Utils.PathInvalidCharsRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : null; }
        public string? ExeArgumentos
        {
            get => _exeArgumentos;
            set => _exeArgumentos = value != null ? Utils.PathInvalidCharsRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : null;
        }
        public string? ExePathDiretorio
        {
            get => _exePathDiretorio;
            set => _exePathDiretorio = value != null ? Utils.PathInvalidCharsRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : null;
        }
        public bool JanelaSeparada { get; set; }
        public bool AutoExec { get; set; }
    }
}
