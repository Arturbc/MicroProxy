using Microsoft.Extensions.Primitives;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace MicroProxy.Models
{
    public partial class Site
    {
        static Process[] Executaveis = [];
        private string[]? _bindAlvos = null;
        private string _urlAlvo = null!;
        private string[]? _methods = null;
        public bool? _ignorarCertificadoAlvo = null;
        public Dictionary<string, string[]>? _requestHeadersAdicionais = null;
        public Dictionary<string, string[]>? _responseHeadersAdicionais = null;
        private string? _exePath = null;
        private string? _exeArgumentos = null!;
        private string? _exePathDiretorio = null!;
        public bool? _janelaVisivel = null;
        public bool? _autoExec = null;
        public string ReqMethodAtual = null!;
        public string UrlAtual = null!;
        public string? ReqBody = null;
        public Exception? Exception = null;

        public string AuthorityAtual => new Uri(UrlAtual).Authority;
        public string HostAtual => new Uri(UrlAtual).Host;
        public string SchemaAtual => new Uri(UrlAtual).Scheme;
        public string HostPortAtual => new Uri(UrlAtual).Port.ToString();
        public string PathAndQueryAtual => new Uri(UrlAtual).PathAndQuery.TrimEnd('/');
        public string AuthorityAlvo => new Uri(_urlAlvo).Authority;
        public string HostAlvo => new Uri(_urlAlvo).Host;
        public string SchemaAlvo => new Uri(_urlAlvo).Scheme;
        public string HostPortAlvo => new Uri(_urlAlvo).Port.ToString();
        public string PathAndQueryAlvo => new Uri(_urlAlvo).PathAndQuery.TrimEnd('/');
        public string? ExceptionMensagem => Exception?.Message;
        public DateTime DataHoras => DateTime.Now;
        public string Dia => DataHoras.ToString("dd");
        public string Mes => DataHoras.ToString("MM");
        public string Ano => DataHoras.ToString("yyyy");
        public string Horas24 => DataHoras.ToString("HH");
        public string Horas12 => DataHoras.ToString("hh");
        public string AM_PM => DataHoras.ToString("tt");
        public string Minutos => DataHoras.ToString("mm");
        public string Segundos => DataHoras.ToString("ss");
        public string HorasAbreviadas => DataHoras.ToString("t");
        public string HorasCompletas => DataHoras.ToString("T");

        public string[]? BindUrls { get => _bindAlvos; set => _bindAlvos ??= ([.. value?.Select(v => (v.StartsWith("http", StringComparison.InvariantCultureIgnoreCase) ? v : $"http://{v}").TrimEnd('/'))]); }
        public string UrlAlvo { get => _urlAlvo; set => _urlAlvo = (value.StartsWith("http", StringComparison.InvariantCultureIgnoreCase) ? value : $"http://{value}").TrimEnd('/'); }
        public string[] Methods { get => _methods!; set => _methods ??= value ?? ["*"]; }
        public bool IgnorarCertificadoAlvo { get => _ignorarCertificadoAlvo ?? false; set => _ignorarCertificadoAlvo ??= value; }
        public Dictionary<string, string[]>? RequestHeadersAdicionais { get => _requestHeadersAdicionais; set => _requestHeadersAdicionais ??= value; }
        public Dictionary<string, string[]>? ResponseHeadersAdicionais { get => _responseHeadersAdicionais; set => _responseHeadersAdicionais ??= value; }
        public string? ExePath { get => _exePath; set => _exePath ??= value != null ? PathInvalidCharsRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : _exePath; }
        public string? ExeArgumentos { get => _exeArgumentos; set => _exeArgumentos ??= value != null ? PathInvalidCharsRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : _exeArgumentos; }
        public string? ExePathDiretorio { get => _exePathDiretorio; set => _exePathDiretorio ??= value != null ? PathInvalidCharsRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : _exePathDiretorio; }
        public bool JanelaVisivel { get => _janelaVisivel ?? false; set => _janelaVisivel ??= value; }
        public bool AutoExec { get => _autoExec ?? false; set => _autoExec ??= value; }

        public void ExibirVariaveisDisponiveis()
        {
            string variaveis = "";

            foreach (var variavel in GetType().GetProperties().Select(p => p.Name)
                .Union(GetType().GetFields().Select(f => f.Name)).Order())
            {
                if (variaveis != "")
                {
                    variaveis += ", ";
                }

                variaveis += $"##{variavel}##";
            }

            if (variaveis != "")
            {
                using ILoggerFactory loggerFactory =
                    LoggerFactory.Create(builder =>
                        builder.AddSimpleConsole(options =>
                        {
                            options.IncludeScopes = true;
                            options.SingleLine = true;
                            options.TimestampFormat = "HH:mm:ss ";
                        }));
                ILogger<Program> logger = loggerFactory.CreateLogger<Program>();

                logger.LogInformation($"Variáveis disponíveis: {variaveis}");
            }
        }

        public static string ProcessarPath(string path)
        {
            if (path.Trim() != "")
            {
                path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
            }

            return path;
        }

        public void InicializarExecutavel()
        {
            if (!string.IsNullOrEmpty(ExePath))
            {
                using ILoggerFactory loggerFactory =
                    LoggerFactory.Create(builder =>
                        builder.AddSimpleConsole(options =>
                        {
                            options.IncludeScopes = true;
                            options.SingleLine = true;
                            options.TimestampFormat = "HH:mm:ss ";
                        }));
                ILogger<Program> logger = loggerFactory.CreateLogger<Program>();
                string exePath = ProcessarPath(ExePath);
                string exePathDiretorio = ProcessarPath(ExePathDiretorio ?? "");
                string nomeProcesso = Path.GetFileNameWithoutExtension(exePath);
                string exeName = Path.GetFileName(exePath);
                string pathExe = string.IsNullOrEmpty(exePathDiretorio) ?
                    exePath.Replace(@$"\{exeName}", "") : exePathDiretorio;
                string[] nomesProcesso = [nomeProcesso, exeName];
                bool consulta(Process e) => nomesProcesso.Contains(e.ProcessName) && e.StartInfo.FileName == exePath
                    && e.StartInfo.WorkingDirectory == pathExe && e.StartInfo.Arguments == ExeArgumentos
                    && e.StartInfo.CreateNoWindow == !JanelaVisivel;
                var exec = Executaveis.FirstOrDefault(consulta);

                exec ??= Process.GetProcesses().FirstOrDefault(p => p.Id != Environment.ProcessId && nomesProcesso.Contains(p.ProcessName)
                   && (p.MainModule == null
                       || (p.MainModule.ModuleName == exeName && (p.MainModule.FileName.StartsWith(pathExe)
                           || pathExe.StartsWith(p.MainModule.FileName.Replace(@$"\{exeName}", ""))))));

                if (exec != null)
                {
                    using (logger.BeginScope($"[SSID {exec.Id} ({exec.ProcessName})]"))
                    {
                        if (!exec.Responding)
                        {
                            logger.LogInformation($" Não está respondendo!");

                            if (!exec.HasExited)
                            {
                                exec.Kill();
                                logger.LogInformation($" Finalizado!");
                            }

                            exec = null;
                        }
                    }
                }

                if (exec == null)
                {
                    ProcessStartInfo info = new() { FileName = exePath, WorkingDirectory = pathExe, Arguments = ExeArgumentos, CreateNoWindow = !JanelaVisivel };

                    logger.LogInformation($"Inicializando {exeName}...");
                    exec = Process.Start(info);

                    if (exec != null)
                    {
                        Executaveis = [.. Executaveis.Where(e => !e.HasExited).Append(exec)];

                        using (logger.BeginScope($"[SSID {exec.Id} ({exec.ProcessName})]"))
                        {
                            logger.LogInformation($"Inicializado!");
                        }
                    }
                }
            }
        }

        public static void OnShutdown()
        {
            foreach (var exec in Executaveis.Where(e => e.StartInfo.CreateNoWindow || !e.Responding))
            {
                if (!exec.HasExited)
                {
                    exec.Close();
                }
            }
        }

        public Dictionary<string, StringValues> ProcessarHeaders(Dictionary<string, StringValues> headersOriginais, Dictionary<string, string[]>? headersAdicionais)
            => ProcessarHeaders(headersOriginais.ToDictionary(h => h.Key, h => (string[])h.Value.Where(v => v != null).ToArray()!), headersAdicionais).ToDictionary(h => h.Key, h => new StringValues(h.Value));

        public Dictionary<string, string[]> ProcessarHeaders(Dictionary<string, string[]> headersOriginais, Dictionary<string, string[]>? headersAdicionais)
        {
            if (headersAdicionais != null)
            {
                string[] keysCoringa = ["", "*"];
                headersAdicionais = headersAdicionais.Where(v => v.Value.Length > 0).ToDictionary();

                foreach (var header in headersOriginais.Where(h => headersAdicionais.Any(ha => FlagKeySubstRegex().Replace(ha.Key, "") == h.Key || keysCoringa.Contains(ha.Key))))
                {
                    string[] valores = [];
                    var listaHeaders = headersAdicionais.Where(h => h.Key == header.Key || h.Key == "").ToDictionary();
                    var listaHeadersSubstitutos = headersAdicionais.Where(h => (FlagKeySubstRegex().Replace(h.Key, "") == header.Key && h.Key != header.Key) || h.Key == "*")
                        .ToDictionary(h => FlagKeySubstRegex().Replace(h.Key, ""), h => h.Value.Select(v => v.ProcessarStringSubstituicao(this)).ToArray());

                    if (listaHeaders.Where(l => l.Key != "").Count() < listaHeadersSubstitutos.Where(l => l.Key != "").Count())
                    {
                        if (listaHeadersSubstitutos.TryGetValue(header.Key, out var headerValores))
                        {
                            headersOriginais[header.Key] = headerValores;
                        }
                    }
                    else
                    {
                        foreach (var valor in header.Value)
                        {
                            string valorTemp = valor;

                            foreach (var headerAdicional in listaHeaders)
                            {
                                bool substituirValores = false;
                                valores = [];

                                if (listaHeadersSubstitutos.TryGetValue(headerAdicional.Key, out var headerAdicionalSubs))
                                {
                                    substituirValores = true;

                                    foreach (var valoresHeader in headerAdicional.Value)
                                    {
                                        Regex substRegex = new(valoresHeader.ProcessarStringSubstituicao(this));
                                        var valido = substRegex.IsMatch(valorTemp);

                                        if (valido)
                                        {
                                            string valorSubstitudo = headerAdicionalSubs
                                                .OrderBy(v => Math.Abs(NonSlashCharsRegex().Replace(v, "x").Length - NonSlashCharsRegex().Replace(valorTemp, "x").Length)).First();

                                            valorTemp = substRegex.Replace(valorTemp, valorSubstitudo);
                                            break;
                                        }
                                    }
                                }
                                else
                                {
                                    valorTemp = valorTemp.ProcessarStringSubstituicao(this, true);
                                }

                                valores = [.. valores.Append(valorTemp)];
                                headersOriginais[header.Key] = substituirValores ? valores : [.. headersOriginais[header.Key].Union(valores)];
                            }
                        }
                    }
                }

                foreach (var header in headersAdicionais.Where(h => !keysCoringa.Contains(h.Key) && !FlagKeySubstRegex().IsMatch(h.Key)
                    && !headersAdicionais.Any(ha => FlagKeySubstRegex().Replace(ha.Key, "") == h.Key && ha.Key != h.Key) && !headersOriginais.ContainsKey(h.Key)))
                {
                    string[] valores = [];

                    foreach (var valor in header.Value)
                    {
                        valores = [.. valores.Append(valor.ProcessarStringSubstituicao(this))];
                    }

                    headersOriginais.Add(header.Key, valores);
                }
            }

            return headersOriginais;
        }

        [GeneratedRegex(@"\*([\w#-]+ *= *[\w#-]+(?=(?: *, *)|(?:$)))?$")]
        private static partial Regex FlagKeySubstRegex();

        [GeneratedRegex(@"(?:(?<!^[a-zA-Z]):)|(?:(?<!(?:^\\?)|(?:\w+[:%])|[\w.~])[\\/](?!%?\w))|[*?""<>|]")]
        public static partial Regex PathInvalidCharsRegex();

        [GeneratedRegex(@"[^/]+")]
        public static partial Regex NonSlashCharsRegex();
    }
}
