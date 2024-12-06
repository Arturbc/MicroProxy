using System.Diagnostics;

namespace MicroProxy.Models
{
    public class Site
    {
        static Process[] Executaveis = [];
        private string? _bindAlvo = null;
        private string _urlAlvo = null!;
        private string? _exePath;
        private string? _exeArgumentos = null!;
        private string? _exePathDiretorio = null!;
        public string ReqMethodAtual = null!;
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

        public string? BindUrl { get => _bindAlvo; private set => _bindAlvo = value?.TrimEnd('/'); }
        public string UrlAlvo { get => _urlAlvo; private set => _urlAlvo = value.TrimEnd('/'); }
        public bool IgnorarCertificadoAlvo { get; private set; }
        public Dictionary<string, string[]>? RequestHeadersAdicionais { get; set; }
        public Dictionary<string, string[]>? ResponseHeadersAdicionais { get; set; }
        public string? ExePath { get => _exePath; private set => _exePath = value != null ? Utils.PathInvalidCharsRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : null; }
        public string? ExeArgumentos
        {
            get => _exeArgumentos;
            private set => _exeArgumentos = value != null ? Utils.PathInvalidCharsRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : null;
        }
        public string? ExePathDiretorio
        {
            get => _exePathDiretorio;
            private set => _exePathDiretorio = value != null ? Utils.PathInvalidCharsRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : null;
        }
        public bool JanelaSeparada { get; private set; }
        public bool AutoExec { get; private set; }

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
                    && e.StartInfo.CreateNoWindow == !JanelaSeparada;
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
                    ProcessStartInfo info = new() { FileName = exePath, WorkingDirectory = pathExe, Arguments = ExeArgumentos, CreateNoWindow = !JanelaSeparada };

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
            foreach (var exec in Executaveis.Where(e => !e.StartInfo.CreateNoWindow || !e.Responding))
            {
                if (!exec.HasExited)
                {
                    exec.Close();
                }
            }
        }
    }
}
