using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Text.RegularExpressions;

namespace MicroProxy.Models
{
    public partial class Site
    {
        private const int MILLISEGUNDO_AGUARDAR_FECHAR = 1000;
        private static readonly Dictionary<string, List<string>> DicUrlsUsadas = [];
        private static readonly Lock LockUrlsUsadas = new();
        private static Executavel[] Executaveis = [];
        private string[]? _bindDestinos = null;
        private UrlDestino[]? _urlsDestinos = null;
        private string? _urlDestino = null;
        private int? _limiteTempoPing = null;
        private string[]? _methods = null;
        private bool? _ignorarCertificadoDestino = null;
        private Dictionary<string, string[]>? _requestHeadersAdicionais = null;
        private Dictionary<string, string[]>? _responseHeadersAdicionais = null;
        private int? _bufferResp;
        private int? _segundosTempoMax;
        private bool? _usarProxy;
        private string? _exePath = null;
        private string? _exeArgumentos = null!;
        private string? _exePathDiretorio = null!;
        private bool? _janelaVisivel = null;
        private bool? _autoExec = null;
        private bool? _autoFechar = null;
        private readonly List<string> _urlsDescartadas = [];

        private static HttpContext HttpContext => Utils.HttpContextAccessor.HttpContext!;
        public static string IpLocal => (HttpContext?.Connection.LocalIpAddress ?? IPAddress.Loopback).ToString();
        public static string IpRemoto => (HttpContext?.Connection.RemoteIpAddress ?? IPAddress.Loopback).ToString();
        public static string IpRemotoFw
        {
            get
            {
                var _ipRemotoFw = IpRemoto;
                var request = HttpContext?.Request;

                if (request != null)
                {
                    string[] headersIpFw = ["X-Real-IP", "X-Forwarded-For"];
                    foreach (string header in headersIpFw) { if (!string.IsNullOrEmpty(request.Headers[header])) { _ipRemotoFw = request.Headers[header]; break; } }
                }

                return _ipRemotoFw!;
            }
        }
        public string[] UrlsDestinos
        {
            get => [.. (_urlsDestinos?.Select(u => u.Url) ?? []).Except(_urlsDescartadas)];
            set => _urlsDestinos = [.. value.Select(v => new UrlDestino() { Url = (v.StartsWith("http", StringComparison.InvariantCultureIgnoreCase) ? v :
                $"http://{v}").TrimEnd('/'), Peso = 0f })];
        }
        public float[] PesosUrlsDestinos
        {
            get => [.. _urlsDestinos?.Select(u => u.Peso) ?? []];
            set
            {
                var qtdUrlsDestinos = _urlsDestinos?.Length ?? 0;
                var novosValores = value[qtdUrlsDestinos..];
                int tamMax = Math.Min(novosValores.Length, qtdUrlsDestinos);

                for (int i = 0; i < tamMax; i++) { _urlsDestinos![i].Peso = novosValores[i]; }
            }
        }
        public Exception? Exception { get; set; } = null;
        public string? ReqHeaders { get; set; } = null;
        public string? ReqBody { get; set; } = null;
        public string? RespHeadersPreAjuste { get; set; } = null;
        public string? RespBody { get; set; } = null;
        public string AuthorityAtual => new Uri(UrlAtual).Authority;
        public string HostAtual => new Uri(UrlAtual).Host;
        public string SchemaAtual => new Uri(UrlAtual).Scheme;
        public string HostPortAtual => new Uri(UrlAtual).Port.ToString();
        public string PathAndQueryAtual => new Uri(UrlAtual).PathAndQuery;
        public string AbsolutePathAtual => new Uri(UrlAtual).AbsolutePath;
        public string PathAtualSubstituto { get; private set; } = "";
        public string PathAtualAdicional { get; set; } = "";
        public string AbsolutePathAtualOrigemRedirect => Utils.AbsolutePathUrlOrigemRedirect ?? "";
        public string AuthorityDestino => new Uri(UrlDestino).Authority;
        public string HostDestino => new Uri(UrlDestino).Host;
        public string SchemaDestino => new Uri(UrlDestino).Scheme;
        public string HostPortDestino => new Uri(UrlDestino).Port.ToString();
        public string PathAndQueryDestino => new Uri(UrlDestino).PathAndQuery;
        public string AbsolutePathDestino => new Uri(UrlDestino).AbsolutePath;
        public string ReqMethodAtual => HttpContext.Request.Method;
        public string ReqHeadersPreAjuste => JsonConvert.SerializeObject(HttpContext.Request.Headers.OrderBy(h => h.Key).ToDictionary(), Formatting.None, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });
        public int RespStatusCode => HttpContext.Response.StatusCode;
        public string RespHeaders => JsonConvert.SerializeObject(HttpContext.Response.Headers.OrderBy(h => h.Key).ToDictionary(), Formatting.None, new JsonSerializerSettings() { ReferenceLoopHandling = ReferenceLoopHandling.Ignore });
        public string UrlAtual => HttpContext?.Request.GetDisplayUrl()!;
        public string? ExceptionMensagem
        {
            get
            {
                var excecao = Exception;
                var mensagem = excecao?.Message;

                while (excecao?.InnerException != null)
                {
                    mensagem += Environment.NewLine + excecao.InnerException.Message;
                    excecao = excecao?.InnerException;
                }

                return mensagem;
            }
        }
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

        public int LimiteTempoPing { get => _limiteTempoPing ?? 500; set => _limiteTempoPing = value; }
        public string[]? BindUrls { get => _bindDestinos; set => _bindDestinos ??= value != null && value.Length != 0 ? [.. value.Select(v => v.StartsWith("http", StringComparison.InvariantCultureIgnoreCase) ? v : $"http://{v}")] : null; }
        public string UrlDestino
        {
            get
            {
                if (_urlDestino != null && (HttpContext.Response.StatusCode < (int)HttpStatusCode.BadRequest)) { return _urlDestino; }

                if (HttpContext != null && _urlsDestinos != null && !HttpContext.Response.HasStarted)
                {
                    lock (LockUrlsUsadas)
                    {
                        var urlsDestinos = _urlsDestinos.Where(u => !_urlsDescartadas.Contains(u.Url)).ToArray() ?? [];

                        if (!DicUrlsUsadas.TryGetValue(IpRemotoFw, out var urls)) { DicUrlsUsadas.Add(IpRemotoFw, urls = []); }
                        if (_urlDestino != null)
                        { _urlsDescartadas.Add(_urlDestino = UrlsDestinos.OrderByDescending(u => u.Length).First(u => _urlDestino.StartsWith(u))); urls.Remove(_urlDestino); }

                        _urlDestino = urls.FirstOrDefault(u => UrlsDestinos.Contains(u));

                        if (_urlDestino == null)
                        {
                            HttpContext.Response.StatusCode = (int)HttpStatusCode.OK;

                            var urlsDestinosAgrupadas = _urlsDestinos.Select(u => new
                            {
                                u.Url,
                                u.Peso,
                                Prioridade = u.Peso != 0 ? MathF.Floor(DicUrlsUsadas.Values.Count(v => v.Contains(u.Url)) / MathF.Abs(u.Peso)) : -1
                            })
                                .GroupBy(u => new { u.Peso, u.Prioridade }, u => u.Url, (metricas, urls) => new { Urls = urls.ToArray(), Metricas = metricas })
                                .OrderBy(u => u.Metricas.Peso == 0).ThenBy(u => u.Metricas.Prioridade).ThenByDescending(u => u.Metricas.Peso).FirstOrDefault();

                            if (urlsDestinosAgrupadas != null)
                            {
                                var urlsPonderadas = urlsDestinosAgrupadas.Urls;

                                if (urlsDestinosAgrupadas.Urls.Length > 1)
                                {
                                    using System.Net.NetworkInformation.Ping ping = new();
                                    urlsPonderadas = [.. urlsDestinosAgrupadas.Urls.OrderBy(u => ping.Send(new Uri(u).Host, LimiteTempoPing).RoundtripTime)];
                                }

                                _urlDestino = urlsPonderadas.First();

                                if (urlsDestinosAgrupadas.Metricas.Peso > 0) { urls.Add(_urlDestino!); }
                            }
                        }
                    }
                }

                return _urlDestino ?? UrlAtual;
            }

            set
            {
                _urlDestino = (value.StartsWith("http", StringComparison.InvariantCultureIgnoreCase) ? value : $"http://{value}").TrimEnd('/');
                if (HttpContext != null && HttpContext.Request.GetDisplayUrl().EndsWith('/')) _urlDestino += '/';
                if (PathAtualSubstituto == "" && _urlDestino.StartsWith("http", StringComparison.InvariantCultureIgnoreCase)) PathAtualSubstituto = new Uri(_urlDestino).AbsolutePath;
            }
        }
        public bool IgnorarCertificadoDestino { get => _ignorarCertificadoDestino ?? false; set => _ignorarCertificadoDestino ??= value; }
        public string[] Methods { get => _methods!; set => _methods ??= value ?? ["*"]; }
        public Dictionary<string, string[]>? RequestHeadersAdicionais { get => _requestHeadersAdicionais; set => _requestHeadersAdicionais ??= value; }
        public Dictionary<string, string[]>? ResponseHeadersAdicionais { get => _responseHeadersAdicionais; set => _responseHeadersAdicionais ??= value; }
        public int BufferResp { get => _bufferResp ?? 0; set => _bufferResp = _bufferResp == null ? value : _bufferResp; }
        public int SegundosTempoMax { get => _segundosTempoMax ?? 0; set => _segundosTempoMax = _segundosTempoMax == null ? value : _segundosTempoMax; }
        public bool UsarProxy { get => _usarProxy ?? false; set => _usarProxy = _usarProxy == null ? value : _usarProxy; }
        public string? ExePath { get => _exePath; set => _exePath ??= !string.IsNullOrEmpty(value) ? CharsInvalidosPathArquivoRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : _exePath; }
        public string? ExeArgumentos { get => _exeArgumentos; set => _exeArgumentos ??= !string.IsNullOrEmpty(value) ? CharsInvalidosPathArquivoRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : _exeArgumentos; }
        public string? ExePathDiretorio { get => _exePathDiretorio; set => _exePathDiretorio ??= !string.IsNullOrEmpty(value) ? CharsInvalidosPathArquivoRegex().Replace(value.ProcessarStringSubstituicao(this), "_") : _exePathDiretorio; }
        public bool JanelaVisivel { get => _janelaVisivel ?? false; set => _janelaVisivel ??= value; }
        public bool AutoExec { get => _autoExec ?? false; set => _autoExec ??= value; }
        public bool AutoFechar { get => _autoFechar ?? !JanelaVisivel; set => _autoFechar ??= value; }

        public void ExibirVariaveisDisponiveis()
        {
            string[] variaveis = [.. GetType().GetProperties().Select(p => "##" + p.Name + "##")
                .Union(GetType().GetFields().Select(f => "##" + f.Name + "##")).Order()];

            if (variaveis.Length != 0) ExibirLog(variaveis, "Variáveis disponíveis:", ", ");
        }

        public static void ExibirLog(string mensagem, string? scope = null) => ExibirLog([mensagem], scope);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1873:Evitar registros em log que possam ser caros", Justification = "É necessário para poder organizar os logs dinamicamente")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA2254:O modelo deve ser uma expressão estática", Justification = "É necessário para usar texto variável.")]
        public static void ExibirLog(string[] mensagens, string? scope = null, string separadorLogs = " ")
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

            if (scope != null)
            {
                using (logger.BeginScope(scope))
                {
                    logger.LogInformation(string.Join(separadorLogs, mensagens));
                }
            }
            else logger.LogInformation(string.Join(separadorLogs, mensagens));
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
                string exePath = ProcessarPath(ExePath);
                string exePathDiretorio = ProcessarPath(ExePathDiretorio ?? "");
                string nomeProcesso = Path.GetFileNameWithoutExtension(exePath);
                string exeName = Path.GetFileName(exePath);
                string pathExe = string.IsNullOrEmpty(exePathDiretorio) ?
                    exePath.Replace(@$"\{exeName}", "") : exePathDiretorio;
                string[] nomesProcesso = [nomeProcesso, exeName];
                bool consulta(Executavel e) => nomesProcesso.Contains(e.Processo.ProcessName) && e.Processo.StartInfo.FileName == exePath
                    && e.Processo.StartInfo.WorkingDirectory == pathExe && e.Processo.StartInfo.Arguments == ExeArgumentos
                    && e.Processo.StartInfo.CreateNoWindow == !JanelaVisivel;
                var exec = Executaveis.FirstOrDefault(consulta)?.Processo;

                try
                {
                    exec ??= Process.GetProcesses().FirstOrDefault(p => p.Id != Environment.ProcessId && nomesProcesso.Contains(p.ProcessName)
                       && (p.MainModule == null
                           || (p.MainModule.ModuleName == exeName && (p.MainModule.FileName.StartsWith(pathExe)
                               || pathExe.StartsWith(p.MainModule.FileName.Replace(@$"\{exeName}", ""))))));

                    if (exec != null)
                    {
                        if (!exec.Responding)
                        {
                            string[] mensagens = [$"{exeName} Não está respondendo!"];

                            if (!exec.HasExited)
                            {
                                exec.Kill();
                                mensagens = [.. mensagens.Append(" Finalizado!")];
                            }

                            ExibirLog(mensagens, $"[SSID {exec.Id} ({exec.ProcessName})]");
                            exec = null;
                        }
                    }

                    if (exec == null)
                    {
                        ProcessStartInfo info = new() { FileName = exePath, WorkingDirectory = pathExe, Arguments = ExeArgumentos, CreateNoWindow = !JanelaVisivel };

                        ExibirLog($"Inicializando {exeName}...");
                        exec = Process.Start(info);

                        if (exec != null)
                        {
                            Executaveis = [.. Executaveis.Where(e => !e.Processo.HasExited).Append(new() { Processo = exec, AutoFechar = AutoFechar })];
                            ExibirLog("Inicializado!", $"[SSID {exec.Id} ({exec.ProcessName})]");
                        }
                    }
                }
                catch (Win32Exception ex)
                {
                    ExibirLog($"Falha ao gerenciar {exeName}... [{ex.GetType()}] {ex.Message}");
                }
            }
        }

        public static void OnShutdown()
        {
            foreach (var exec in Executaveis.Where(e => e.AutoFechar || !e.Processo.Responding).Select(e => e.Processo))
            {
                if (!exec.HasExited)
                {
                    if (exec.CloseMainWindow()) exec.WaitForExit(MILLISEGUNDO_AGUARDAR_FECHAR);
                    else exec.Kill();
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

                foreach (var header in headersOriginais.Where(h => headersAdicionais.Any(ha => FlagChaveSubstRegex().Replace(ha.Key, "") == h.Key || keysCoringa.Contains(ha.Key))))
                {
                    string[] valores = [];
                    var listaHeaders = headersAdicionais.Where(h => h.Key.Equals(header.Key, StringComparison.InvariantCultureIgnoreCase) || h.Key == "").ToDictionary();
                    var listaHeadersSubstitutos = headersAdicionais.Where(h => (FlagChaveSubstRegex().Replace(h.Key, "").Equals(header.Key, StringComparison.InvariantCultureIgnoreCase)
                            && !h.Key.Equals(header.Key, StringComparison.InvariantCultureIgnoreCase)) || h.Key == "*")
                        .ToDictionary(h => FlagChaveSubstRegex().Replace(h.Key, ""), h => h.Value.Select(v => v.ProcessarStringSubstituicao(this)).ToArray());

                    if (listaHeaders.Count(l => l.Key != "") < listaHeadersSubstitutos.Count(l => l.Key != ""))
                    {
                        if (listaHeadersSubstitutos.TryGetValue(header.Key, out var headerValores))
                        {
                            headersOriginais[header.Key] = headerValores;
                        }
                    }
                    else
                    {
                        bool substituirValores = false;

                        valores = [];

                        foreach (var valor in header.Value)
                        {
                            string valorTemp = valor;

                            foreach (var headerAdicional in listaHeaders)
                            {

                                if (listaHeadersSubstitutos.TryGetValue(headerAdicional.Key, out var valoresHeaderSubs))
                                {
                                    substituirValores = true;

                                    uint i = 0;

                                    foreach (var valorHeader in headerAdicional.Value)
                                    {
                                        Regex substRegex = new(valorHeader.ProcessarStringSubstituicao(this));
                                        var valido = substRegex.IsMatch(valorTemp);

                                        if (valido)
                                        {
                                            if (valoresHeaderSubs.Length == headerAdicional.Value.Length)
                                            {
                                                valorTemp = substRegex.Replace(valorTemp, valoresHeaderSubs[i]);
                                            }
                                            else
                                            {
                                                string valorSubstitudo = valoresHeaderSubs.OrderByDescending(v =>
                                                    {
                                                        Match[] separadores = [.. CharsSeparadoresRegex().Matches(valorTemp).ToArray()];
                                                        char charSeparadorPrincipal = separadores.OrderByDescending(s => separadores.Count(sc => sc.Value == s.Value))
                                                            .FirstOrDefault()?.Value.First() ?? '\0';

                                                        if (charSeparadorPrincipal == '\0')
                                                        {
                                                            return 0;
                                                        }

                                                        return Math.Abs(v.Split(charSeparadorPrincipal).Length - valorTemp.Split(charSeparadorPrincipal).Length);
                                                    }).ThenBy(v => Math.Abs(v.Length - valorHeader.Length)).ThenBy(v => v.Length).First();

                                                valorTemp = substRegex.Replace(valorTemp, valorSubstitudo);

                                                break;
                                            }
                                        }

                                        i++;
                                    }
                                }
                                else
                                {
                                    valorTemp = valorTemp.ProcessarStringSubstituicao(this, true);
                                }

                                valores = [.. valores.Append(valorTemp)];
                            }
                        }

                        headersOriginais[header.Key] = substituirValores ? valores : [.. headersOriginais[header.Key].Union(valores)];
                    }
                }

                foreach (var header in headersAdicionais.Where(h => !keysCoringa.Contains(h.Key) && !FlagChaveSubstRegex().IsMatch(h.Key)
                    && !headersAdicionais.Any(ha => FlagChaveSubstRegex().Replace(ha.Key, "") == h.Key && ha.Key != h.Key) && !headersOriginais.ContainsKey(h.Key)))
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
        private static partial Regex FlagChaveSubstRegex();

        [GeneratedRegex(@"(?:(?<!^[a-zA-Z]):)|(?:(?<!(?:^\\?)|(?:\w+[:%])|[\w.~])[\\/](?!%?\w))|[*?""<>|]")]
        public static partial Regex CharsInvalidosPathArquivoRegex();

        [GeneratedRegex(@"[\\/;,:]+")]
        public static partial Regex CharsSeparadoresRegex();
    }
}
