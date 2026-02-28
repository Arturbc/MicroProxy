using Microsoft.Extensions.FileProviders;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Text.RegularExpressions;
using static MicroProxy.Extensions.ExceptionExtension;
using static MicroProxy.Helpers.CriptografiaHelper;

namespace MicroProxy.Helpers
{
    [DebuggerNonUserCode]
    public static partial class FuncoesHelper
    {
        public static char?[] UnidadesBytesArquivos { get; } = [null, 'K', 'M', 'G', 'T', 'P', 'H'];

        //Senha com 9 caracteres
        public static string GerarSenha(int nLengthMinuscula = 3, int nLengthMaiuscula = 2, int nLengthEspecial = 2, int nLengthNumero = 2)
        {
            Dictionary<string, string> dictChar = new()
            {
                { "minuscula", "abcdefghijklmnpqrstuvwxyz" },
                { "maiusucula", "ABCDEFGHIJKLMNOPQRSTUVWXYZ" },
                { "numero", "0123456789" },
                { "especial", "#/&" }
            };
            Dictionary<string, int> dictLength = new()
            {
                { "minuscula", nLengthMinuscula },
                { "maiusucula", nLengthMaiuscula },
                { "numero", nLengthNumero },
                { "especial", nLengthEspecial }
            };
            Random rnd = new();
            string senhaAleatoria = "";

            foreach (string chave in dictChar.Keys)
            {
                for (int i = 0; i < dictLength[chave]; i++)
                {
                    string chars = dictChar[chave];
                    int nRnd = rnd.Next(chars.Length);
                    int nSenha = senhaAleatoria.Length;
                    int nRndInserir = rnd.Next(nSenha + 1);

                    senhaAleatoria = senhaAleatoria.Insert(nRndInserir, chars[nRnd].ToString());
                }
            }

            return senhaAleatoria;
        }

        public static bool IsValid(string senhaNova, int Minimum_Length = 8, int Lower_Case_length = 1, int Upper_Case_length = 1, int NonAlpha_length = 1, int Numeric_length = 1)
        {
            if (senhaNova.Length < Minimum_Length) return false;
            if (MaiusculasRegex().Count(senhaNova) < Upper_Case_length) return false;
            if (MinusculasRegex().Count(senhaNova) < Lower_Case_length) return false;
            if (NumericoRegex().Count(senhaNova) < Numeric_length) return false;
            if (NaoAlfaNumRegex().Count(senhaNova) < NonAlpha_length) return false;

            return true;
        }

        public static Dictionary<string, string> TratarDadosSensiveis(Dictionary<string, string?> dic, string escopo = "")
        {
            List<string> mensagensAviso = [];
            Dictionary<string, string> novosValores = [];

            if (!string.IsNullOrEmpty(escopo)) { escopo = " de " + escopo; }

            foreach (var item in dic.Where(d => !string.IsNullOrEmpty(d.Value)))
            {
                var novoValor = item.Value!;

                try
                {
                    if (NaoHexRegex().IsMatch(novoValor)) { novoValor = novoValor.DecifrarBase64(); }
                    else { try { novoValor = novoValor.DecifrarHex(); } catch (FormatException) { novoValor = novoValor.DecifrarBase64(); } }

                    novosValores.Add(item.Key, novoValor);
                }
                catch (Exception ex) when (ex.Contains([typeof(FormatException), typeof(OverflowException)]))
                {
                    if (!string.IsNullOrEmpty(escopo))
                    {
                        mensagensAviso.AddRange([
                            @$"O item ""{item.Key}"" de valor ""{novoValor}"" foi detectado nas configurações{escopo}.",
                            $@"Por favor, substitua por um dos valores cifrados:",
                            $@"Hex: ""{novoValor.CifrarHex()}""",
                            $@"Base64: ""{novoValor.CifrarBase64()}""",
                            ""
                        ]);
                    }
                }
            }

            if (mensagensAviso.Count != 0) { ExibirLog(mensagensAviso, $"Configuração{escopo}", LogLevel.Warning, " " + Environment.NewLine, true, false); }

            return novosValores;
        }

        public static void ExibirLog(string mensagem, string? scope = null, LogLevel level = LogLevel.Information, bool includeScopes = true, bool singleLine = true, string formatoHora = "")
            => ExibirLog([mensagem], scope, level, " ", includeScopes, singleLine, formatoHora);

        public static void ExibirLog(IEnumerable<string> mensagens, string? scope = null, string separadorLogs = " ",
            LogLevel level = LogLevel.Information, bool includeScopes = true, bool singleLine = true, string formatoHora = "")
                => ExibirLog(mensagens, scope, level, separadorLogs, includeScopes, singleLine, formatoHora);

        public static void ExibirLog(IEnumerable<string> mensagens, string? scope, LogLevel level, string separadorLogs = " ", bool includeScopes = true, bool singleLine = true, string formatoHora = "")
        {
            if (string.IsNullOrEmpty(formatoHora))
            {
                formatoHora = "HH:mm:ss ";
            }

            using ILoggerFactory loggerFactory =
                LoggerFactory.Create(builder =>
                    builder.AddSimpleConsole(options =>
                    {
                        options.IncludeScopes = includeScopes;
                        options.SingleLine = singleLine;
                        options.TimestampFormat = formatoHora;
                    }));
            ILogger<Program> logger = loggerFactory.CreateLogger<Program>();

            if (scope != null)
            {
                using (logger.BeginScope(scope))
                {
                    logger.Log(level, string.Join(separadorLogs, mensagens));
                }
            }
            else logger.Log(level, string.Join(separadorLogs, mensagens));
        }

        public static string ObterTamanhoArquivo(this FileInfo fileInfo, string formatoTamanho = "N2", int tamByte = 1024)
        {
            double tamArquivo = fileInfo.Length;
            int i = 0;
            string formatoTamanhoAtual = "N0";

            for (; tamArquivo >= tamByte; i++)
            {
                tamArquivo /= tamByte;
                formatoTamanhoAtual = formatoTamanho;
            }

            return $"{tamArquivo.ToString(formatoTamanhoAtual)}{UnidadesBytesArquivos[i]}B";
        }

        public static string RemoverAcentos(this string str)
        {
            if (string.IsNullOrEmpty(str)) { return str; }

            string normalized = str.Normalize(NormalizationForm.FormD);
            StringBuilder sb = new();

            foreach (char c in normalized)
            {
                UnicodeCategory uc = CharUnicodeInfo.GetUnicodeCategory(c);

                if (uc != UnicodeCategory.NonSpacingMark) { sb.Append(c); }
            }

            return sb.ToString().Normalize(NormalizationForm.FormC);
        }

        public static bool EnviarEmail(string destinatario, MailAddress sender, string html, string[] SMTPs, string? assunto = null,
                                       MailPriority prioridade = MailPriority.Normal, bool ssl = false, NetworkCredential? credentials = null)
            => EnviarEmailAsync(destinatario, sender, html, SMTPs, assunto, prioridade, ssl, credentials).Result;

        public static async Task<bool> EnviarEmailAsync(string destinatario, MailAddress sender, string html, string[] SMTPs, string? assunto = null,
                                                        MailPriority prioridade = MailPriority.Normal, bool ssl = false, NetworkCredential? credentials = null)
        {
            using var mail = new MailMessage();
            var recipient = new MailAddress(destinatario);
            mail.To.Add(recipient);
            mail.From = sender;
            mail.Subject = assunto ?? "Sem assunto";
            mail.Body = html;
            mail.IsBodyHtml = true;
            mail.Priority = prioridade;

            foreach (var SMTP in SMTPs)
            {
                try
                {
                    var portaStr = PortaUrlRegex().Match(SMTP).Value;

                    if (portaStr == "") { portaStr = "25"; }

                    using var client = new SmtpClient
                    {
                        EnableSsl = ssl,
                        Port = int.Parse(portaStr),
                        Host = SMTP.Replace($":{portaStr}", ""),
                        Credentials = credentials,
                        DeliveryMethod = SmtpDeliveryMethod.Network
                    };

                    await client.SendMailAsync(mail);

                    return true;
                }
                catch (Exception ex)
                {
                    if (SMTP == SMTPs.Last())
                    {
                        var e = ex;

                        throw new("Falha ao enviar e-mail!", e);
                    }
                }
            }

            return false;
        }

        public static bool Arquivo_Incrementar(string strCaminho, string strTexto)
        {
            try
            {
                DateTime dataLog;
                DateTime dataNow = DateTime.Now;
                string strDataLog = "";
                string srtDataNow = dataNow.ToShortDateString();

                strCaminho = Path.GetFullPath(strCaminho);
                char separador = Path.DirectorySeparatorChar;
                string[] partesCaminho = strCaminho.Split([separador, '/']);
                string strDiretorio = string.Join(separador, partesCaminho[..(partesCaminho.Length - 1)]);

                if (!File.Exists(strCaminho))
                {
                    if (!Directory.Exists(strDiretorio)) { Directory.CreateDirectory(strDiretorio); }
                }
                else
                {
                    dataLog = File.GetLastWriteTime(strCaminho);
                    strDataLog = dataLog.ToShortDateString();

                    if (DateOnly.FromDateTime(dataNow) > DateOnly.FromDateTime(dataLog))
                    {
                        if (partesCaminho.Length > 1) { strDiretorio += separador; }

                        File.Move(strCaminho, $@"{strDiretorio}{Path.GetFileNameWithoutExtension(strCaminho)}_{dataLog:yyyy-MM-dd}{Path.GetExtension(strCaminho)}");
                    }
                }

                if (strDataLog != srtDataNow)
                {
                    strTexto = $"------------------------------------------------------------------- Data dos logs abaixo: {srtDataNow} -------------------------------------------------------------------------------------------------------\r\n\r\n" +
                        $"{strTexto}";
                }

                File.AppendAllText(strCaminho, $"\r\n{strTexto}\r\n");

                return true;
            }
            catch (IOException)
            {
                // Funcoes.ErroReportar(exc)
                return false;
            }
        }

        public static string LerArquivoTexto(string strCaminho)
        {
            var pathPart = strCaminho.Split(Path.DirectorySeparatorChar);
            var arquivo = new PhysicalFileProvider(strCaminho.TrimEnd(pathPart.Last().ToCharArray()).TrimEnd(Path.DirectorySeparatorChar)).GetFileInfo(pathPart.Last());

            return arquivo.LerArquivoTexto();
        }

        public static string LerArquivoTexto(this IFileInfo arquivo) => arquivo.LerArquivoTexto(out _);

        public static string LerArquivoTexto(this IFileInfo arquivo, out Encoding encoding)
        {
            var stream = arquivo.CreateReadStream();
            var formFile = new FormFile(stream, 0, stream.Length, arquivo.Name, arquivo.Name);

            return LerArquivoTexto(formFile, out encoding);
        }

        public static string LerArquivoTexto(this IFormFile arquivo) => arquivo.LerArquivoTexto(out _);

        public static string LerArquivoTexto(this IFormFile arquivo, out Encoding encoding)
        {
            using var memoryStream = new MemoryStream();
            byte[] buffer;
            string txt;

            encoding = Encoding.UTF8;
            arquivo.CopyTo(memoryStream);
            buffer = memoryStream.ToArray();

            try { txt = encoding.GetString(buffer); if (txt.Any(c => c > 255)) { throw new InvalidDataException("O arquivo possui caractere(s) inválido(s)!"); } }
            catch { encoding = Encoding.GetEncoding(1252); txt = encoding.GetString(buffer); }

            return txt;
        }

        public static string ProcessarPath(string path)
        {
            if (path.Trim() != "")
            {
                path = Path.GetFullPath(Environment.ExpandEnvironmentVariables(path));
            }

            return path;
        }

        [GeneratedRegex("[A-Z]")]
        public static partial Regex MaiusculasRegex();
        [GeneratedRegex("[a-z]")]
        public static partial Regex MinusculasRegex();
        [GeneratedRegex("[0-9]")]
        public static partial Regex NumericoRegex();
        [GeneratedRegex("[^0-9]")]
        public static partial Regex NaoNumericoRegex();
        [GeneratedRegex("[^0-9A-Z]", RegexOptions.IgnoreCase)]
        public static partial Regex NaoAlfaNumRegex();
        [GeneratedRegex("(?:^(?: *&& *)+)|(?:(?: *&& *)+$)")]
        public static partial Regex FiltroExtraTabelaConectorExtremidadeRegex();
        [GeneratedRegex("(?: *&& *){2,}")]
        public static partial Regex FiltroExtraTabelaDuploConectorRegex();
        [GeneratedRegex(@"\?.+")]
        public static partial Regex QueryStringRegex();
        [GeneratedRegex("(?<esquema>https?:(?:(?://)|^))?(?<authority>[^/]+)")]
        public static partial Regex HostUrlRegex();
        [GeneratedRegex("(?<=:)\\d+")]
        public static partial Regex PortaUrlRegex();
        [GeneratedRegex(@"(?:(?:(?<ipv4>(?:\d{1,3}\.){3}\d{1,3}))|(?:(?:\[(?=[^]]+\]:))?(?<ipv6>(?:(?:\w{1,4}:){7}\w{1,4})|(?:(?:\w{1,4}:){1,6}:(?:\w{1,4})?)|(?:(?:\w{1,4})?:(?::\w{1,4}){1,6})|(?:::))(?:(?<=\[[^]]+)\](?=:))?))(?::(?<porta>\d{1,5}))?")]
        public static partial Regex IpPortaRegex();
    }

    public class ParamTabela
    {
        public int pagina = 1, itens = 10, maxItens = 0, totalItens = 0;
        public bool filtroUsuario = false, tituloTemplateVisivel = false;
        public bool? orderAsc;
        public string? colunaOrder, filtroExtra, ancora, layout;
        public string action = "Index", controller = "";
    }
}
