using Microsoft.Extensions.Primitives;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace MicroProxy.Helpers
{
    public static class HttpHelper
    {
        public static string ReadLine(Stream stream) => ReadLineAsync(stream).Result;

        public static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken = default)
        {
            StringBuilder stringBuilder = new();
            var buffer = new byte[1];

            do
            {
                cancellationToken.ThrowIfCancellationRequested();
                var bytesRead = await stream.ReadAsync(buffer, cancellationToken);

                if (bytesRead != 0 && buffer[0] != '\n') { if (buffer[0] != '\r') { stringBuilder.Append((char)buffer[0]); } }
                else { buffer[0] = (byte)'\n'; }
            } while (buffer[0] != '\n');

            return stringBuilder.ToString();
        }

        public static string[] LerCabecalhoPacote(Stream stream, NetworkStream clientStream, IHeaderDictionary headers, CancellationToken cancellationToken = default)
            => LerCabecalhoPacoteAsync(stream, clientStream, headers, cancellationToken).Result;

        public static async Task<string[]> LerCabecalhoPacoteAsync(Stream stream, NetworkStream clientStream, IHeaderDictionary headers, CancellationToken cancellationToken = default)
        {
            string[] info = [];
            string[] header;
            string linha = await ReadLineAsync(stream, cancellationToken);

            if (!string.IsNullOrEmpty(linha)) { info = linha.Split(' '); }

            do
            {
                header = (await ReadLineAsync(stream, cancellationToken)).Split(": ") ?? [];
                if (header.Length > 1) { headers.Append(header[0], new(header[1])); }
            } while (header.Length > 1);

            return info;
        }

        public static string MontarCabecalhoPacote(string protocol, HttpStatusCode statusCode, IHeaderDictionary headers)
            => MontarCabecalhoPacote(protocol, statusCode, headers.ToDictionary());

        public static string MontarCabecalhoPacote(string protocol, HttpStatusCode statusCode, Dictionary<string, StringValues> headers)
            => $"{protocol} {(int)statusCode} {statusCode}\r\n" +
                string.Join("", headers.Select(h => $"{h.Key}: {h.Value}\r\n")) +
                "\r\n";

        public static string MontarCabecalhoPacote(string protocol, string url, string method, IHeaderDictionary headers)
            => MontarCabecalhoPacote(protocol, url, method, headers.ToDictionary());

        public static string MontarCabecalhoPacote(string protocol, string url, string method, Dictionary<string, StringValues> headers)
            => $"{method} {url} {protocol}\r\n" +
                string.Join("", headers.Select(h => $"{h.Key}: {h.Value}\r\n")) +
                "\r\n";

        public static Stream Compactar(this Stream conteudoResposta, string? tipoConteudo = null, string? codecConteudo = null,
            CompressionLevel compressionLevel = CompressionLevel.Optimal) => conteudoResposta.ProcessarCompactacao(compressionLevel, tipoConteudo, codecConteudo);

        public static Stream Extrair(this Stream conteudoResposta, string? tipoConteudo = null, string? codecConteudo = null)
            => conteudoResposta.ProcessarCompactacao(CompressionMode.Decompress, tipoConteudo, codecConteudo);

        public static Stream ProcessarCompactacao<T>(this Stream stream, T compressionMode, string? tipoConteudo = null, string? codecConteudo = null)
            where T : Enum
        {
            if (compressionMode is not CompressionLevel && compressionMode is not CompressionMode) { throw new ArgumentException("Argumento inválido", nameof(compressionMode)); }

            if (tipoConteudo == null
                || tipoConteudo.StartsWith("text", StringComparison.InvariantCultureIgnoreCase)
                || tipoConteudo.StartsWith("application", StringComparison.InvariantCultureIgnoreCase))
            {
                if (stream.CanSeek) { stream.Seek(0, SeekOrigin.Begin); }

                if (codecConteudo != null)
                {
                    if (codecConteudo.Equals("br", StringComparison.OrdinalIgnoreCase)) { codecConteudo = "Brotli"; }
                    var tipo = Type.GetType($"{codecConteudo}Stream", true, true)!;
                    dynamic conteudoProc = Activator.CreateInstance(tipo, [stream, compressionMode])!;

                    return conteudoProc;
                }
            }

            return stream;
        }

        public static async Task<string> BodyAsStringAsync(this Stream conteudoResposta, string? tipoConteudo = null, string? codecConteudo = null, CancellationToken cancellationToken = default)
        {
            var resultado = $"Dado[{tipoConteudo}]";

            if (tipoConteudo == null
                || tipoConteudo.StartsWith("text", StringComparison.InvariantCultureIgnoreCase)
                || tipoConteudo.StartsWith("application", StringComparison.InvariantCultureIgnoreCase))
            {
                conteudoResposta.Seek(0, SeekOrigin.Begin);

                resultado = await new StreamReader(conteudoResposta.Extrair(tipoConteudo, codecConteudo)).ReadToEndAsync(cancellationToken);
            }

            return resultado;
        }
    }
}
