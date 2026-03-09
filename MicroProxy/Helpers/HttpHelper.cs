using MicroProxy.Models;
using Microsoft.Extensions.Primitives;
using System.Diagnostics;
using System.IO.Compression;
using System.Net;
using System.Text;

namespace MicroProxy.Helpers
{
    [DebuggerNonUserCode]
    public static class HttpHelper
    {
        public static string ReadLine(Stream stream) => ReadLineAsync(stream).Result;

        public static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken = default)
        {
            StringBuilder stringBuilder = new();
            var buffer = new byte[1];
            char[] cProibido = ['\n', '\r', '\0'];
            char c;

            do
            {
                cancellationToken.ThrowIfCancellationRequested();
                var bytesRead = await stream.ReadAsync(buffer, cancellationToken);

                if (bytesRead != 0) { if (!cProibido.Contains(c = (char)buffer[0])) { stringBuilder.Append(c); } }
                else { c = '\n'; }
            } while (c != '\n');

            return stringBuilder.ToString();
        }

        public static string[] LerCabecalhoPacote(Stream stream, IHeaderDictionary headers, CancellationToken cancellationToken = default)
            => LerCabecalhoPacoteAsync(stream, headers, cancellationToken).Result;

        public static async Task<string[]> LerCabecalhoPacoteAsync(Stream stream, IHeaderDictionary headers, CancellationToken cancellationToken = default)
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
            => MontarInicioCabecalhoPacote(protocol, statusCode) + MontarHeadersCabecalhoPacote(headers.ToDictionary()) + "\r\n";

        public static string MontarCabecalhoPacote(string protocol, string url, string method, IHeaderDictionary headers)
            => MontarCabecalhoPacote(protocol, url, method, headers.ToDictionary());

        public static string MontarCabecalhoPacote(string protocol, string url, string method, Dictionary<string, StringValues> headers)
            => $"{method} {url} {protocol}\r\n" + MontarHeadersCabecalhoPacote(headers.ToDictionary()) + "\r\n";

        public static string MontarInicioCabecalhoPacote(string protocol, HttpStatusCode statusCode) => $"{protocol} {(int)statusCode} {statusCode}\r\n";

        public static string MontarHeadersCabecalhoPacote(IHeaderDictionary headers) => MontarHeadersCabecalhoPacote(headers.ToDictionary());

        public static string MontarHeadersCabecalhoPacote(Dictionary<string, StringValues> headers) => string.Join("", headers.Select(h => $"{h.Key}: {h.Value}\r\n"));

        public static Stream Compactar(this Stream conteudoResposta, string? tipoConteudo = null, string? codecConteudo = null,
            CompressionLevel compressionLevel = CompressionLevel.Optimal) => conteudoResposta.Compactar(out _, tipoConteudo, codecConteudo, compressionLevel);

        public static Stream Compactar(this Stream conteudoResposta, out string? codecUsado, string? tipoConteudo = null, string? codecConteudo = null,
            CompressionLevel compressionLevel = CompressionLevel.Optimal) => conteudoResposta.ProcessarCompactacao(compressionLevel, out codecUsado, tipoConteudo, codecConteudo);

        public static Stream Extrair(this Stream conteudoResposta, string? tipoConteudo = null, string? codecConteudo = null)
            => conteudoResposta.Extrair(out _, tipoConteudo, codecConteudo);

        public static Stream Extrair(this Stream conteudoResposta, out string? codecUsado, string? tipoConteudo = null, string? codecConteudo = null)
            => conteudoResposta.ProcessarCompactacao(CompressionMode.Decompress, out codecUsado, tipoConteudo, codecConteudo);

        public static Stream ProcessarCompactacao<T>(this Stream stream, T compressionMode, string? tipoConteudo = null, string? codecConteudo = null)
            => ProcessarCompactacao(stream, (dynamic)compressionMode!, out string? _, tipoConteudo, codecConteudo);

        public static Stream ProcessarCompactacao<T>(this Stream stream, T compressionMode, out string? codecUsado, string? tipoConteudo = null, string? codecConteudo = null)
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
                    dynamic cm = compressionMode;
                    Stream pacote = stream;
                    var comprimir = compressionMode is CompressionLevel;
                    var memoria = new MemoryStream();
                    var streamUsado = comprimir ? memoria : stream;

                    switch (codecConteudo.ToLower())
                    {
                        case "brotli" or "br": pacote = new BrotliStream(streamUsado, cm); break;
                        case "gzip" or "g" or "gz": pacote = new GZipStream(streamUsado, cm); break;
                        case "deflate" or "d": pacote = new DeflateStream(streamUsado, cm); break;
                        case "zlib" or "z" or "zl" or "zstd": pacote = new ZLibStream(streamUsado, cm); break;
                    }

                    codecUsado = pacote.GetType().Name[..^"Stream".Length];

                    if (pacote != stream)
                    {
                        if (comprimir) { stream.CopyTo(pacote); } else { pacote.CopyTo(memoria); }
                        pacote.Flush(); memoria.Seek(0, SeekOrigin.Begin);
                    }
                    else { memoria.Dispose(); return stream; }

                    return memoria;
                }
            }

            codecUsado = null;

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

        public static void RedirectPreserveMethod(this HttpResponseFromListener response, string novoDestino, bool permanent = false, string? method = null)
        {
            method ??= response.HttpContext.Request.Method;

            if (HttpMethods.IsGet(method)) { response.Redirect(novoDestino); }
            else
            {
                response.Headers.Location = novoDestino;
                response.StatusCode = permanent ? StatusCodes.Status308PermanentRedirect : StatusCodes.Status307TemporaryRedirect;
            }
        }
    }
}
