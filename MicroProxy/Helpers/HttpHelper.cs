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
            var buffer = new byte[stream.CanSeek ? 1024 : 1];
            char[] cProibido = ['\n', '\r', '\0'];
            char c;

            do
            {
                cancellationToken.ThrowIfCancellationRequested();
                var posInicial = stream.CanSeek ? stream.Position : 0;
                var bytesRead = await stream.ReadAsync(buffer, cancellationToken);

                if (bytesRead != 0)
                {
                    if (bytesRead > 1)
                    {
                        var i = buffer.IndexOf((byte)'\n');

                        if (i > 0)
                        {
                            stream.Seek(posInicial + i + 1, SeekOrigin.Begin);
                            stringBuilder.Append(Encoding.Default.GetString(buffer[..i]).TrimEnd(cProibido));
                        }
                        else if (i == -1) { stringBuilder.Append(Encoding.Default.GetString(buffer).TrimEnd(cProibido)); }
                        var teste = Encoding.Default.GetString(buffer);

                        c = '\n';
                    }
                    else if (!cProibido.Contains(c = (char)buffer[0])) { stringBuilder.Append(c); }
                }
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
                else if (stream.CanSeek && header[0].Length > 0)
                {
                    var buffer = new byte[4];

                    stream.Seek(-header[0].Length, SeekOrigin.Current);
                    do
                    {
                        _ = await stream.ReadAsync(buffer, cancellationToken);

                        if (buffer.Count(b => b.Equals((byte)'\n')) < 2)
                        {
                            if (stream.Position >= (buffer.Length - 1)) { stream.Seek(-buffer.Length - 1, SeekOrigin.Current); }
                            else { break; }
                        }
                    } while (buffer.Count(b => b.Equals((byte)'\n')) < 2);

                    var i = buffer.Reverse().ToArray().IndexOf((byte)'\n');
                    if (i != -1) { stream.Seek(-i, SeekOrigin.Current); }
                }
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

        public static string MontarHeadersCabecalhoPacote(Dictionary<string, StringValues> headers) => string.Join("", headers.SelectMany(h => h.Value.Select(v => $"{h.Key}: {v}\r\n")));

        public static Stream Compactar(this Stream stream, string? tipoConteudo = null, string? codecConteudo = null,
            CompressionLevel compressionLevel = CompressionLevel.Optimal) => stream.Compactar(out _, tipoConteudo, codecConteudo, compressionLevel);

        public static Stream Compactar(this Stream stream, out string? codecUsado, string? tipoConteudo = null, string? codecConteudo = null,
            CompressionLevel compressionLevel = CompressionLevel.Optimal) => stream.ProcessarCompactacao(compressionLevel, out codecUsado, tipoConteudo, codecConteudo);

        public static Stream Extrair(this Stream stream, string? tipoConteudo = null, string? codecConteudo = null)
            => stream.Extrair(out _, tipoConteudo, codecConteudo);

        public static Stream Extrair(this Stream stream, out string? codecUsado, string? tipoConteudo = null, string? codecConteudo = null)
            => stream.ProcessarCompactacao(CompressionMode.Decompress, out codecUsado, tipoConteudo, codecConteudo);

        public static Stream ProcessarCompactacao(this Stream stream, dynamic compressionMode, string? tipoConteudo = null, string? codecConteudo = null)
            => ProcessarCompactacao(stream, compressionMode, out string? _, tipoConteudo, codecConteudo);

        public static Stream ProcessarCompactacao(this Stream stream, dynamic compressionMode, out string? codecUsado, string? tipoConteudo = null, string? codecConteudo = null)
        {
            if (compressionMode is not CompressionLevel && compressionMode is not CompressionMode) { throw new ArgumentException("Argumento inválido", nameof(compressionMode)); }

            if (tipoConteudo == null
                || tipoConteudo.StartsWith("text", StringComparison.InvariantCultureIgnoreCase)
                || tipoConteudo.StartsWith("application", StringComparison.InvariantCultureIgnoreCase))
            {
                if (stream.CanSeek) { stream.Seek(0, SeekOrigin.Begin); }

                if (codecConteudo != null)
                {
                    Stream pacote;
                    var memoria = new MemoryStream();

                    codecUsado = null;

                    if (compressionMode is CompressionLevel cl)
                    {
                        switch (codecConteudo.ToLower())
                        {
                            case "brotli" or "br": pacote = new BrotliStream(memoria, cl); break;
                            case "gzip" or "g" or "gz": pacote = new GZipStream(memoria, cl); break;
                            case "deflate" or "d": pacote = new DeflateStream(memoria, cl); break;
                            case "zlib" or "z" or "zl" or "zstd": pacote = new ZLibStream(memoria, cl); break;
                            default: memoria.Dispose(); return stream;
                        }

                        stream.CopyTo(pacote);
                    }
                    else if (compressionMode is CompressionMode cm)
                    {
                        switch (codecConteudo.ToLower())
                        {
                            case "brotli" or "br": pacote = new BrotliStream(stream, cm); break;
                            case "gzip" or "g" or "gz": pacote = new GZipStream(stream, cm); break;
                            case "deflate" or "d": pacote = new DeflateStream(stream, cm); break;
                            case "zlib" or "z" or "zl" or "zstd": pacote = new ZLibStream(stream, cm); break;
                            default: memoria.Dispose(); return stream;
                        }

                        pacote.CopyTo(memoria);
                    }
                    else { memoria.Dispose(); return stream; }

                    codecUsado = pacote.GetType().Name[..^"Stream".Length];
                    pacote.Flush(); memoria.Flush(); memoria.Seek(0, SeekOrigin.Begin);

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
