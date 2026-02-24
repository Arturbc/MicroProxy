using Microsoft.Extensions.Primitives;
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

            do
            {
                string linha = await ReadLineAsync(stream, cancellationToken);
                if (!string.IsNullOrEmpty(linha)) { info = linha.Split(' '); }
                else { await Task.Delay(1, cancellationToken); }
            } while (!clientStream.DataAvailable && info.Length != 3);

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
    }
}
