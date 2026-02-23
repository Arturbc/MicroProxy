using System.Net;
using System.Text;

namespace MicroProxy.Helpers
{
    public static class StreamHelper
    {
        public static string ReadLine(Stream stream)
        {
            StringBuilder stringBuilder = new();
            var buffer = new byte[1];

            do
            {
                var bytesRead = stream.Read(buffer);

                if (bytesRead != 0 && buffer[0] != '\n') { if (buffer[0] != '\r') { stringBuilder.Append((char)buffer[0]); } }
                else { buffer[0] = (byte)'\n'; }
            } while (buffer[0] != '\n');

            return stringBuilder.ToString();
        }

        public static string MontarCabecalhoPacote(string protocol, HttpStatusCode statusCode, IHeaderDictionary headers)
            => $"{protocol} {(int)statusCode} {statusCode}\r\n" +
                string.Join("", headers.Select(h => $"{h.Key}: {h.Value}\r\n")) +
                "\r\n";

        public static string MontarCabecalhoPacote(string protocol, string url, string method, IHeaderDictionary headers)
            => $"{method} {url} {protocol}\r\n" +
                string.Join("", headers.Select(h => $"{h.Key}: {h.Value}\r\n")) +
                "\r\n";
    }
}
