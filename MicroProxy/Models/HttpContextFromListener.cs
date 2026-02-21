using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using System.IO.Pipelines;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MicroProxy.Models
{
    public interface IHttpContextFromListenerAccessor
    {
        /// <summary>
        /// Gets or sets the current <see cref="HttpContext"/>. Returns <see langword="null" /> if there is no active <see cref="HttpContext" />.
        /// </summary>
        HttpContextFromListener? HttpContext { get; set; }
    }
    public class HttpContextFromListenerAccessor : IHttpContextFromListenerAccessor
    {
        private static readonly AsyncLocal<HttpContextFromListenerHolder> _httpContextCurrent = new();

        /// <inheritdoc/>
        public HttpContextFromListener? HttpContext
        {
            get
            {
                return _httpContextCurrent.Value?.Context;
            }
            set
            {
                _httpContextCurrent.Value?.Context = null;

                if (value != null)
                { _httpContextCurrent.Value = new HttpContextFromListenerHolder { Context = value }; }
            }
        }

        private sealed class HttpContextFromListenerHolder
        {
            public HttpContextFromListener? Context;
        }
    }
    public class HttpContextFromListener : IDisposable
    {
        public HttpContextFromListener(Stream stream)
        {
            Request = new(stream, this);
            Response = new(stream, this);
            RequestAborted = cancellationTokenSource.Token;
        }

        private readonly CancellationTokenSource cancellationTokenSource = new();
        private bool disposedValue;

        public ISession? Session { get; private set; }
        public HttpRequestFromListener Request { get; }
        public HttpResponseFromListener Response { get; }
        public CancellationToken RequestAborted { get; set; }
        public ConnectionInfoFromListener Connection { get; } = new();

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    Request.Dispose();
                    Response.Dispose();
                    cancellationTokenSource.Dispose();
                }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    public class ConnectionInfoFromListener
    {
        public X509Certificate2? ClientCertificate { get; }
        public IPAddress LocalIpAddress { get; } = IPAddress.Loopback;
        public IPAddress RemoteIpAddress { get; } = IPAddress.Loopback;
    }

    public abstract class HttpPacoteFromListener(HttpContextFromListener context) : IDisposable
    {
        private bool disposedValue;

        public HttpContextFromListener HttpContext { get; } = context;
        public IHeaderDictionary Headers { get; } = new HeaderDictionary();
        public BodyStream Body { get; set; } = null!;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing) { Body.Dispose(); }

                disposedValue = true;
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    public class HttpRequestFromListener : HttpPacoteFromListener
    {
        internal HttpRequestFromListener(Stream stream, HttpContextFromListener context) : base(context)
        {
            var req = ReadLine(stream).Split(' ');
            string[] header;

            uri = new(req[1], UriKind.RelativeOrAbsolute);
            Method = req[0];
            Path = uri.IsAbsoluteUri ? uri.AbsolutePath : uri.OriginalString;
            QueryString = new QueryString(uri.IsAbsoluteUri ? uri.Query : (uri.OriginalString.Contains('?') ? uri.OriginalString.Split('?')[1] : null));
            Protocol = req[2];

            do
            {
                header = ReadLine(stream).Split(": ") ?? [];
                if (header.Length > 1) { Headers.Append(header[0], header[1]); }
            } while (header.Length > 1);

            Body = new(stream, this, true, false);
        }

        private readonly Uri uri;
        public string Protocol { get; private set; } = null!;
        public PathString Path { get; private set; }
        public QueryString QueryString { get; private set; }
        public string Method { get; private set; } = null!;
        public bool IsHttps => Body.BaseStream is SslStream;

        private static string ReadLine(Stream stream)
        {
            StringBuilder stringBuilder = new();
            var buffer = new byte[1];

            if ((stream is NetworkStream networkStream) && networkStream.Socket.Poll(0, SelectMode.SelectRead)) { networkStream.ReadTimeout = 1000; }

            do
            {
                try
                {
                    var bytesRead = stream.Read(buffer);

                    if (bytesRead != 0 && buffer[0] != '\n') { if (buffer[0] != '\r') { stringBuilder.Append((char)buffer[0]); } }
                    else { buffer[0] = (byte)'\n'; }
                }
                catch (IOException) { break; }
            } while (buffer[0] != '\n');

            return stringBuilder.ToString();
        }

        private static void CopyTo(Stream stream, Stream destino)
        {
            int bytesRead;
            var buffer = new byte[1] { 0 };

            if ((stream is NetworkStream networkStream) && networkStream.Socket.Poll(0, SelectMode.SelectRead)) { networkStream.ReadTimeout = 1000; }

            do
            {
                try
                {
                    bytesRead = stream.Read(buffer);

                    if (bytesRead != 0) { destino.Write(buffer); }
                }
                catch (IOException) { break; }
            } while (bytesRead != 0);
        }

        public void EnableBuffering()
        {
            var memoria = new MemoryStream();

            CopyTo(Body, memoria);
            memoria.Flush();
            if (Body.BaseStream is MemoryStream) { Body.Dispose(); } else { Body.Flush(); }
            Body = new(memoria, this, true, false, true);
            Body.Seek(0, SeekOrigin.Begin);
        }

        public string GetDisplayUrl()
        {
            if (uri.IsAbsoluteUri) { return uri.AbsoluteUri; }

            StringBuilder stringBuilder = new();

            stringBuilder.Append("http://");

            if (IsHttps) { stringBuilder.Insert(4, 's'); }

            stringBuilder.Append(string.IsNullOrEmpty(Headers.Host) ? "localhost" : Headers.Host);
            stringBuilder.Append(uri.OriginalString);

            return stringBuilder.ToString();
        }

        public string GetEncodedPathAndQuery() => uri.IsAbsoluteUri ? uri.PathAndQuery : uri.OriginalString;
    }

    public class HttpResponseFromListener : HttpPacoteFromListener
    {
        internal HttpResponseFromListener(Stream stream, HttpContextFromListener context) : base(context)
        {
            Body = new(stream, this, false);
        }

        public int StatusCode { get; set; } = (int)HttpStatusCode.OK;
        public bool HasStarted { get; private set; }
        public StringValues ContentType { get => Headers.ContentType; set => Headers.ContentType = value; }
        public long? ContentLength { get => Headers.ContentLength; set => Headers.ContentLength = value; }

        public virtual void Redirect(string location, bool permanent = false)
        {
            Headers.Location = location;
            StatusCode = (int)(permanent ? HttpStatusCode.PermanentRedirect : HttpStatusCode.Redirect);
        }

        public virtual async Task WriteAsync(string entrada, CancellationToken cancellationToken)
        {
            await Body.WriteAsync(Encoding.UTF8.GetBytes(entrada), cancellationToken);
            HasStarted = true;
        }

        public virtual async Task SendFileAsync(IFileInfo fileInfo, CancellationToken cancellationToken)
        {
            using var stream = fileInfo.CreateReadStream();

            await stream.CopyToAsync(Body, cancellationToken);
        }
    }

    public class BodyStream : Stream
    {
        internal BodyStream(Stream stream, HttpPacoteFromListener httpPacote, bool read = true, bool write = true, bool seek = false)
        {
            BaseStream = stream;
            CanRead = read;
            CanWrite = write;
            CanSeek = seek;
            _httpPacote = httpPacote;
        }

        public Stream BaseStream { get; }

        public override bool CanRead { get; }

        public override bool CanSeek { get; }

        public override bool CanWrite { get; }

        public override long Length => BaseStream.Length;

        public override long Position { get => BaseStream.Position; set => BaseStream.Position = value; }

        private readonly HttpPacoteFromListener _httpPacote;

        public override void Flush() => BaseStream.Flush();

        public override int Read(byte[] buffer, int offset, int count) => BaseStream.Read(buffer, offset, count);

        public override long Seek(long offset, SeekOrigin origin) => BaseStream.Seek(offset, origin);

        public override void SetLength(long value) => BaseStream.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count).Wait();

        public override void Write(ReadOnlySpan<byte> buffer) => WriteAsync(buffer.ToArray()).AsTask().Wait();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            var cabecalho = MontarCabecalho();

            return BaseStream.WriteAsync(Encoding.UTF8.GetBytes(cabecalho + Encoding.UTF8.GetString(buffer)), offset, count + cabecalho.Length, cancellationToken);
        }

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
            => BaseStream.WriteAsync(Encoding.UTF8.GetBytes(MontarCabecalho() + Encoding.UTF8.GetString(buffer.ToArray())), cancellationToken);

        private string MontarCabecalho()
        {
            var httpResponse = (HttpResponseFromListener)_httpPacote;
            return httpResponse.HasStarted ? ""
                : $"HTTP/1.1 {httpResponse.StatusCode} {(HttpStatusCode)httpResponse.StatusCode}\r\n" +
                string.Join("\r\n", httpResponse.Headers.Select(h => $"{h.Key}: {h.Value}")) +
                "\r\n";
        }
    }
}
