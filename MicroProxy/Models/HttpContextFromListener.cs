using MicroProxy.Extensions;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
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
        public HttpContextFromListener(Stream stream, NetworkStream clientStream)
        {
            Request = new(stream, clientStream, this);
            Response = new(stream, clientStream, this);
            Connection = new(clientStream.Socket,
                stream is SslStream ssl && ssl.RemoteCertificate != null ? new X509Certificate2(ssl.RemoteCertificate) : null);
            RequestAborted = cancellationTokenSource.Token;
        }

        private readonly CancellationTokenSource cancellationTokenSource = new();
        private bool disposedValue;

        public ISession? Session { get; private set; }
        public HttpRequestFromListener Request { get; }
        public HttpResponseFromListener Response { get; }
        public CancellationToken RequestAborted { get; set; }
        public ConnectionInfoFromListener Connection { get; }

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

    public class ConnectionInfoFromListener(Socket socket, X509Certificate2? certificado = null)
    {
        public X509Certificate2? ClientCertificate { get; } = certificado;
        public IPAddress LocalIpAddress { get; } = ((IPEndPoint)socket.LocalEndPoint!).Address;
        public IPAddress RemoteIpAddress { get; } = ((IPEndPoint)socket.RemoteEndPoint!).Address;
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
        internal HttpRequestFromListener(Stream stream, NetworkStream clientStream, HttpContextFromListener context) : base(context)
        {
            Body = new(stream, clientStream, this, true, false);
            EnableBuffering();
            var req = ReadLine(Body).Split(' ');
            string[] header;

            do
            {
                header = ReadLine(Body).Split(": ") ?? [];
                if (header.Length > 1) { Headers.Append(header[0], new(header[1])); }
            } while (header.Length > 1);

            uri = new(req[1], UriKind.RelativeOrAbsolute);
            Method = req[0];
            Path = uri.IsAbsoluteUri ? uri.AbsolutePath : uri.OriginalString;
            QueryString = new QueryString(uri.IsAbsoluteUri ? uri.Query : (uri.OriginalString.Contains('?') ? uri.OriginalString.Split('?')[1] : null));
            Protocol = req[2];
        }

        private readonly Uri uri;
        public string Protocol { get; private set; } = null!;
        public PathString Path { get; private set; }
        public QueryString QueryString { get; private set; }
        public string Method { get; private set; } = null!;
        public bool IsHttps => Body.BaseStream is SslStream;

        private static string ReadLine(BodyStream stream)
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

        public void EnableBuffering()
        {
            var clientStream = (NetworkStream)Body.GetType()
                .GetField("_clientStream", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(Body)!;
            if (Body.GetType()
                .GetField("_buffer", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(Body) is not MemoryStream)
            { Body = new(Body.BaseStream, clientStream, this, true, false, true, new MemoryStream()); }
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
        internal HttpResponseFromListener(Stream stream, NetworkStream clientStream, HttpContextFromListener context) : base(context)
        { Body = new(stream, clientStream, this, false); }

        public int StatusCode { get; set; } = (int)HttpStatusCode.OK;
        public bool HasStarted { get; private set; }
        public StringValues ContentType { get => Headers.ContentType; set => Headers.ContentType = value; }
        public long? ContentLength { get => Headers.ContentLength; set => Headers.ContentLength = value; }

        public virtual void Redirect(string location, bool permanent = false)
        {
            Headers.Location = location;
            StatusCode = (int)(permanent ? HttpStatusCode.PermanentRedirect : HttpStatusCode.Redirect);
        }

        public virtual async Task WriteAsync(string entrada, CancellationToken cancellationToken) => await Body.WriteAsync(Encoding.UTF8.GetBytes(entrada), cancellationToken);

        public virtual async Task SendFileAsync(IFileInfo fileInfo, CancellationToken cancellationToken)
        {
            using var stream = fileInfo.CreateReadStream();

            await stream.CopyToAsync(Body, cancellationToken);
        }
    }

    public class BodyStream : Stream, IDisposable
    {
        internal BodyStream(Stream stream, NetworkStream clientStream, HttpPacoteFromListener httpPacote, bool read = true, bool write = true, bool seek = false, MemoryStream? buffer = null)
        {
            BaseStream = stream is NetworkStream || stream is SslStream ? stream : throw new ArgumentException("Parâmetro to tipo inválido", nameof(stream));
            CanRead = read;
            CanWrite = write;
            CanSeek = seek;
            _httpPacote = httpPacote;
            _clientStream = clientStream;

            if (buffer != null)
            {
                do { CopyTo(buffer, BaseStream is SslStream ? 17000 : _clientStream.Socket.Available); }
                while (BaseStream is not SslStream && _clientStream.Socket.Poll(0, SelectMode.SelectRead));
                buffer.Seek(0, SeekOrigin.Begin);
                _buffer = buffer;
            }
        }

        private bool disposedValue;
        private readonly MemoryStream? _buffer = null;
        private readonly HttpPacoteFromListener _httpPacote;
        private readonly NetworkStream _clientStream;
        public Stream BaseStream { get; }
        public override bool CanRead { get; }
        public override bool CanSeek { get; }
        public override bool CanWrite { get; }
        public override long Length => BaseStream.Length;
        public override long Position { get => BaseStream.Position; set => BaseStream.Position = value; }

        public override void Flush() => BaseStream.Flush();

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count).Result;

        public override int Read(Span<byte> buffer)
        {
            var bufferArray = buffer.ToArray();
            var read = ReadAsync(bufferArray).AsTask().Result;
            bufferArray.AsSpan().CopyTo(buffer);
            return read;
        }

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            var bufferMemory = buffer.AsMemory(offset, count);
            var read = await ReadAsync(bufferMemory, cancellationToken);
            var bufferTemp = bufferMemory.ToArray();
            for (int i = 0; i < read; i++) { buffer[i] = bufferTemp[i]; }
            return read;
        }

        public override void CopyTo(Stream destination, int bufferSize = 1) => CopyToAsync(destination, bufferSize).Wait();

        public override async Task CopyToAsync(Stream destination, int bufferSize = 1, CancellationToken cancellationToken = default)
        {
            int read;
            var buffer = new byte[bufferSize];

            if (_buffer != null || BaseStream is SslStream || _clientStream.Socket.Poll(0, SelectMode.SelectRead))
            {
                read = await ReadAsync(buffer, cancellationToken);

                if (read != 0) { await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken); }
            }
        }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(new CancellationTokenSource(TimeSpan.FromSeconds(1)).Token, cancellationToken);
            int maxBuffer = _buffer != null ? 0 : Math.Min(_clientStream.Socket.Available, buffer.Length);
            int read;

            try
            {
                do
                {
                    read = _buffer != null ? await _buffer.ReadAsync(buffer, cts.Token) : await BaseStream.ReadAsync(buffer, cts.Token);

                    if (read == 0 && _buffer == null)
                    {
                        await Task.Delay(1, cts.Token);
                        maxBuffer = Math.Min(_clientStream.Socket.Available, buffer.Length);
                    }
                } while (read == 0 && _buffer == null);
            }
            catch (Exception ex) when (ex.Contains([typeof(OperationCanceledException), typeof(TaskCanceledException)])) { read = maxBuffer; }

            return read;
        }

        public override long Seek(long offset, SeekOrigin origin) => BaseStream.Seek(offset, origin);

        public override void SetLength(long value) => BaseStream.SetLength(value);

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count).Wait();

        public override void Write(ReadOnlySpan<byte> buffer) => WriteAsync(buffer.ToArray()).AsTask().Wait();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var cabecalho = MontarCabecalho();
            var bytes = string.IsNullOrEmpty(cabecalho) ? buffer : Encoding.UTF8.GetBytes(cabecalho + Encoding.UTF8.GetString(buffer.ToArray()));
            return BaseStream.WriteAsync(bytes, cancellationToken);
        }

        private string MontarCabecalho()
        {
            if (_httpPacote is HttpResponseFromListener httpResponse && !httpResponse.HasStarted)
            {
                httpResponse.GetType().GetProperty(nameof(httpResponse.HasStarted))!.SetValue(httpResponse, true);
                return $"HTTP/1.1 {httpResponse.StatusCode} {(HttpStatusCode)httpResponse.StatusCode}\r\n" +
                    string.Join("\r\n", httpResponse.Headers.Select(h => $"{h.Key}: {h.Value}")) +
                    "\r\n\r\n";
            }

            return "";
        }

        protected override void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing) { _buffer?.Dispose(); }

                base.Dispose(disposing);
                disposedValue = true;
            }
        }
    }
}
