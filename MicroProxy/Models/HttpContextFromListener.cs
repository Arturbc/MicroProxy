using MicroProxy.Extensions;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static MicroProxy.Helpers.HttpHelper;

namespace MicroProxy.Models
{
    public interface IHttpContextFromListenerAccessor
    {
        HttpContextFromListener? HttpContext { get; set; }
    }
    public class HttpContextFromListenerAccessor : IHttpContextFromListenerAccessor
    {
        private static readonly AsyncLocal<HttpContextFromListenerHolder> _httpContextCurrent = new();

        public HttpContextFromListener? HttpContext
        {
            get { return _httpContextCurrent.Value?.Context; }
            set
            {
                _httpContextCurrent.Value?.Context = null;

                if (value != null)
                { _httpContextCurrent.Value = new HttpContextFromListenerHolder { Context = value }; }
            }
        }

        private sealed class HttpContextFromListenerHolder { public HttpContextFromListener? Context; }
    }
    public class HttpContextFromListener : IDisposable
    {
        public HttpContextFromListener(Stream stream, NetworkStream clientStream, CancellationToken cancellationToken = default)
        {
            Request = new(stream, clientStream, this, cancellationToken);
            Response = new(stream, clientStream, this);
            Connection = new(clientStream.Socket,
                stream is SslStream ssl && ssl.RemoteCertificate != null ? new X509Certificate2(ssl.RemoteCertificate) : null);
            RequestAborted = cancellationToken;
        }
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
        public int Timeout { get; set; } = 100;
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
        internal HttpRequestFromListener(Stream stream, NetworkStream clientStream, HttpContextFromListener context, CancellationToken cancellationToken = default) : base(context)
        {
            string[] methodsSemBody = [HttpMethods.Head, HttpMethods.Get, HttpMethods.Connect, HttpMethods.Delete, HttpMethods.Trace];
            Body = new(stream, clientStream, this, true, false);
            string[] req = LerCabecalhoPacote(Body, Headers, cancellationToken);

            uri = new(req[1].Contains("://") || req[1].StartsWith('/') ? req[1] : "http://" + req[1], UriKind.RelativeOrAbsolute);
            Method = req[0];
            Path = uri.IsAbsoluteUri ? uri.AbsolutePath : uri.OriginalString;
            QueryString = new QueryString(uri.IsAbsoluteUri ? uri.Query : (uri.OriginalString.Contains('?') ? '?' + uri.OriginalString.Split('?')[1] : null));
            Protocol = req[2];

            if (methodsSemBody.Contains(Method) || HttpMethods.IsGet(Method)) { AtualizarBody(false, false, false); }
        }

        private readonly Uri uri;
        public string Protocol { get; private set; } = null!;
        public PathString Path { get; private set; }
        public QueryString QueryString { get; private set; }
        public string Method { get; private set; } = null!;
        public bool IsHttps => Body.BaseStream is SslStream;

        private void AtualizarBody(bool read = true, bool write = true, bool canSeek = false)
        {
            var clientStream = (NetworkStream)Body.GetType().GetField("_clientStream", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(Body)!;
            var buffer = (MemoryStream)Body.GetType().GetField("_buffer", BindingFlags.NonPublic | BindingFlags.Instance)!.GetValue(Body)!;
            Body = new(Body.BaseStream, clientStream, this, read, write, canSeek, buffer);
        }

        public void EnableBuffering() { if (!Body.CanSeek) { AtualizarBody(true, false, true); } }

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
        internal HttpResponseFromListener(Stream stream, NetworkStream clientStream, HttpContextFromListener context, bool clonarContext = false) : base(context)
        {
            if (clonarContext)
            {
                Body = new(stream, clientStream, this, true, !HttpMethods.IsHead(HttpContext.Request.Method));
                Timeout = context.Response.Timeout;
                HasStarted = context.Response.HasStarted;
                string[] resp = LerCabecalhoPacote(Body, Headers, context.RequestAborted);

                StatusCode = int.Parse(resp[1]);
            }
            else
            {
                Body = new(stream, clientStream, this, false, !HttpMethods.IsHead(HttpContext.Request.Method));
                StatusCode = (int)HttpStatusCode.OK;
            }
        }

        public int StatusCode { get; set; }
        public bool HasStarted { get; protected set; }
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

        public async Task CompleteAsync()
        {
            var cabecalho = MontarCabecalho();
            if (!string.IsNullOrEmpty(cabecalho)) { await Body.WriteAsync(Encoding.UTF8.GetBytes(cabecalho), default); }
            await Body.FlushAsync(HttpContext.RequestAborted);
        }

        private string MontarCabecalho()
        {
            var metodo = Body.GetType().GetMethod(nameof(MontarCabecalho), BindingFlags.NonPublic | BindingFlags.Instance);

            return (metodo?.Invoke(Body, null) as string) ?? "";
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1844:Fornecer substituições baseadas em memória de métodos assíncronos ao subclasse 'Stream'", Justification = "Sem necessidade")]
    public class BodyStream : Stream, IDisposable
    {
        internal BodyStream(Stream stream, NetworkStream clientStream, HttpPacoteFromListener httpPacote, bool read = true, bool write = true, bool canSeek = false, MemoryStream? buffer = null)
        {
            BaseStream = stream is NetworkStream || stream is SslStream ? stream : throw new ArgumentException("Parâmetro to tipo inválido", nameof(stream));
            CanRead = read;
            CanWrite = write;
            CanSeek = canSeek && buffer != null;
            _httpPacote = httpPacote;
            _clientStream = clientStream;
            _buffer = buffer ?? new();
            _bufferInicio = (int)_buffer.Position;
            SetDataAvailable();
        }

        private bool disposedValue;
        private int _bufferInicio;
        private readonly MemoryStream _buffer;
        private readonly HttpPacoteFromListener _httpPacote;
        private readonly NetworkStream _clientStream;
        private Stream StreamRef => CanSeek ? _buffer : BaseStream;
        public Stream BaseStream { get; }
        public override bool CanRead { get; }
        public override bool CanSeek { get; }
        public override bool CanWrite { get; }
        public override long Length => StreamRef.Length - _bufferInicio;
        public override long Position { get => StreamRef.Position - _bufferInicio; set => StreamRef.Position = value + _bufferInicio; }
        public int DataAvailable { get; private set; }

        private string MontarCabecalho()
        {
            if (_httpPacote is HttpResponseFromListener httpResponse && !httpResponse.HasStarted)
            {
                httpResponse.GetType().GetProperty(nameof(httpResponse.HasStarted))!.SetValue(httpResponse, true);
                return MontarCabecalhoPacote(_httpPacote.HttpContext.Request.Protocol, (HttpStatusCode)httpResponse.StatusCode, httpResponse.Headers);
            }

            return "";
        }

        private void SetDataAvailable()
        {
            DataAvailable = _buffer.Length != 0 ? (int)(_buffer.Length - _bufferInicio) : _clientStream.Socket.Available;
            if (BaseStream is SslStream)
            {
                if (_httpPacote.Headers.ContentLength != null) { DataAvailable = (int)_httpPacote.Headers.ContentLength; }
                else { DataAvailable *= 3; }
            }
        }

        public override void Flush()
        {
            _buffer?.Flush();
            BaseStream.Flush();
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

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count).Result;

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            int read = 0;
            int totalRead = 0;
            bool bufferNovo = _buffer.Length == 0;

            if (bufferNovo) { SetDataAvailable(); }

            var internalBuffer = bufferNovo ? new byte[Configuracao.MAX_BUFFER_SSL] : buffer;
            CancellationTokenSource? cts = null;
            try
            {
                do
                {
                    if (bufferNovo)
                    {
                        if (_clientStream.Socket.Poll(0, SelectMode.SelectRead)) { read = await BaseStream.ReadAsync(internalBuffer, cts?.Token ?? cancellationToken); }
                        if (read == 0)
                        {
                            cts ??= CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, new CancellationTokenSource(TimeSpan.FromSeconds(_httpPacote.Timeout)).Token);
                            await Task.Delay(1, cts.Token);
                            continue;
                        }
                        cts?.Dispose();
                        cts = null;
                        await _buffer.WriteAsync(internalBuffer.AsMemory(0, read), cancellationToken);
                    }
                    else { read = await _buffer.ReadAsync(buffer, cancellationToken); }
                    totalRead += read;
                    if (totalRead < buffer.Length && read > 0) { await Task.Delay(1, cancellationToken); }
                } while (totalRead < buffer.Length && read > 0);
            }
            catch (Exception ex) when (ex.Contains([typeof(OperationCanceledException), typeof(TaskCanceledException)])) { }

            if (bufferNovo) { _buffer.Seek(0, SeekOrigin.Begin); }
            if (totalRead > buffer.Length) { totalRead = buffer.Length; }
            if (internalBuffer != buffer) { await _buffer.ReadAsync(buffer, cancellationToken); }
            if (!CanSeek) { _bufferInicio = (int)_buffer.Position; }
            SetDataAvailable();

            return totalRead;
        }

        public override long Seek(long offset, SeekOrigin origin) => _buffer?.Seek(_bufferInicio + offset, origin) ?? 0;

        public override void SetLength(long value) => _buffer?.SetLength(_bufferInicio + value);

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count).Wait();

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            var cabecalho = MontarCabecalho();
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, new CancellationTokenSource(TimeSpan.FromSeconds(_httpPacote.Timeout)).Token);
            _clientStream.Socket.Poll(0, SelectMode.SelectWrite);
            if (!string.IsNullOrEmpty(cabecalho)) { await BaseStream.WriteAsync(Encoding.UTF8.GetBytes(cabecalho), cts.Token); }

            await BaseStream.WriteAsync(buffer, cts.Token);
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
