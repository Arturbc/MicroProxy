using MicroProxy.Extensions;
using MicroProxy.Helpers;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
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
            : this(stream, clientStream, null, cancellationToken) { }
        public HttpContextFromListener(Stream stream, NetworkStream clientStream, string? codec, CancellationToken cancellationToken = default)
        {
            Request = new(stream, clientStream, this);
            Response = new(stream, clientStream, this, codec);
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
        internal HttpRequestFromListener(Stream stream, NetworkStream clientStream, HttpContextFromListener context) : base(context)
        {
            string[] methodsSemBody = [HttpMethods.Head, HttpMethods.Get, HttpMethods.Connect, HttpMethods.Delete, HttpMethods.Trace];
            using var body = new BodyStream(stream, clientStream, this, true, false);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(new CancellationTokenSource(100).Token, context.RequestAborted);
            string[] req = LerCabecalhoPacote(body, Headers, cts.Token);
            uri = new(req[1].Contains("://") || req[1].StartsWith('/') ? req[1] : "http://" + req[1], UriKind.RelativeOrAbsolute);
            Method = req[0];
            Path = uri.IsAbsoluteUri ? uri.AbsolutePath : uri.OriginalString;
            QueryString = new QueryString(uri.IsAbsoluteUri ? uri.Query : (uri.OriginalString.Contains('?') ? '?' + uri.OriginalString.Split('?')[1] : null));
            Protocol = req[2];
            Body = body.AtualizarBody(!methodsSemBody.Contains(Method), false);
        }

        private readonly Uri uri;
        public string Protocol { get; private set; } = null!;
        public PathString Path { get; private set; }
        public QueryString QueryString { get; private set; }
        public string Method { get; private set; } = null!;
        public bool IsHttps => Body.BaseStream is SslStream;

        public void EnableBuffering() { if (!Body.CanSeek) { using var body = Body; Body = body.AtualizarBody(true, false, true); } }

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
        internal HttpResponseFromListener(Stream stream, NetworkStream clientStream, HttpContextFromListener context, bool clonarContext = false)
            : this(stream, clientStream, context, null, clonarContext) { }
        internal HttpResponseFromListener(Stream stream, NetworkStream clientStream, HttpContextFromListener context, string? codec, bool clonarContext = false) : base(context)
        {
            if (clonarContext)
            {
                using var body = new BodyStream(stream, clientStream, this, true, !HttpMethods.IsHead(context.Request.Method));
                Timeout = context.Response.Timeout;
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(new CancellationTokenSource(100).Token, context.RequestAborted);
                string[] resp = LerCabecalhoPacote(body, Headers, cts.Token);
                StatusCode = int.Parse(resp[1]);
                Body = body.AtualizarBody(true, !HttpMethods.IsHead(context.Request.Method));
                _codec = codec ?? Headers.ContentEncoding.ToString() ?? context.Response._codec;
            }
            else
            {
                Body = new(stream, clientStream, this, false, !HttpMethods.IsHead(HttpContext.Request.Method));
                StatusCode = (int)HttpStatusCode.OK;
                _codec = codec;
            }
        }
        private readonly string? _codec;
        public int StatusCode { get; set; }
        public bool HasStarted { get; protected set; }
        public StringValues ContentType { get => Headers.ContentType; set => Headers.ContentType = value; }
        public long? ContentLength { get => Headers.ContentLength; set => Headers.ContentLength = value; }

        public void Redirect(string location, bool permanent = false)
        {
            Headers.Location = location;
            StatusCode = (int)(permanent ? HttpStatusCode.PermanentRedirect : HttpStatusCode.Redirect);
        }

        public async Task WriteAsync(string entrada, CancellationToken cancellationToken)
        {
            var buffer = Encoding.UTF8.GetBytes(entrada);

            if (Headers.ContentEncoding.Count == 0)
            {
                using var memoria = new MemoryStream(buffer);
                using var pacote = (MemoryStream)ProcessarCodificacao(memoria);
                buffer = pacote.ToArray();
            }

            if (Headers.ContentLength == null) { Headers.ContentLength = buffer.Length; }
            await Body.WriteAsync(buffer, cancellationToken);
        }

        private Stream ProcessarCodificacao(Stream stream)
        {
            var partesCodec = _codec?.Split(',', StringSplitOptions.TrimEntries);
            var acceptedEncodings = HttpContext.Request.Headers.AcceptEncoding.ToString();

            if (partesCodec != null && partesCodec.Length > 0 && acceptedEncodings.Contains(partesCodec[0], StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    stream = stream.Compactar(out var codec, ContentType, partesCodec[0], (CompressionLevel)(partesCodec.Length > 1 ? int.Parse(partesCodec[1]) : 0));
                    Headers.ContentEncoding = codec;
                }
                catch { }
            }

            return stream;
        }

        public async Task SendFileAsync(IFileInfo fileInfo, CancellationToken cancellationToken)
        {
            var stream = fileInfo.CreateReadStream();

            if (Headers.ContentEncoding.Count == 0)
            {
                stream = ProcessarCodificacao(stream);
            }
            using var streamEmUso = stream;
            ContentLength = streamEmUso.Length;
            await streamEmUso.CopyToAsync(Body, cancellationToken);
        }

        public async Task<string?> SendFileAsync(string? pathDiretorio, string? pathArquivo, CancellationToken cancellationToken = default)
        {
            if (!string.IsNullOrEmpty(pathDiretorio) && !string.IsNullOrEmpty(pathArquivo))
            {
                var pathArquivoUsado = pathArquivo;
                var partesCodec = _codec?.Split(',', StringSplitOptions.TrimEntries);
                var acceptedEncodings = HttpContext.Request.Headers.AcceptEncoding.ToString();

                if (partesCodec != null && partesCodec.Length > 0 && acceptedEncodings.Contains(partesCodec[0], StringComparison.OrdinalIgnoreCase))
                {
                    var pathArquivoCod = Directory.GetFiles(pathDiretorio, pathArquivo + ".*", SearchOption.TopDirectoryOnly)
                        .FirstOrDefault(a => partesCodec[0].StartsWith(Path.GetExtension(a).TrimStart('.'), StringComparison.OrdinalIgnoreCase));

                    if (pathArquivoCod != null)
                    {
                        var codec = acceptedEncodings.Split(',', StringSplitOptions.TrimEntries)
                            .FirstOrDefault(s => s.Contains(partesCodec[0], StringComparison.OrdinalIgnoreCase));

                        if (codec != null)
                        {
                            pathArquivoUsado = Path.GetFileName(pathArquivoCod);
                            Headers.ContentEncoding = acceptedEncodings.Split(',', StringSplitOptions.TrimEntries)
                                .FirstOrDefault(s => s.Contains(partesCodec[0], StringComparison.OrdinalIgnoreCase));
                        }
                    }
                }

                using var pfp = new PhysicalFileProvider(pathDiretorio);
                var arquivo = pfp.GetFileInfo(pathArquivoUsado);
                var provedor = new FileExtensionContentTypeProvider();
                if (provedor.TryGetContentType(pathArquivo, out string? tipoConteudo)) { ContentType = tipoConteudo; }
                await using var conteudoResposta = arquivo.CreateReadStream();
                await SendFileAsync(arquivo, cancellationToken);
                var resultado = await conteudoResposta.BodyAsStringAsync(tipoConteudo, Headers.ContentEncoding, cancellationToken);

                return resultado;
            }

            return null;
        }

        public async Task CompleteAsync()
        {
            var cabecalho = Body.MontarCabecalho();
            HasStarted = true;
            if (!string.IsNullOrEmpty(cabecalho)) { await Body.BaseStream.WriteAsync(Encoding.UTF8.GetBytes(cabecalho), default); }
            await Body.FlushAsync(HttpContext.RequestAborted);
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
        }

        private bool disposedValue;
        private int _bufferInicio;
        private bool _checkedState = false;
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
        public bool DataAvailable => _clientStream.DataAvailable || _buffer.Length > _buffer.Position;

        internal BodyStream AtualizarBody(bool read = true, bool write = true, bool canSeek = false)
        {
            var novoBuffer = new MemoryStream();
            _buffer.CopyTo(novoBuffer);
            _buffer.Dispose();
            novoBuffer.Seek(0, SeekOrigin.Begin);
            return new(BaseStream, _clientStream, _httpPacote, read, write, canSeek, novoBuffer);
        }

        internal string MontarCabecalho()
        {
            if (_httpPacote is HttpResponseFromListener httpResponse && !httpResponse.HasStarted)
            {
                httpResponse.GetType().GetProperty(nameof(httpResponse.HasStarted))!.SetValue(httpResponse, true);
                return _checkedState ? MontarHeadersCabecalhoPacote(httpResponse.Headers) + "\r\n"
                    : MontarCabecalhoPacote(_httpPacote.HttpContext.Request.Protocol, (HttpStatusCode)httpResponse.StatusCode, httpResponse.Headers);
            }

            return "";
        }

        public async Task<bool> CheckStateAsync()
        {
            try
            {
                if (!DataAvailable && _httpPacote is HttpResponseFromListener httpResponse && !httpResponse.HasStarted)
                {
                    using var cts = new CancellationTokenSource(100);
                    if (!_checkedState)
                    {
                        _checkedState = true;
                        var cabecalho = MontarInicioCabecalhoPacote(_httpPacote.HttpContext.Request.Protocol, (HttpStatusCode)httpResponse.StatusCode);
                        await WriteAsync(Encoding.UTF8.GetBytes(cabecalho), cts.Token);
                    }
                    await WriteAsync(new byte[] { 0x01 }, cts.Token);
                }
            }
            catch (Exception ex) when (ex.Contains([typeof(IOException), typeof(OperationCanceledException), typeof(TaskCanceledException)])) { return false; }
            return true;
        }

        public override void Flush()
        {
            _buffer?.Flush();
            BaseStream.Flush();
        }

        public override void CopyTo(Stream destination, int bufferSize = 1) => CopyToAsync(destination, bufferSize).Wait();

        public override async Task CopyToAsync(Stream destination, int bufferSize = 1, CancellationToken cancellationToken = default)
        {
            var buffer = new byte[bufferSize];
            int read = await ReadAsync(buffer, cancellationToken);

            if (read != 0) { await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken); }
        }

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer, offset, count).Result;

        public override async Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            int totalRead = 0;
            bool bufferNovo = _buffer.Length == _buffer.Position;
            bool loopAtivo;
            var internalBuffer = new byte[_clientStream.Socket.ReceiveBufferSize];
            int posicaoAtualBuffer = (int)_buffer.Position;
            CancellationTokenSource? cts = null;

            try
            {
                do
                {
                    int read = 0;
                    var ct = cts?.Token ?? cancellationToken;
                    var parteBuffer = internalBuffer.AsMemory(offset + totalRead, count - totalRead);

                    if (bufferNovo)
                    {
                        _buffer.Seek(_buffer.Length, SeekOrigin.Begin);
                        try
                        {
                            if (_clientStream.Socket.Poll(0, SelectMode.SelectRead) || BaseStream is SslStream)
                            {
                                using var ctsRead = new CancellationTokenSource(200);
                                using var ctsReadLink = CancellationTokenSource.CreateLinkedTokenSource(ctsRead.Token, ct);
                                read = await BaseStream.ReadAsync(parteBuffer, ctsReadLink.Token);
                            }
                            if (read != 0) { await _buffer.WriteAsync(parteBuffer[..read], cancellationToken); posicaoAtualBuffer += read; }
                        }
                        catch (Exception ex) when (ex.Contains([typeof(OperationCanceledException), typeof(TaskCanceledException)]))
                        { if (ct.IsCancellationRequested) { throw new Exception("Ação cancelada...", ex); } else { await Task.Delay(1, ct); } }
                    }
                    else { read = await _buffer.ReadAsync(parteBuffer, cancellationToken); posicaoAtualBuffer = (int)_buffer.Position; }
                    totalRead += read;
                    loopAtivo = totalRead < count && (totalRead == 0 || read > 0) && (bufferNovo || _buffer.Position < _buffer.Length);

                    if (read == 0)
                    {
                        if (_clientStream.Socket.Connected)
                        {
                            bufferNovo = true;
                            cts ??= CancellationTokenSource.CreateLinkedTokenSource(cancellationToken,
                                new CancellationTokenSource(_buffer.Length == 0 ? _httpPacote.Timeout * 1000 : 200).Token);
                            await Task.Delay(1, cts.Token);
                            continue;
                        }
                        else { loopAtivo = false; }
                    }

                    cts?.Dispose();
                    cts = null;
                } while (loopAtivo);
            }
            catch (Exception ex) when (ex.Contains([typeof(OperationCanceledException), typeof(TaskCanceledException)])) { cts?.Dispose(); }

            var fimBuffer = totalRead + offset;
            _buffer.Seek(posicaoAtualBuffer, SeekOrigin.Begin);
            Array.Copy(internalBuffer, buffer, fimBuffer);
            if (!CanSeek)
            {
                if (_buffer.Position == _buffer.Length)
                {
                    _buffer.Seek(0, SeekOrigin.Begin);
                    _buffer.SetLength(0);
                }
                _bufferInicio = (int)_buffer.Position;
            }

            return totalRead;
        }

        public override long Seek(long offset, SeekOrigin origin) => _buffer?.Seek(_bufferInicio + offset, origin) ?? 0;

        public override void SetLength(long value) => _buffer?.SetLength(_bufferInicio + value);

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer, offset, count).Wait();

        public override async Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken = default)
        {
            var cabecalho = MontarCabecalho();
            if (!string.IsNullOrEmpty(cabecalho)) { await _buffer.WriteAsync(Encoding.UTF8.GetBytes(cabecalho), cancellationToken); }
            await _buffer.WriteAsync(buffer.AsMemory(offset, count), cancellationToken);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, new CancellationTokenSource(200).Token);
            _clientStream.Socket.Poll(0, SelectMode.SelectWrite);
            await BaseStream.WriteAsync(_buffer.ToArray().AsMemory(0, (int)_buffer.Position), cts.Token);
            _buffer.Seek(0, SeekOrigin.Begin);
            _buffer.SetLength(0);
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
