using MicroProxy.Extensions;
using MicroProxy.Helpers;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using static MicroProxy.Helpers.HttpHelper;

namespace MicroProxy.Models
{
    public interface IHttpContextFromListenerAccessor
    {
        HttpContextFromListener? HttpContext { get; set; }
    }

    [DebuggerNonUserCode]
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

    [DebuggerNonUserCode]
    public class HttpContextFromListener : IDisposable
    {
        public HttpContextFromListener(Stream stream, NetworkStream clientStream, CancellationToken cancellationToken = default)
            : this(stream, clientStream, null, null, cancellationToken) { }

        public HttpContextFromListener(Stream stream, NetworkStream clientStream, SessionOptions? sessionOptions, IDataProtector? protector,
            CancellationToken cancellationToken = default) : this(stream, clientStream, sessionOptions, protector, null, cancellationToken) { }

        public HttpContextFromListener(Stream stream, NetworkStream clientStream, SessionOptions? sessionOptions, IDataProtector? protector, string? codec,
            CancellationToken cancellationToken = default)
        {
            Request = new(stream, clientStream, this);
            Response = new(stream, clientStream, this, codec);
            Connection = new(clientStream.Socket, stream is SslStream ssl && ssl.RemoteCertificate != null ? new X509Certificate2(ssl.RemoteCertificate) : null);
            RequestAborted = cancellationToken;

            if (sessionOptions != null)
            {
                var clientCookies = ParseCookies(Request.Headers.Cookie);
                Request.Headers.Cookie = FiltrarCookie(sessionOptions.Cookie.Name);
                var sessionCookie = clientCookies!.GetValueOrDefault(sessionOptions.Cookie.Name)?.Split('-');
                var sessionId = sessionCookie?[0] ?? GenerateSessionId();
                Session = new SessionFromListener(protector ?? throw new InvalidOperationException(), sessionId, sessionCookie?[1], sessionOptions, this);
            }
        }

        private bool disposedValue;
        public ISession? Session { get; }
        public HttpRequestFromListener Request { get; }
        public HttpResponseFromListener Response { get; }
        public CancellationToken RequestAborted { get; set; }
        public ConnectionInfoFromListener Connection { get; }

        private StringValues FiltrarCookie(string? nome)
        {
            if (string.IsNullOrEmpty(nome) || string.IsNullOrEmpty(Request.Headers.Cookie)) { return Request.Headers.Cookie; }
            return new Regex($"(?<=(?:^|(?:; *))){nome}[^;]+(?:(?:; *)|(?: *$))").Replace(Request.Headers.Cookie!, "");
        }

        private static Dictionary<string, string> ParseCookies(string? cookieHeader)
        {
            var cookies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (string.IsNullOrEmpty(cookieHeader?.Trim())) { return cookies; }

            foreach (var pair in cookieHeader.Split(';', StringSplitOptions.TrimEntries))
            {
                var eqIndex = pair.IndexOf('=');

                if (eqIndex > 0)
                {
                    var key = pair[..eqIndex].Trim();
                    var value = pair[(eqIndex + 1)..].Trim().Trim('"');

                    if (!string.IsNullOrEmpty(key)) { cookies[key] = Uri.UnescapeDataString(value); }
                }
            }

            return cookies;
        }

        private static string GenerateSessionId()
        {
            var randomBytes = RandomNumberGenerator.GetBytes(16);
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var data = BitConverter.GetBytes(timestamp).Concat(randomBytes).ToArray();
            var sessionId = Convert.ToBase64String(data);

            return sessionId;
        }

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

    [DebuggerNonUserCode]
    public class ConnectionInfoFromListener(Socket socket, X509Certificate2? certificado = null)
    {
        public X509Certificate2? ClientCertificate { get; } = certificado;
        public IPAddress LocalIpAddress { get; } = ((IPEndPoint)socket.LocalEndPoint!).Address;
        public IPAddress RemoteIpAddress { get; } = ((IPEndPoint)socket.RemoteEndPoint!).Address;
    }

    [DebuggerNonUserCode]
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

    [DebuggerNonUserCode]
    public class HttpRequestFromListener : HttpPacoteFromListener
    {
        internal HttpRequestFromListener(Stream stream, NetworkStream clientStream, HttpContextFromListener context) : base(context)
        {
            try
            {
                if (stream is not NetworkStream && stream is not SslStream) { throw new ArgumentException("O parâmetro é de tipo não suportado.", nameof(stream)); }
                string[] methodsSemBody = [HttpMethods.Head, HttpMethods.Get, HttpMethods.Connect, HttpMethods.Delete, HttpMethods.Trace];
                using var body = new BodyStream(stream, clientStream, this, true, false);
                var req = LerCabecalhoPacote(body, Headers, context.RequestAborted);
                uri = new(req[1].Contains("://") || req[1].StartsWith('/') ? req[1] : "http://" + req[1], UriKind.RelativeOrAbsolute);
                var splitPath = uri.OriginalString.Contains('?') ? uri.OriginalString.Split('?') : null;
                Method = req[0];
                Path = uri.IsAbsoluteUri ? uri.AbsolutePath : splitPath?[0] ?? uri.OriginalString;
                QueryString = new QueryString(uri.IsAbsoluteUri ? uri.Query : (splitPath != null ? '?' + splitPath[1] : null));
                Protocol = req[2];
                Body = body.AtualizarBody(!methodsSemBody.Contains(Method), false, false);
            }
            catch (Exception ex) { clientStream.Dispose(); throw new("Falha ao carregar cabeçalho da requisição", ex); }
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

    [DebuggerNonUserCode]
    public class HttpResponseFromListener : HttpPacoteFromListener
    {
        internal HttpResponseFromListener(Stream stream, NetworkStream clientStream, HttpContextFromListener context, bool clonarContext = false)
            : this(stream, clientStream, context, null, clonarContext) { }

        internal HttpResponseFromListener(Stream stream, NetworkStream clientStream, HttpContextFromListener context, string? codec, bool clonarContext = false) : base(context)
        {
            try
            {
                if (stream is not NetworkStream && stream is not SslStream) { throw new ArgumentException("O parâmetro é de tipo não suportado.", nameof(stream)); }
                _clientStream = clientStream;
                if (clonarContext)
                {
                    using var body = new BodyStream(stream, clientStream, this, true, false);
                    Timeout = context.Response.Timeout;
                    var resp = LerCabecalhoPacote(body, Headers, context.RequestAborted);
                    StatusCode = int.Parse(resp[1]);
                    Body = body.AtualizarBody(true, !HttpMethods.IsHead(context.Request.Method));
                    _codec = codec ?? Headers.ContentEncoding.ToString() ?? context.Response._codec;
                }
                else
                {
                    Body = new(stream, clientStream, this, false, !HttpMethods.IsHead(HttpContext.Request.Method));
                    StatusCode = StatusCodes.Status200OK;
                    _codec = codec;
                }
            }
            catch (Exception ex) { clientStream.Dispose(); throw new("Falha ao carregar cabeçalho da resposta", ex); }
        }
        private readonly string? _codec;
        private readonly NetworkStream _clientStream;
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

        public async Task<Stream> SendFileAsync(IFileInfo fileInfo, CancellationToken cancellationToken)
        {
            var stream = fileInfo.CreateReadStream();

            if (Headers.ContentEncoding.Count == 0) { stream = ProcessarCodificacao(stream); }
            ContentLength = stream.Length;
            await stream.CopyToAsync(Body, cancellationToken);
            stream.Seek(0, SeekOrigin.Begin);
            return stream;
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
                using var conteudoResposta = await SendFileAsync(arquivo, cancellationToken);
                return await conteudoResposta.BodyAsStringAsync(tipoConteudo, Headers.ContentEncoding, cancellationToken);
            }

            return null;
        }

        public async Task CompleteAsync()
        {
            try
            {
                var cabecalho = Body.MontarCabecalho();
                if (!string.IsNullOrEmpty(cabecalho)) { await Body.BaseStream.WriteAsync(Encoding.UTF8.GetBytes(cabecalho), HttpContext.RequestAborted); }
                try { await Body.FlushAsync(); } catch { }
            }
            catch { }
        }

        public async Task CompleteAsync(TcpClient tcpClient)
        {
            try
            {
                if (tcpClient.Client != _clientStream.Socket) { throw new ArgumentException("O parâmetro não pertence ao contexto...", nameof(tcpClient)); }
                if (!ConnectionPool.IsAlive(tcpClient)) { await _clientStream.DisposeAsync(); }
                else { ConnectionPool.SaveConnection(tcpClient); }
            }
            catch { }
        }
    }

    [DebuggerNonUserCode]
    [SuppressMessage("Performance", "CA1844:Fornecer substituições baseadas em memória de métodos assíncronos ao subclasse 'Stream'", Justification = "Sem necessidade")]
    public class BodyStream : Stream, IDisposable
    {
        internal BodyStream(Stream stream, NetworkStream clientStream, HttpPacoteFromListener httpPacote, bool read = true, bool write = true, bool canSeek = false, MemoryStream? buffer = null)
        {
            BaseStream = stream is NetworkStream || stream is SslStream ? stream : throw new ArgumentException("Parâmetro to tipo inválido", nameof(stream));
            CanRead = read;
            CanWrite = write;
            CanSeek = canSeek;
            _httpPacote = httpPacote;
            _clientStream = clientStream;
            _buffer = buffer ?? new();
            _bufferInicio = (int)_buffer.Position;
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
        public bool DataAvailable => _clientStream.DataAvailable || _buffer.Length > _buffer.Position;

        internal BodyStream AtualizarBody(bool? canRead = null, bool? canWrite = null, bool? canSeek = null)
        {
            var novoBuffer = new MemoryStream();
            _buffer.CopyTo(novoBuffer);
            _buffer.Dispose();
            novoBuffer.Seek(0, SeekOrigin.Begin);
            return new(BaseStream, _clientStream, _httpPacote, canRead ?? CanRead, canWrite ?? CanWrite, canSeek ?? CanSeek, novoBuffer);
        }

        internal string MontarCabecalho()
        {
            if (_httpPacote is HttpResponseFromListener httpResponse && !httpResponse.HasStarted)
            {
                httpResponse.GetType().GetProperty(nameof(httpResponse.HasStarted))!.SetValue(httpResponse, true);
                httpResponse.HttpContext.Session?.CommitAsync(httpResponse.HttpContext.RequestAborted).Wait();
                return MontarCabecalhoPacote(_httpPacote.HttpContext.Request.Protocol, (HttpStatusCode)httpResponse.StatusCode, httpResponse.Headers);
            }

            return "";
        }

        public override void Flush() { _buffer?.Flush(); BaseStream.Flush(); }

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
            var totalRead = 0;
            var disponivelBuffer = _buffer.Length - _buffer.Position;
            var bufferNovo = disponivelBuffer == 0;
            var tamInternalBuffer = count + offset;

            if (tamInternalBuffer > disponivelBuffer)
            { tamInternalBuffer = Math.Max(_clientStream.Socket.ReceiveBufferSize, tamInternalBuffer) + (int)disponivelBuffer; }

            var internalBuffer = new byte[tamInternalBuffer].AsMemory();
            var posicaoAtualBuffer = (int)_buffer.Position;
            var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, new CancellationTokenSource(TimeSpan.FromSeconds(_httpPacote.Timeout)).Token);
            bool loopAtivo;

            try
            {
                do
                {
                    var inicioParteBuffer = offset + totalRead;
                    var parteBuffer = internalBuffer[inicioParteBuffer..];
                    var read = 0;
                    var ct = cts?.Token ?? cancellationToken;

                    if (bufferNovo)
                    {
                        _buffer.Seek(_buffer.Length, SeekOrigin.Begin);
                        try
                        {
                            using var ctsLink = CancellationTokenSource.CreateLinkedTokenSource(ct, new CancellationTokenSource(1).Token);
                            read = await BaseStream.ReadAsync(parteBuffer, ctsLink.Token);
                            if (read != 0)
                            {
                                await _buffer.WriteAsync(parteBuffer[..read], cancellationToken); posicaoAtualBuffer += read;
                                cts?.Dispose();
                                cts = null;
                            }
                        }
                        catch (Exception ex) when (ex.Contains([typeof(OperationCanceledException), typeof(TaskCanceledException)]))
                        { if (ct.IsCancellationRequested) { throw new Exception("Ação cancelada...", ex); } }

                        if (read == 0) { if (cancellationToken.IsCancellationRequested || _buffer.Length > 0) { break; } }
                    }
                    else
                    {
                        read = await _buffer.ReadAsync(parteBuffer, cancellationToken); posicaoAtualBuffer = (int)_buffer.Position;
                        if (_buffer.Position == _buffer.Length && _clientStream.DataAvailable) { bufferNovo = true; }
                    }

                    totalRead += read;
                    loopAtivo = bufferNovo && ((read > 0 && totalRead < count) || totalRead == 0)
                        && _clientStream.Socket.Connected && !_clientStream.Socket.Poll(1, SelectMode.SelectError)
                        && (!_clientStream.Socket.Poll(1, SelectMode.SelectRead) || _clientStream.DataAvailable);
                } while (loopAtivo);
            }
            catch (Exception ex) when (ex.Contains([typeof(OperationCanceledException), typeof(TaskCanceledException)]))
            {
                if (cts == null) { throw new("Tarefa cancelada", ex); }
                else if (cts.IsCancellationRequested)
                { cts.Dispose(); throw new TimeoutException("O tempo máximo de espera foi atingido!"); }
            }

            cts?.Dispose();
            var indexChunk = internalBuffer[1..].ToArray().IndexOf((byte)'\r');
            var chunk = -1;

            if (indexChunk != -1)
            {
                indexChunk += 3;
                var byteString = Encoding.UTF8.GetString(internalBuffer[..indexChunk].ToArray());
                var hexString = byteString.Trim(['\r', '\n', ' ']);
                try { chunk = Convert.ToInt32(hexString, 16); }
                catch { indexChunk = 0; }
            }
            else { indexChunk = 0; }

            if (chunk > count || chunk == -1) { chunk = count; }

            if (totalRead > chunk)
            {
                posicaoAtualBuffer -= totalRead - chunk - indexChunk;
                totalRead = chunk;
            }

            if ((totalRead + indexChunk) > count)
            {
                var diff = totalRead + indexChunk - count;

                posicaoAtualBuffer -= diff;
                totalRead -= diff;
            }

            _buffer.Seek(posicaoAtualBuffer, SeekOrigin.Begin);
            internalBuffer.Slice(indexChunk + offset, totalRead).CopyTo(buffer.AsMemory(offset));
            //Console.WriteLine($"\"{Encoding.UTF8.GetString(buffer.AsMemory(offset, chunk).ToArray()).Replace("\n", "\\n\n").Replace("\r", "\\r")}\"");
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
            if (_clientStream.Socket.Poll(1, SelectMode.SelectWrite)) { await BaseStream.WriteAsync(_buffer.ToArray().AsMemory(0, (int)_buffer.Position), cancellationToken); }
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

    [DebuggerNonUserCode]
    public class SessionFromListener : ISession
    {
        public SessionFromListener(IDataProtector protector, string sessionId, string? cookieValue, SessionOptions sessionOptions, HttpContextFromListener context)
        {
            _protector = protector;
            _sessionId = sessionId;
            _cookieValue = cookieValue;
            _sessionOptions = sessionOptions;
            _context = context;
            LoadAsync().Wait();
        }

        private readonly Dictionary<string, byte[]> _store = [];
        private readonly IDataProtector _protector;
        private readonly string _sessionId;
        private readonly string? _cookieValue;
        private readonly SessionOptions _sessionOptions;
        private readonly HttpContextFromListener _context;
        public bool IsAvailable => _sessionId != null;
        public string Id => _sessionId;
        public IEnumerable<string> Keys => _store.Keys;

        public void Clear() => _store.Clear();

        public Task CommitAsync(CancellationToken cancellationToken = default)
        {
            var json = JsonConvert.SerializeObject(_store);
            var jsonBytes = Encoding.UTF8.GetBytes(json);
            var protectedData = _protector.Protect(jsonBytes);
            var cookieValue = $"{_sessionOptions.Cookie.Name}={_sessionId}-{Convert.ToBase64String(protectedData)}";

            _context.Response.Headers.SetCookie = new StringValues([.. _context.Response.Headers.SetCookie.Append($"{cookieValue}; " +
                (_sessionOptions.IdleTimeout == TimeSpan.MaxValue ? "" : $"Max-Age={(int)_sessionOptions.IdleTimeout.TotalSeconds}; " +
                    $"Expires={DateTimeOffset.UtcNow.Add(_sessionOptions.IdleTimeout):ddd, dd MMM yyyy HH:mm:ss GMT}; ") + $"Path=/; HttpOnly; SameSite=Lax" +
                (_sessionOptions.Cookie.SecurePolicy == CookieSecurePolicy.Always ? "; Secure" : ""))]);

            return Task.CompletedTask;
        }

        public Task LoadAsync(CancellationToken cancellationToken = default)
        {
            if (!string.IsNullOrEmpty(_cookieValue))
            {
                try
                {
                    var protectedData = Convert.FromBase64String(_cookieValue);
                    var jsonBytes = _protector.Unprotect(protectedData);
                    var json = Encoding.UTF8.GetString(jsonBytes);
                    var store = JsonConvert.DeserializeObject<Dictionary<string, byte[]>>(json) ?? [];

                    foreach (var item in store) { if (!_store.TryAdd(item.Key, item.Value)) { _store[item.Key] = item.Value; } }
                }
                catch { }
            }

            return Task.CompletedTask;
        }

        public void Remove(string key) => _store.Remove(key);

        public void Set(string key, byte[] value) { if (!_store.TryAdd(key, value)) { _store[key] = value; } }

        public bool TryGetValue(string key, [NotNullWhen(true)] out byte[]? value) => _store.TryGetValue(key, out value);
    }
}
