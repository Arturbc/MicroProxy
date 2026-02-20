using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MicroProxy.Models
{
    public class HttpContextFromListener
    {
        public HttpContextFromListener(Stream stream)
        {
            Request = new(stream, this);
            Response = new(stream, this);
            RequestAborted = cancellationTokenSource.Token;
        }

        private readonly CancellationTokenSource cancellationTokenSource = new();
        public HttpRequestFromListener Request { get; }
        public HttpResponseFromListener Response { get; }
        public CancellationToken RequestAborted { get; set; }
        public ConnectionInfoFromListener Connection { get; } = new();
    }

    public class ConnectionInfoFromListener
    {
        public X509Certificate2? ClientCertificate { get; }
    }

    public abstract class HttpPacoteFromListener(HttpContextFromListener context)
    {
        public HttpContextFromListener HttpContext { get; } = context;
        public IHeaderDictionary Headers { get; } = new HeaderDictionary();
        public Stream Body { get; set; } = null!;
    }

    public class HttpRequestFromListener : HttpPacoteFromListener
    {
        internal HttpRequestFromListener(Stream stream, HttpContextFromListener context) : base(context)
        {
            StreamReader reader = new(stream);
            var req = reader.ReadLine()!.Split(' ');
            string[] header;

            uri = new(req[1], UriKind.RelativeOrAbsolute);
            Method = req[0];
            Path = uri.AbsolutePath;
            QueryString = new QueryString(uri.Query);
            Protocol = req[2];

            do
            {
                header = reader.ReadLine()?.Split(": ") ?? [];
                if (header.Length > 1) { Headers.Append(header[0], header[1]); }
            } while (header.Length > 1);

            Body = stream;
        }

        private readonly Uri uri;
        public string Protocol { get; private set; } = null!;
        public PathString Path { get; private set; }
        public QueryString QueryString { get; private set; }
        public string Method { get; private set; } = null!;
        public bool IsHttps => Body is SslStream;

        public void EnableBuffering()
        {
            var memoria = new MemoryStream();

            Body.CopyTo(memoria);
            memoria.Flush();
            if (Body is MemoryStream) { Body.Dispose(); } else { Body.Flush(); }
            Body = memoria;
            Body.Seek(0, SeekOrigin.Begin);
        }

        public string GetDisplayUrl()
        {
            if (uri.IsAbsoluteUri) { return uri.AbsoluteUri; }

            StringBuilder stringBuilder = new();

            stringBuilder.Append("http://");

            if (IsHttps) { stringBuilder.Insert(4, 's'); }

            stringBuilder.Append(string.IsNullOrEmpty(Headers.Host) ? "localhost" : Headers.Host);
            stringBuilder.Append(uri.PathAndQuery);

            return stringBuilder.ToString();
        }

        public string GetEncodedPathAndQuery() => GetDisplayUrl();
    }

    public class HttpResponseFromListener : HttpPacoteFromListener
    {
        internal HttpResponseFromListener(Stream stream, HttpContextFromListener context) : base(context)
        {
            Body = stream;
            tamInicialStream = Body.Length;
        }

        private readonly long tamInicialStream;
        public int StatusCode { get; set; } = (int)HttpStatusCode.OK;
        public bool HasStarted => Body.Length > tamInicialStream;
        public StringValues ContentType { get => Headers.ContentType; set => Headers.ContentType = value; }
        public long? ContentLength { get => Headers.ContentLength; set => Headers.ContentLength = value; }

        public void Redirect(string url)
        {
            Headers.Location = url;
            StatusCode = (int)HttpStatusCode.Redirect;
        }

        public async Task WriteAsync(string entrada, CancellationToken cancellationToken) => await Body.WriteAsync(Encoding.UTF8.GetBytes(entrada), cancellationToken);

        public async Task SendFileAsync(IFileInfo fileInfo, CancellationToken cancellationToken)
        {
            using var stream = fileInfo.CreateReadStream();

            await stream.CopyToAsync(Body, cancellationToken);
            await Body.FlushAsync(cancellationToken);
        }

        public async Task CompleteAsync()
        {

        }
    }
}
