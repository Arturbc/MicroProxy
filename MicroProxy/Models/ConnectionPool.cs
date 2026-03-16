using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace MicroProxy.Models
{
    public static class ConnectionPool
    {
        static readonly ConcurrentDictionary<string, ConcurrentQueue<TcpClient>> _pools = [];
        static readonly ConcurrentDictionary<string, List<Task>> _tarefas = [];

        public static Task<TcpClient> GetConnectionAsync(string host, int port, CancellationToken cancel = default)
            => GetConnectionAsync(host, port, 1, cancel);

        public static async Task<TcpClient> GetConnectionAsync(string host, int port, int tamPool = 1, CancellationToken cancel = default)
        {
            var detalhesHost = await Dns.GetHostEntryAsync(host, cancel);
            var iPs = detalhesHost?.AddressList ?? [];
            string? conexao = _pools.Keys.FirstOrDefault(p => iPs.Any(i => p.Split(':').Contains(i.ToString())));

            if (conexao != null)
            {
                var pool = _pools.GetOrAdd(conexao, _ => new ConcurrentQueue<TcpClient>());

                while (!pool.IsEmpty)
                {
                    if (pool.TryDequeue(out var tcp) && tcp.Connected && IsAlive(tcp))
                    {
                        _ = ReservarConexoes(host, port, pool.Count + 1, tamPool, cancel);
                        return tcp;
                    }
                }
            }

            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancel, cts.Token);
            var tcpNew = new TcpClient();
            _ = ReservarConexoes(host, port, 0, tamPool - 1, cancel);
            await tcpNew.ConnectAsync(host, port, cts.Token);
            return tcpNew;
        }

        private static async Task ReservarConexoes(string host, int port, int offset, int count, CancellationToken cancel = default)
        {
            var tarefas = _tarefas.GetOrAdd($"{host}:{port}", _ => []);

            tarefas.RemoveAll(t => t.IsCompleted);

            for (var i = offset + tarefas.Count; i < count; i++)
            {
                tarefas.Add(Task.Run(async () =>
                {
                    var tcpNew = new TcpClient();
                    await tcpNew.ConnectAsync(host, port, cancel);
                    SaveConnection(tcpNew);
                }, cancel));
            }

            do
            {
                await Task.Delay(10, cancel);
                await Task.WhenAny(tarefas);
                tarefas.RemoveAll(t => t.IsCompleted);
            } while (tarefas.Count > 0 && !tarefas.Any(t => t.IsCompletedSuccessfully));
        }

        public static void SaveConnection(TcpClient tcp)
        {
            try
            {
                if (tcp.Client.RemoteEndPoint is not IPEndPoint ip) { return; }

                var conexao = $"{ip.Address}:{ip.Port}";
                var pool = _pools.GetOrAdd(conexao, _ => new ConcurrentQueue<TcpClient>());

                if (!pool.Contains(tcp)) { pool.Enqueue(tcp); }
            }
            catch (ObjectDisposedException) { }
        }

        public static bool IsAlive(TcpClient tcp) => IsAlive(tcp.Client);

        public static bool IsAlive(Socket socket)
        {
            try
            {
                if (!socket.Connected || socket.Poll(1000, SelectMode.SelectError)) { return false; }
                return !socket.Poll(1000, SelectMode.SelectRead) && socket.Available == 0;
            }
            catch
            {
                socket.Dispose();
                return false;
            }
        }
    }
}
