using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace MicroProxy.Models
{
    public static class ConnectionPool
    {
        static readonly ConcurrentDictionary<string, ConcurrentQueue<TcpClient>> _pools = [];

        public static async Task<TcpClient> GetConnectionAsync(string host, int port, CancellationToken cancel = default)
        {
            var detalhesHost = await Dns.GetHostEntryAsync(host, cancel);
            var iPs = detalhesHost?.AddressList ?? [];
            string? conexao = _pools.Keys.FirstOrDefault(p => iPs.Any(i => p.Split(':').Contains(i.ToString())));

            if (conexao != null)
            {
                var pool = _pools.GetOrAdd(conexao, _ => new ConcurrentQueue<TcpClient>());
                while (!pool.IsEmpty) { if (pool.TryDequeue(out var tcp) && tcp.Connected && IsAlive(tcp)) { return tcp; } }
            }

            using var cts = new CancellationTokenSource(25000);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancel, cts.Token);
            var tcpNew = new TcpClient();
            await tcpNew.ConnectAsync(host, port, linked.Token);
            return tcpNew;
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

        static bool IsAlive(TcpClient tcp)
        {
            try
            {
                var socket = tcp.Client;
                if (!socket.Connected) { return false; }
                return !socket.Poll(1000, SelectMode.SelectRead) || socket.Available != 0;
            }
            catch
            {
                tcp.Dispose();
                return false;
            }
        }
    }
}
