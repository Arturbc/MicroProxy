using System.Collections.Concurrent;
using System.Net.Sockets;

namespace MicroProxy.Models
{
    public static class ConnectionPool
    {
        static readonly ConcurrentDictionary<string, ConcurrentQueue<TcpClient>> _pools = [];

        public static async Task<TcpClient> GetConnectionAsync(string host, int port, CancellationToken cancel = default)
        {
            var conexao = $"{host}:{port}";
            var pool = _pools.GetOrAdd(conexao, _ => new ConcurrentQueue<TcpClient>());
            if (pool.TryDequeue(out var tcp) && tcp.Connected && IsAlive(tcp)) { pool.Enqueue(tcp); return tcp; }

            using var cts = new CancellationTokenSource(25000);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancel, cts.Token);
            var tcpNew = new TcpClient();
            await tcpNew.ConnectAsync(host, port, linked.Token);
            pool.Enqueue(tcpNew);
            return tcpNew;
        }

        static bool IsAlive(TcpClient tcp)
        {
            try
            {
                var socket = tcp.Client;
                if (!socket.Connected) { return false; }
                return !(socket.Poll(1000, SelectMode.SelectRead) && socket.Available == 0);
            }
            catch
            {
                tcp.Dispose();
                return false;
            }
        }
    }
}
