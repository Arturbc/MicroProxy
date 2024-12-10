using System.Diagnostics;

namespace MicroProxy.Models
{
    public class Executavel
    {
        public Process Processo { get; set; } = null!;
        public bool AutoFechar { get; set; }
    }
}
