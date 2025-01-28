namespace MicroProxy.Models
{
    public class Log
    {
        public bool IgnorarArquivosEstaticos { get; set; } = true;
        public string Path { get; set; } = null!;
        public string Mensagem { get; set; } = null!;
        public string[]? TratamentoRegex { get; set; } = null;
    }
}
