namespace MicroProxy.Models
{
    public class Log
    {
        public string Path { get; set; } = null!;
        public string Mensagem { get; set; } = null!;
        public string[]? TratamentoRegex { get; set; } = null;
    }
}
