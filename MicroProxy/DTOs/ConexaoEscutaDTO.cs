namespace MicroProxy.DTOs
{
    public class ConexaoEscutaDTO
    {
        public string IP { get; set; } = null!;
        public ushort? PortaHttp { get; set; }
        public string? CertificadoPrivado { get; set; }
        public string? CertificadoPrivadoSenha { get; set; }
        public string? CertificadoPrivadoChave { get; set; }
    }
}
