namespace MicroProxy.DTOs
{
    public class ConexaoEscutaDTO
    {
        public string IP { get; internal set; } = null!;
        public ushort? PortaHttp {  get; internal set; }
        public string? CertificadoPrivado { get; internal set; }
        public string? CertificadoPrivadoSenha { get; internal set; }
        public string? CertificadoPrivadoChave { get; internal set; }
    }
}
