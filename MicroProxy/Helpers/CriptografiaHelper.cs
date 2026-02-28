using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using static MicroProxy.Helpers.FuncoesHelper;

namespace MicroProxy.Helpers
{
    [DebuggerNonUserCode]
    public static partial class CriptografiaHelper
    {
        public readonly struct CertificadoEKUOID
        {
            public const string Cliente = "1.3.6.1.5.5.7.3.2";
            public const string Servidor = "1.3.6.1.5.5.7.3.1";

            public static string? ToString(string ekuoid)
            {
                foreach (var item in typeof(CertificadoEKUOID).GetFields())
                { if (item.GetRawConstantValue() is string valorItem && valorItem.Equals(ekuoid, StringComparison.OrdinalIgnoreCase)) { return item.Name; } }

                return null;
            }
        }

        public static string CifrarBase64(this string texto, byte[]? chave = null, byte[]? IV = null) => Convert.ToBase64String(texto.Cifrar(chave, IV));

        public static string CifrarHex(this string texto, byte[]? chave = null, byte[]? IV = null) => Convert.ToHexString(texto.Cifrar(chave, IV));

        public static byte[] Cifrar(this string texto, byte[]? chave = null, byte[]? IV = null)
        {
            chave ??= Encoding.UTF8.GetBytes("4E635266556A586E3272357537782141");

            if (texto == null || texto.Length <= 0)
            {
                throw new ArgumentNullException(nameof(texto));
            }

            byte[] cifra;

            using Aes aesAlg = Aes.Create();

            if (IV == null || IV.Length <= 0)
            {
                aesAlg.GenerateIV();
            }
            else
            {
                aesAlg.IV = IV;
            }

            aesAlg.Key = chave;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using MemoryStream msEncrypt = new();
            using CryptoStream csEncrypt = new(msEncrypt, encryptor, CryptoStreamMode.Write);
            using (StreamWriter swEncrypt = new(csEncrypt))
            {
                msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);
                swEncrypt.Write(texto);
            }

            cifra = msEncrypt.ToArray();

            return cifra;
        }

        public static string DecifrarBase64(this string cifra, byte[]? chave = null, byte[]? IV = null) => Convert.FromBase64String(cifra).Decifrar(chave, IV);

        public static string DecifrarHex(this string cifra, byte[]? chave = null, byte[]? IV = null) => Convert.FromHexString(cifra).Decifrar(chave, IV);

        public static string Decifrar(this byte[] cifra, byte[]? chave = null, byte[]? IV = null)
        {
            chave ??= Encoding.UTF8.GetBytes("4E635266556A586E3272357537782141");

            // Check arguments.
            if (cifra == null || cifra.Length <= 0)
                throw new ArgumentNullException(nameof(cifra));
            byte[] cifraBytes = cifra;

            // Create an Aes object
            // with the specified key and IV.
            using Aes aesAlg = Aes.Create();

            if (IV == null || IV.Length <= 0)
            {
                IV = new byte[16];
                int tamCifra = cifraBytes.Length - IV.Length;
                byte[] novaCifraByte = new byte[tamCifra];
                Array.Copy(cifraBytes, IV, IV.Length);
                Array.Copy(cifraBytes, IV.Length, novaCifraByte, 0, tamCifra);
                cifraBytes = novaCifraByte;
            }

            aesAlg.IV = IV;
            aesAlg.Key = chave;

            // Create a decryptor to perform the stream transform.
            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            // Create the streams used for decryption.
            using MemoryStream msDecrypt = new(cifraBytes);
            using CryptoStream csDecrypt = new(msDecrypt, decryptor, CryptoStreamMode.Read);
            using StreamReader srDecrypt = new(csDecrypt);

            // Declare the string used to hold
            // the decrypted text.
            // Read the decrypted bytes from the decrypting stream
            // and place them in a string.
            string? texto = srDecrypt.ReadToEnd();

            return texto;
        }

        public static string GerarHash(this string? dado) => dado.GerarHashAsync().Result;

        public static string GerarHash(this byte[]? bytes) => bytes.GerarHashAsync().Result;

        public static string GerarHash(this Stream stream) => stream.GerarHashAsync().Result;

        public static async Task<string> GerarHashAsync(this string? dado)
        {
            byte[]? bytes = dado != null && dado.Length != 0 ? Encoding.UTF8.GetBytes(dado) : null;

            return await bytes.GerarHashAsync();
        }

        public static async Task<string> GerarHashAsync(this byte[]? bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                return "00";
            }

            using var stream = new MemoryStream(bytes);

            return await stream.GerarHashAsync();
        }

        public static async Task<string> GerarHashAsync(this Stream stream)
        {
            var senhaCifrada = await SHA512.HashDataAsync(stream);

            return Convert.ToHexString(senhaCifrada);
        }

        public static RSA CreateRsaFromPem(string pathKey, string? senha = null)
        {
            RSA rsa = RSA.Create();
            string conteudoChave = File.ReadAllText(pathKey);

            try
            {
                if (senha != null) { rsa.ImportFromEncryptedPem(conteudoChave, senha); }
                else { rsa.ImportFromPem(conteudoChave); }
            }
            catch (ArgumentException ex)
            {
                byte[] chaveFonte = Convert.FromBase64String(ElemsKeyCertRegex().Replace(conteudoChave, ""));

                try
                {
                    if (senha != null) { rsa.ImportEncryptedPkcs8PrivateKey(senha, chaveFonte, out _); }
                    else { rsa.ImportPkcs8PrivateKey(chaveFonte, out _); }
                }
                catch (ArgumentException ex2)
                {
                    try { rsa.ImportRSAPrivateKey(chaveFonte, out _); }
                    catch (ArgumentException ex3) { throw new ArgumentException(ex3.Message, new ArgumentException(ex2.Message, ex)); }
                }
            }

            if (OperatingSystem.IsWindows())
            {
                CspParameters cspParameters = new()
                {
                    KeyContainerName = pathKey,
                    Flags = CspProviderFlags.UseNonExportableKey,
                };

                RSACryptoServiceProvider rsaPersistente = new(cspParameters);

                rsaPersistente.ImportParameters(rsa.ExportParameters(true));
                rsa.Dispose();
                rsa = rsaPersistente;
            }

            return rsa;
        }

        public static X509Certificate2 ObterCertificado(string path, string? senha = null, string? pathChave = null, string? ekuoid = null, bool exibirLog = false)
        {
            X509Certificate2? certificado = null;
            string pathArquivoCertificado = ProcessarPath(path);
            bool certificadoArquivo = File.Exists(pathArquivoCertificado);
            string certificadoPrivado = path;
            string? chave = ProcessarPath(pathChave ?? "");

            if (certificadoArquivo) { certificado = X509CertificateLoader.LoadPkcs12FromFile(pathArquivoCertificado, senha); }
            else
            {
                using X509Store x509StoreUsuario = new(StoreLocation.CurrentUser);
                using X509Store x509StorePC = new(StoreLocation.LocalMachine);

                x509StoreUsuario.Open(OpenFlags.ReadOnly);
                x509StorePC.Open(OpenFlags.ReadOnly);

                var agora = DateTime.Now;
                var certificados = x509StoreUsuario.Certificates.Union(x509StorePC.Certificates)
                    .Where(c => c.Extensions.Any(e => e is X509EnhancedKeyUsageExtension ekue && (ekuoid == null || ekue.EnhancedKeyUsages[ekuoid] != null)))
                    .OrderByDescending(c => c.NotAfter >= agora).ThenByDescending(c => c.NotBefore <= agora).ThenByDescending(c => c.NotAfter).ThenByDescending(c => c.NotBefore);
                try { certificado = certificados.FirstOrDefault(c => c.Subject == certificadoPrivado) ?? certificados.First(c => c.Subject.Contains(certificadoPrivado)); }
                catch (InvalidOperationException ex) { var e = ex; throw new($"Arquivo ou caminho de certificado \"{certificadoPrivado}\" inválido!", e); }

                string[] mensagensLog = [.. certificados.Select(c =>  $"{(c.Subject == certificado.Subject ? "(" : "")}Path/Destinatário " +
                                         $"\"{c.Subject}\" - Valido de {c.NotBefore} até {c.NotAfter}{(c.Subject == certificado.Subject ? ")" : "")}")];

                if (exibirLog) { ExibirLog(mensagensLog, "Certificados de validação de servidor disponíveis:", "; "); }
                x509StoreUsuario.Close();
                x509StorePC.Close();
            }

            if (!certificado.HasPrivateKey && chave != null) { certificado = certificado.CopyWithPrivateKey(CreateRsaFromPem(chave, senha)); }

            return certificado;
        }

        [GeneratedRegex("[^A-F0-9]", RegexOptions.IgnoreCase)]
        public static partial Regex NaoHexRegex();
        [GeneratedRegex(@"(?:-{5}[\w ]+-{5})|[\r\n]")]
        private static partial Regex ElemsKeyCertRegex();
    }
}
