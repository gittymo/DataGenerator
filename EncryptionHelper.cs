using System.Security.Cryptography;

namespace DataProvider
{
    public sealed class EncryptionHelper
    {
        public EncryptionHelper(ConfigurationManager configurationManager)
        {
            // Get the Enc section from configuration.
            var encSection = configurationManager.GetSection("Enc") ?? throw new InvalidOperationException("ConfigurationManager.GetSection returned null for 'Enc' section.");

            key = EncryptionHelper._DecryptString(encSection.GetValue<string>("key") ?? throw new InvalidOperationException("Enc:key not found"), EncryptionHelper.masterKey, EncryptionHelper.masterIv);
            iv = EncryptionHelper._DecryptString(encSection.GetValue<string>("iv") ?? throw new InvalidOperationException("Enc:iv not found"), EncryptionHelper.masterKey, EncryptionHelper.masterIv);
        }

        public string EncryptString(string str)
        {
            return _EncryptString(str, key, iv);
        }

        public string DecryptString(string cipherText)
        {
            return _DecryptString(cipherText, key, iv);
        }

        internal static string _EncryptString(string str, string key, string iv)
        {
            ArgumentNullException.ThrowIfNull(str);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(iv);

            using Aes aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);
            aes.IV = Convert.FromBase64String(iv);
            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
            {
                using var sw = new StreamWriter(cs);
                sw.Write(str);
            }
            return Convert.ToBase64String(ms.ToArray());
        }

        internal static string _DecryptString(string cipherText, string key, string iv)
        {
            ArgumentNullException.ThrowIfNull(cipherText);
            ArgumentNullException.ThrowIfNull(key);
            ArgumentNullException.ThrowIfNull(iv);

            using Aes aes = Aes.Create();
            aes.Key = Convert.FromBase64String(key);
            aes.IV = Convert.FromBase64String(iv);
            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var ms = new MemoryStream(Convert.FromBase64String(cipherText));
            using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
            using var sr = new StreamReader(cs);
            return sr.ReadToEnd();
        }

        private readonly string key;
        private readonly string iv;
    
        internal static readonly string masterKey = "XE3kSJJRPNY9zDqyGpsNH2kAapZbYko1OqNYqp0voSw=";
        internal static readonly string masterIv = "7l++7FEGWs+tjCGxz8RGYQ==";
    }
}