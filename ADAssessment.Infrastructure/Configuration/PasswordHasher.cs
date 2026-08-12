using System;
using System.Security.Cryptography;

namespace ADAssessment.Infrastructure.Configuration
{
    /// <summary>
    /// PBKDF2 (Rfc2898DeriveBytes) tabanlı, dış bağımlılık gerektirmeyen parola
    /// hashleme/doğrulama yardımcısı. Sabit-zamanlı karşılaştırma ile timing
    /// saldırılarına karşı korunur.
    /// </summary>
    public static class PasswordHasher
    {
        private const int Iterations = 100_000;
        private const int SaltSize = 16;
        private const int HashSize = 32;

        /// <summary>
        /// "{iterasyon}.{saltBase64}.{hashBase64}" formatında encode edilmiş hash üretir.
        /// </summary>
        public static string Hash(string password)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(password);

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, HashSize);

            return $"{Iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
        }

        /// <summary>
        /// Verilen düz parolanın, encode edilmiş hash ile eşleşip eşleşmediğini
        /// sabit-zamanlı karşılaştırma ile doğrular.
        /// </summary>
        public static bool Verify(string password, string encodedHash)
        {
            if (string.IsNullOrEmpty(password) || string.IsNullOrWhiteSpace(encodedHash))
            {
                return false;
            }

            string[] parts = encodedHash.Split('.', 3);
            if (parts.Length != 3 || !int.TryParse(parts[0], out int iterations))
            {
                return false;
            }

            try
            {
                byte[] salt = Convert.FromBase64String(parts[1]);
                byte[] expectedHash = Convert.FromBase64String(parts[2]);
                byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expectedHash.Length);

                return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }
}
