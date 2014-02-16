namespace BlackFox.Cryptography.NetScrypt.Scrypt
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    class ScryptAesCtr
    {
        readonly long nonce;
        long byteCounter;
        readonly byte[] buf = new byte[16];

        private readonly Aes aes;

        public ScryptAesCtr(byte[] key, long nonce)
        {
            var iv = new byte[16];
            for (int i = 0; i < 16; i++)
            {
                iv[i] = 0;
            }

            aes = Aes.Create();
            if (aes == null)
            {
                throw new InvalidOperationException("Can't find an implementation of AES");
            }

            aes.KeySize = 256;
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            this.nonce = nonce;
        }

        public void EncryptOrDectrypt(Stream input, Stream output)
        {
            var pblk = new byte[16];

            ICryptoTransform aesEncryptor = aes.CreateEncryptor();
            byte[] nonceArray = BitConverter.GetBytes(nonce);
            if (BitConverter.IsLittleEndian) Array.Reverse(nonceArray);

            for (long pos = 0; pos < input.Length; pos++)
            {
                /* How far through the buffer are we? */
                var bytemod = (int)(byteCounter % 16);

                /* Generate a block of cipherstream if needed. */
                if (bytemod == 0)
                {
                    Array.Copy(nonceArray, 0, pblk, 0, nonceArray.Length);
                    var counterBytes = BitConverter.GetBytes(byteCounter / 16);
                    if (BitConverter.IsLittleEndian) Array.Reverse(counterBytes);
                    Array.Copy(counterBytes, 0, pblk, 8, counterBytes.Length);
                    aesEncryptor.TransformBlock(pblk, 0, pblk.Length, buf, 0);
                }

                /* Encrypt a byte. */
                var newbyte = input.ReadByte() ^ buf[bytemod];
                output.WriteByte((byte)newbyte);

                /* Move to the next byte of cipherstream. */
                byteCounter += 1;
            }
        }
    }
}