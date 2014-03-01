namespace BlackFox.Cryptography.NetScrypt.Scrypt.Streams
{
    using System;
    using System.IO;

    static class StreamExtensions
    {
        public static void ReadExactly(this Stream stream, byte[] buffer, int offset, int count)
        {
            if (stream == null) throw new ArgumentNullException("stream");

            int read;
            do
            {
                read = stream.Read(buffer, offset, count);
                offset += read;
                count -= read;
            } while (count > 0 && read != 0);

            if (read == 0)
            {
                throw new EndOfStreamException();
            }
        }

        public static byte[] ToArray(this Stream input)
        {
            if (input == null) throw new ArgumentNullException("input");

            var buffer = new byte[16 * 1024];
            using (var memoryStream = new MemoryStream())
            {
                int read;
                while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
                {
                    memoryStream.Write(buffer, 0, read);
                }
                return memoryStream.ToArray();
            }
        }
    }
}