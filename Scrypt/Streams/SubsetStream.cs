namespace BlackFox.Cryptography.Scrypt.Streams
{
    using System;
    using System.IO;

    class SubsetStream : Stream
    {
        readonly Stream stream;
        readonly long start;
        readonly long length;
        readonly long end;

        public SubsetStream(Stream stream, long start, long length)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }
            if (start >= stream.Length)
            {
                throw new ArgumentOutOfRangeException("start");
            }
            if (start + length >= stream.Length)
            {
                throw new ArgumentOutOfRangeException("start");
            }

            this.stream = stream;
            this.start = start;
            this.length = length;
            end = start + length;
        }

        public override void Flush()
        {
            stream.Flush();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            switch (origin)
            {
                case SeekOrigin.Begin:
                    return stream.Seek(start + offset, SeekOrigin.Begin);

                case SeekOrigin.Current:
                    return stream.Seek(offset, SeekOrigin.Current);

                case SeekOrigin.End:
                    return stream.Seek(end - offset, SeekOrigin.Begin);

                default:
                    throw new ArgumentOutOfRangeException("origin");
            }
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            count = Math.Min(count, (int)(end - stream.Position));
            return stream.Read(buffer, offset, count);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            count = Math.Min(count, (int)(end - stream.Position));
            stream.Write(buffer, offset, count);
        }

        public override bool CanRead
        {
            get { return stream.CanRead; }
        }

        public override bool CanSeek
        {
            get { return stream.CanSeek; }
        }

        public override bool CanWrite
        {
            get { return stream.CanWrite; }
        }

        public override long Length
        {
            get { return length; }
        }

        public override long Position
        {
            get { return stream.Position - start; }
            set { stream.Position = value + start; }
        }
    }
}