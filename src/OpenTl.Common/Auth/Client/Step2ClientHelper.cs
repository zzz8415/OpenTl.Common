namespace OpenTl.Common.Auth.Client
{
    using System;
    using System.IO;
    using System.Linq;

    using BarsGroup.CodeGuard;

    using DotNetty.Buffers;

    using OpenTl.Common.Crypto;
    using OpenTl.Common.GuardExtensions;
    using OpenTl.Schema;
    using OpenTl.Schema.Serialization;

    using Org.BouncyCastle.Math;

    public static class Step2ClientHelper
    {
        private static readonly Random Random = new Random();

        public static RequestReqDHParams GetRequest(TResPQ resPq, string publicKey, out byte[] newNonce)
        {
            var pq = new BigInteger(resPq.PqAsBinary);
            var f1 = PollardRho.Factor(pq);
            var f2 = pq.Divide(f1);
            var p = f1.Min(f2);
            var q = f1.Max(f2);
            
            newNonce = new byte[32];
            Random.NextBytes(newNonce);

            var pqInnerData = new TPQInnerData
                              {
                                  PqAsBinary = pq.ToByteArrayUnsigned(),
                                  PAsBinary = p.ToByteArrayUnsigned(),
                                  QAsBinary = q.ToByteArrayUnsigned(),
                                  ServerNonce = resPq.ServerNonce,
                                  Nonce = resPq.Nonce,
                                  NewNonce = newNonce
                              };

            var buffer = PooledByteBufferAllocator.Default.Buffer();

            Serializer.Serialize(pqInnerData, buffer);
           
            var innerData = new byte[buffer.ReadableBytes];
            buffer.ReadBytes(innerData);

            var fingerprint = RSAHelper.GetFingerprint(publicKey);
            Guard.That(resPq.ServerPublicKeyFingerprints.Items).Contains(fingerprint);
            
            var hashsum = Sha1Helper.ComputeHashsum(innerData);

            buffer.ResetReaderIndex();
            buffer.ResetWriterIndex();
            
            buffer.WriteBytes(hashsum);
            buffer.WriteBytes(innerData);
            
            var paddingBytes = new byte[255 - buffer.ReadableBytes];
            Random.NextBytes(paddingBytes);
            buffer.WriteBytes(paddingBytes);
            
            var innerDataWithHash = new byte[buffer.ReadableBytes];
            buffer.ReadBytes(innerDataWithHash);
            
            var ciphertext = RSAHelper.RsaEncryptWithPublic(innerDataWithHash, publicKey);

            return new RequestReqDHParams
                   {
                       Nonce = resPq.Nonce,
                       PAsBinary = p.ToByteArrayUnsigned(),
                       QAsBinary = q.ToByteArrayUnsigned(),
                       ServerNonce = resPq.ServerNonce,
                       PublicKeyFingerprint = fingerprint,
                       EncryptedDataAsBinary = ciphertext
                   };
        }
    }
}