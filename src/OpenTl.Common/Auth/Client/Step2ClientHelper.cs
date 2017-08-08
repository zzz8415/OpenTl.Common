namespace OpenTl.Common.Auth.Client
{
    using System;
    using System.IO;
    using System.Linq;

    using BarsGroup.CodeGuard;

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
            var p = BigIntegerHelper.SmallestPrimeFactor(pq);

            var q = pq.Divide(p);

            newNonce = new byte[32];
            Random.NextBytes(newNonce);

            var pqInnerData = new TPQInnerData
                              {
                                  PqAsBinary = resPq.PqAsBinary,
                                  PAsBinary = p.ToByteArrayUnsigned(),
                                  QAsBinary = q.ToByteArrayUnsigned(),
                                  ServerNonce = resPq.ServerNonce,
                                  Nonce = resPq.Nonce,
                                  NewNonce = newNonce
                              };

            var innerData = Serializer.SerializeObject(pqInnerData);

            var fingerprint = RSAHelper.GetFingerprint(publicKey);
            Guard.That(resPq.ServerPublicKeyFingerprints.Items).Contains(fingerprint);
            
            var hashsum = SHA1Helper.ComputeHashsum(innerData);
            var innerDataWithHash = hashsum.Concat(innerData).ToArray();

            var ciphertext = RSAHelper.RsaEncryptWithPublic(innerDataWithHash, publicKey);

            if (ciphertext.Length != 256)
            {
                var paddedCiphertext = new byte[256];
                var padding = 256 - ciphertext.Length;
                for (var i = 0; i < padding; i++)
                    paddedCiphertext[i] = 0;
                ciphertext.CopyTo(paddedCiphertext, padding);
                ciphertext = paddedCiphertext;
            }

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