using System;
using System.Collections.Generic;
using BarsGroup.CodeGuard;
using DotNetty.Buffers;
using OpenTl.Common.Auth.Client;
using OpenTl.Common.Crypto;
using OpenTl.Common.GuardExtensions;
using OpenTl.Common.UnitTests.Old;
using OpenTl.Schema;
using OpenTl.Schema.Serialization;
using Org.BouncyCastle.Math;
using Xunit;

namespace OpenTl.Common.UnitTests.Handshake
{
    public class Step2RequestTest
    {
        private readonly Random _random = new Random();

        private const string PrivateKey = @"-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQB37X8dr0yaFWT8fMhPnaWrrK7ztFiz1o+eP6ZPpquQcxRBesdQ
E+KLdvhimSxR7m2L07xnmIg0ibNbCysnae8eTTofheaEschYMOxn8bx/EgwKHw5U
Q/kji4gfB/HiIYZEamXvXdJ/Q1KfW5f7uowGERPZKVVUrPhMVf77aeZqORVGBorg
8nhmkomLbZZcEP8XX6mGiLLZndNNQer3JH0ibW/LrsZBlBvmE4c3nhlhKiMGBh/C
kucNcBk1xjxtO7qdakg4bj6Gz2Vn7wYFyARTsWPyZHmK55Cs0wKTekvj+gpQaCMR
a0x6t2xLMeTpBlSLOYBLpVr1PTafedZaBaLnAgMBAAECggEAYpe3JzpUaWApU4Fq
VDmwV4BxnBypx78e9uQw386PwQM6pdJARU7zseAutzBhxUGUgZ2iiDBX2YlTEAgQ
hCiM0oZ+wCeeqXxWzln6IEIVywmVKET7zL7M9THiyFAJxPP2pAwsnSquwL0iEayF
OAfW0a38eU2Hv0MsJeWU6C/Zo30BV7/sJ98gliyGaH+hCVVqqEVg8cKLKAHCqSI6
cnleyt+V9pjq5SKoCCJ7pM7kSKUMC/SC3XN9yMKRMo+3eitkOWPHS1yO/JBFhapb
Nds//TO8x5m/Fiz6iZ1GrDoU/kVHzPgRj33u+waIX3YqomxY6hdagri2vVWQajkJ
1+MigQKBgQDSYuwTjDLlJX/k97e4gg6m7ZKV1z5Xy/i4+RhgJP0CsG60O4dpmV+U
2M5b39o+6Ae9WJBhEMMFg2+N/bSmYcJc/0IXqv1x07p55J06jmzuqnRDLXdcHNcu
Ry8qgZxI3YB9XEd2nLiNpS+M0NotChBtzD2TfUQ3J+dyCWJqXdWioQKBgQCR7dhf
obTmtmGoOxOCyizSl160LyVFU7JC4hM7OIo1O/DCZRUK7ALIlwXERIdOD02dAi0U
2TgVog/acJQSKdT2eBQimzObw3V1xY4/l156V7u3hvbow9PsVswbTjeGGQrSZma3
pwTNGlzpuNwpETn7z96bBf6RfCPvhYo6BhDghwKBgH7YJ4+tkq33iwGonPtAZscc
K6nt6WeT0fTsMlcdVfI+H7DIx17Smv8qLFjWQUZ2LNxrPjlXms2DLkoEsdsyy7W4
LMgKTt5HEoIVZPp+Do1i9c/e5L0DonUDdBuDo4+HBMYQUgHggaDc/CtBbJmFHNym
LGX1O6CpjXCC2fRZeMmhAoGASWgSqvCGNnRSJbUp+GXJLFo2qn74yanzhw+ASw8C
/wpa7v64GhlkwRCvNu6d/ZdXHH8GvHEUdFVkkiaFZamjViRLRKk7ycQF5ytshfKX
9QUDCawbsjUn+sAixi2PYqZgOjyGuSWMFbyINo3mOcZPm6sSOHtIdlizHv7W7J82
iCsCgYAaZCoeK8LCyyRTvUi4YmHTy9ctMNdkCXfHE95+1vJ5mgltxXLFgeUuIetb
3OYbMLrWu3XeYMdIb+isNoWF9ptGs1iIkk7SE7zdijh5H7gM7LEYt9poSZzbL8EQ
buOTw+gL/RnTazPLUaDs/hgZYXXbkV0bQOBEcsm689viyHKCpA==
-----END RSA PRIVATE KEY-----";

        private const string PublicKey = @"-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQB37X8dr0yaFWT8fMhPnaWr
rK7ztFiz1o+eP6ZPpquQcxRBesdQE+KLdvhimSxR7m2L07xnmIg0ibNbCysnae8e
TTofheaEschYMOxn8bx/EgwKHw5UQ/kji4gfB/HiIYZEamXvXdJ/Q1KfW5f7uowG
ERPZKVVUrPhMVf77aeZqORVGBorg8nhmkomLbZZcEP8XX6mGiLLZndNNQer3JH0i
bW/LrsZBlBvmE4c3nhlhKiMGBh/CkucNcBk1xjxtO7qdakg4bj6Gz2Vn7wYFyART
sWPyZHmK55Cs0wKTekvj+gpQaCMRa0x6t2xLMeTpBlSLOYBLpVr1PTafedZaBaLn
AgMBAAE=
-----END PUBLIC KEY-----";
        [Fact]
        public void ValidationTest()
        {
            var pqData = new byte[] {35, 85, 96, 197, 87, 11, 113, 253};
            
            var resPq = new TResPQ
            {
                Nonce = new byte[16],
                ServerNonce = new byte[16],
                PqAsBinary = pqData,
                ServerPublicKeyFingerprints = new TVector<long>(5611009732197236050)
            };

            _random.NextBytes(resPq.Nonce);
            _random.NextBytes(resPq.ServerNonce);

           var response = Step2ClientHelper.GetRequest(resPq, PublicKey, out var newNonce);

            var a = new Step2DhExchange();
            var bytes = a.ToBytes(resPq.Nonce, resPq.ServerNonce, newNonce, new List<byte[]>(){BitConverter.GetBytes(5611009732197236050)},
                new Old.MTProto.Crypto.BigInteger(1, pqData));

            var buffer = PooledByteBufferAllocator.Default.Buffer();
            buffer.WriteBytes(bytes);
            var responseOld = (RequestReqDHParams)Serializer.Deserialize(buffer);

            Assert.Equal(response.PAsBinary,responseOld.PAsBinary);
            Assert.Equal(response.QAsBinary,responseOld.QAsBinary);
            Assert.Equal(response.Nonce,responseOld.Nonce);
            Assert.Equal(response.ServerNonce,responseOld.ServerNonce);
            Assert.Equal(response.PublicKeyFingerprint, responseOld.PublicKeyFingerprint);

            var responseInnerData = Decrypt(response, out var responseInnerDataChecksum);
            var responseOldInnerData = Decrypt(responseOld, out var responseOldInnerDataChecksum);
            
            Assert.Equal(responseInnerDataChecksum,responseOldInnerDataChecksum);
            Assert.Equal(responseInnerData.PqAsBinary,responseOldInnerData.PqAsBinary);
            Assert.Equal(responseInnerData.PAsBinary,responseOldInnerData.PAsBinary);
            Assert.Equal(responseInnerData.QAsBinary,responseOldInnerData.QAsBinary);
            Assert.Equal(responseInnerData.Nonce,responseOldInnerData.Nonce);
            Assert.Equal(responseInnerData.ServerNonce, responseOldInnerData.ServerNonce);
            Assert.Equal(responseInnerData.NewNonce, responseOldInnerData.NewNonce);
        }

        [Fact(Skip = "Need to disable random padding")]
        public void DeserializatinTest()
        {
            var pq = new BigInteger("2821213750622862821", 10);
            
            var resPq = new TResPQ
            {
                Nonce = new byte[16],
                ServerNonce = new byte[16],
                PqAsBinary = pq.ToByteArrayUnsigned(),
                ServerPublicKeyFingerprints = new TVector<long>(5611009732197236050)
            };

            _random.NextBytes(resPq.Nonce);
            _random.NextBytes(resPq.ServerNonce);

            var response = Step2ClientHelper.GetRequest(resPq, PublicKey, out var newNonce);

            var buffer = PooledByteBufferAllocator.Default.Buffer();
            Serializer.Serialize(response, buffer);

            var dataNew = new byte[buffer.ReadableBytes];
            buffer.ReadBytes(dataNew);
                
            var a = new Step2DhExchange();
            var dataOld = a.ToBytes(resPq.Nonce, resPq.ServerNonce, newNonce, new List<byte[]>(){BitConverter.GetBytes(5611009732197236050)},
                new Old.MTProto.Crypto.BigInteger("2821213750622862821", 10));
            
            Assert.Equal(dataNew, dataOld);
        }

        private static TPQInnerData Decrypt(RequestReqDHParams requestReqDhParams, out byte[] checksum)
        {
            var decryptedResponse = RSAHelper.RsaDecryptWithPrivate(requestReqDhParams.EncryptedDataAsBinary, PrivateKey);

            var decryptedResponseBuffer = PooledByteBufferAllocator.Default.Buffer();

            decryptedResponseBuffer.WriteBytes(decryptedResponse);
            
            checksum = new byte[20];
            decryptedResponseBuffer.ReadBytes(checksum);

           return (TPQInnerData) Serializer.Deserialize(decryptedResponseBuffer);
        }
    }
}