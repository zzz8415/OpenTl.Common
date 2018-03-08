using System;
using DotNetty.Buffers;
using OpenTl.Common.Auth;
using OpenTl.Common.Extesions;
using OpenTl.Common.Interfaces;
using OpenTl.Common.MtProto;
using OpenTl.Schema;
using OpenTl.Schema.Serialization;
using Xunit;

namespace OpenTl.Common.UnitTests
{
    public class MtProtoTest
    {
        private static readonly Random Random = new Random();

        private readonly ISession _session = GenerateSession();
        
        private int _seqNumber;
        private int SeqNumber => _seqNumber++;
        
        [Fact]
        public void ToServerEncryption()
        {
            var user = new TUser
            {
                AccessHash = 11111,
                Id = 1
            };

            var input = PooledByteBufferAllocator.Default.Buffer();
            Serializer.Serialize(user, input);
            
            var output = PooledByteBufferAllocator.Default.Buffer();
            MtProtoHelper.ToServerEncrypt(input, _session, 0, SeqNumber, output);
            
            var dencryptedData = MtProtoHelper.FromClientDecrypt(output, _session, out var authKeyId, out var serverSalt, out var sessionId, out var messageId, out var seqNumber);

            input.ResetReaderIndex();
            Assert.Equal(input.ToArray(input.ReadableBytes), dencryptedData.ToArray(dencryptedData.ReadableBytes));
            Assert.Equal(_session.AuthKey.Id, authKeyId);
            Assert.Equal(_session.ServerSalt, serverSalt);
            Assert.Equal(_session.SessionId, sessionId);
            Assert.Equal(_seqNumber - 1, seqNumber);
        }
        
        
//        [Fact]
//        public void FromServerEncryption()
//        {
//            var user = new TUser
//            {
//                AccessHash = 11111,
//                Id = 1
//            };
//
//            var buffer = PooledByteBufferAllocator.Default.Buffer();
//            Serializer.Serialize(user, buffer);
//            var data = new byte[buffer.ReadableBytes];
//            buffer.ReadBytes(data);
//
//            var encryptedData = MtProtoHelper.ToClientEncrypt(data, _session, 0, SeqNumber,);
//            var dencryptedData = MtProtoHelper.FromServerDecrypt(encryptedData, _session, out var authKeyId, out var serverSalt, out var sessionId, out var messageId, out var seqNumber);
//            
//            Assert.Equal(data, dencryptedData);
//            Assert.Equal(_session.AuthKey.Id, authKeyId);
//            Assert.Equal(_session.ServerSalt, serverSalt);
//            Assert.Equal(_session.SessionId, sessionId);
//            Assert.Equal(_seqNumber - 1, seqNumber);
//        }

        private static ISession GenerateSession()
        {
            return new TestSession
            {
                AuthKey = GenerateAuthKey(),
                ServerTime = 1,
                SessionId = GenerateSessionId(),
                ServerSalt = GenerateSalt()
            };
        }
        private static ulong GenerateSessionId()
        {
            var data = new byte[8];
            Random.NextBytes(data);

            return BitConverter.ToUInt64(data, 0);
        }
        
        private static AuthKey GenerateAuthKey()
        {
            var keyData = new byte[256];
            Random.NextBytes(keyData);
            return  new AuthKey(keyData);
        }
        
        private static byte[] GenerateSalt()
        {
            var salt = new byte[8];
            Random.NextBytes(salt);

            return salt;
        }
      
    }
}