using System;
using OpenTl.Common.Auth;
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

        public ISession Session = GenerateSession();
        
        private int _seqNumber;
        public int SeqNumber => _seqNumber++;
        
        [Fact]
        public void FromClientEncryption()
        {
            var user = new TUser
            {
                AccessHash = 11111,
                Id = 1
            };

            var data = Serializer.SerializeObject(user);

            var encryptedData = MtProtoHelper.FromClientEncrypt(data, Session, SeqNumber);
            var dencryptedData = MtProtoHelper.FromClientDecrypt(encryptedData, Session, out var authKeyId, out var serverSalt, out var sessionId, out var messageId, out var seqNumber);
            
            Assert.Equal(data, dencryptedData);
            Assert.Equal(Session.AuthKey.Id, authKeyId);
            Assert.Equal(Session.ServerSalt, serverSalt);
            Assert.Equal(Session.SessionId, sessionId);
            Assert.Equal(_seqNumber - 1, seqNumber);
        }
        
        
        [Fact]
        public void FromServerEncryption()
        {
            var user = new TUser
            {
                AccessHash = 11111,
                Id = 1
            };

            var data = Serializer.SerializeObject(user);

            var encryptedData = MtProtoHelper.FromServerEncrypt(data, Session, SeqNumber);
            var dencryptedData = MtProtoHelper.FromServerDecrypt(encryptedData, Session, out var authKeyId, out var serverSalt, out var sessionId, out var messageId, out var seqNumber);
            
            Assert.Equal(data, dencryptedData);
            Assert.Equal(Session.AuthKey.Id, authKeyId);
            Assert.Equal(Session.ServerSalt, serverSalt);
            Assert.Equal(Session.SessionId, sessionId);
            Assert.Equal(_seqNumber - 1, seqNumber);
        }

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