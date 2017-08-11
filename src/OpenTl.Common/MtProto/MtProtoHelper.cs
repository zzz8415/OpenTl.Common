using System;
using System.IO;
using System.Linq;
using BarsGroup.CodeGuard;
using OpenTl.Common.Crypto;
using OpenTl.Common.Interfaces;

namespace OpenTl.Common.MtProto
{
    public static class MtProtoHelper
    {
        private static AesKeyData CalcKey(byte[] sharedKey, byte[] msgKey, bool client)
        {
            Guard.That(sharedKey.Length, nameof(sharedKey)).IsEqual(256);
            Guard.That(msgKey.Length, nameof(msgKey)).IsEqual(16);

            var x = client ? 0 : 8;
            var buffer = new byte[48];

            Array.Copy(msgKey, 0, buffer, 0, 16); // buffer[0:16] = msgKey
            Array.Copy(sharedKey, x, buffer, 16, 32); // buffer[16:48] = authKey[x:x+32]
            var sha1A = SHA1Helper.ComputeHashsum(buffer); // sha1a = sha1(buffer)

            Array.Copy(sharedKey, 32 + x, buffer, 0, 16); // buffer[0:16] = authKey[x+32:x+48]
            Array.Copy(msgKey, 0, buffer, 16, 16); // buffer[16:32] = msgKey
            Array.Copy(sharedKey, 48 + x, buffer, 32, 16); // buffer[32:48] = authKey[x+48:x+64]
            var sha1B = SHA1Helper.ComputeHashsum(buffer); // sha1b = sha1(buffer)

            Array.Copy(sharedKey, 64 + x, buffer, 0, 32); // buffer[0:32] = authKey[x+64:x+96]
            Array.Copy(msgKey, 0, buffer, 32, 16); // buffer[32:48] = msgKey
            var sha1C = SHA1Helper.ComputeHashsum(buffer); // sha1c = sha1(buffer)

            Array.Copy(msgKey, 0, buffer, 0, 16); // buffer[0:16] = msgKey
            Array.Copy(sharedKey, 96 + x, buffer, 16, 32); // buffer[16:48] = authKey[x+96:x+128]
            var sha1D = SHA1Helper.ComputeHashsum(buffer); // sha1d = sha1(buffer)

            var key = new byte[32]; // key = sha1a[0:8] + sha1b[8:20] + sha1c[4:16]
            Array.Copy(sha1A, 0, key, 0, 8);
            Array.Copy(sha1B, 8, key, 8, 12);
            Array.Copy(sha1C, 4, key, 20, 12);

            var iv = new byte[32]; // iv = sha1a[8:20] + sha1b[0:8] + sha1c[16:20] + sha1d[0:8]
            Array.Copy(sha1A, 8, iv, 0, 12);
            Array.Copy(sha1B, 0, iv, 12, 8);
            Array.Copy(sha1C, 16, iv, 20, 4);
            Array.Copy(sha1D, 0, iv, 24, 8);

            return new AesKeyData(key, iv);
        }

        public static byte[] FromClientDecrypt(byte[] packet, ISession session, out ulong authKeyId,
            out byte[] serverSalt, out ulong sessionId, out ulong messageId, out int seqNumber)
        {
            return Decrypt(packet, session, true, out authKeyId, out serverSalt, out sessionId, out messageId, out seqNumber);
        }
        
        public static byte[] FromClientEncrypt(byte[] packet, ISession session, int seqNumber)
        {
            return Encypt(packet, true, session, seqNumber);
        }
        
        public static byte[] FromServerDecrypt(byte[] packet, ISession session, out ulong authKeyId,
            out byte[] serverSalt, out ulong sessionId, out ulong messageId, out int seqNumber)
        {
            return Decrypt(packet, session, false, out authKeyId, out serverSalt, out sessionId, out messageId, out seqNumber);
        }
        
        public static byte[] FromServerEncrypt(byte[] packet, ISession session, int seqNumber)
        {
            return Encypt(packet, false, session, seqNumber);
        }

        private static byte[] Decrypt(byte[] packet, ISession session, bool isClient, out ulong authKeyId, out byte[] serverSalt, out ulong sessionId, out ulong messageId, out int seqNumber)
        {
            byte[] messageKey;
            byte[] encryptedData;
            using (var stream = new MemoryStream(packet))
            using (var binaryReader = new BinaryReader(stream))
            {
                authKeyId = binaryReader.ReadUInt64();
                messageKey = binaryReader.ReadBytes(16);
                encryptedData = binaryReader.ReadBytes(packet.Length - 16 - 8);
            }

            var aesKey = CalcKey(session.AuthKey.Data, messageKey, isClient);

            var message = AES.DecryptAes(aesKey, encryptedData);

            using (var stream = new MemoryStream(message))
            using (var binaryReader = new BinaryReader(stream))
            {
                serverSalt = binaryReader.ReadBytes(8);
                sessionId = binaryReader.ReadUInt64();
                messageId = binaryReader.ReadUInt64();
                seqNumber = binaryReader.ReadInt32();
                var length = binaryReader.ReadInt32();

                return binaryReader.ReadBytes(length);
            }
        }

        private static byte[] Encypt(byte[] packet, bool isClient, ISession session, int seqNumber)
        {
            byte[] messsage;
            using (var stream = new MemoryStream())
            using (var binaryWriter = new BinaryWriter(stream))
            {
                binaryWriter.Write(session.ServerSalt);
                binaryWriter.Write(session.SessionId);
                binaryWriter.Write(session.MessageId);
                binaryWriter.Write(seqNumber);
                binaryWriter.Write(packet.Length);
                binaryWriter.Write(packet);

                messsage = stream.ToArray();
            }

            var messageKey = SHA1Helper.ComputeHashsum(messsage).Take(16).ToArray();

            var aesKey = CalcKey(session.AuthKey.Data, messageKey, isClient);

            using (var stream = new MemoryStream())
            using (var binaryWriter = new BinaryWriter(stream))
            {
                binaryWriter.Write(session.AuthKey.Id);
                binaryWriter.Write(messageKey);
                binaryWriter.Write(AES.EncryptAes(aesKey, messsage));

                return stream.ToArray();
            }
        }
    }
}