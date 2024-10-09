using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.IO;

namespace Org.BouncyCastle.Cms
{
    /// <remarks>
    /// General class for generating a CMS enveloped-data message using
    /// an authenticated encryption algorithm for content encryption.
    /// 
    /// Supported authenticated encryption algorithms:
    /// AES128 GCM, AES192 GCM, AES256 GCM
    /// AES128 CCM, AES192 CCM, AES256 CCM
    /// 
    /// A simple example of usage.
    ///
    /// <pre>
    ///      CmsAuthEnvelopedDataGenerator cms =
    ///          new CmsAuthEnvelopedDataGenerator();
    ///
    ///      cms.AddKeyTransRecipient(recipientCert);
    ///
    ///      CmsAuthEnvelopedData envelopedData =
    ///          cms.Generate(new CmsProcessableByteArray(inputByteArray), Aes128Gcm);
    ///
    ///      byte[] result = envelopedData.GetEncoded();
    /// </pre>
    /// </remarks>
    public class CmsAuthEnvelopedDataGenerator : CmsAuthEnvelopedGenerator
    {
        /// <summary>
        /// Constructs an instance using the default values
        /// </summary>
        public CmsAuthEnvelopedDataGenerator()
            : base()
        {
        }

        /// <summary>
        /// Constructor allowing specific source of randomness
        /// </summary>
        /// <param name="random">Instance of <c>SecureRandom</c> to use.</param>
        public CmsAuthEnvelopedDataGenerator(SecureRandom random)
            : base(random)
        {
        }


        /// <summary>
        /// Called to generate a enveloped data object.
        /// </summary>
        /// <param name="content">Content to encrypt</param>
        /// <param name="encryptionOid">Content encryption algorithm object identifier</param>
        /// <returns>Enveloped data object</returns>
        public CmsAuthEnvelopedData Generate(CmsProcessable content, string encryptionOid)
        {
            try
            {
                CipherKeyGenerator keyGen = GeneratorUtilities.GetKeyGenerator(encryptionOid);

                keyGen.Init(new KeyGenerationParameters(m_random, keyGen.DefaultStrength));

                return Generate(content, encryptionOid, keyGen);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("can't find key generation algorithm.", e);
            }
        }

        /// <summary>
        /// Called to generate a enveloped data object.
        /// </summary>
        /// <param name="content">Content to encrypt</param>
        /// <param name="encryptionOid">Content encryption algorithm object identifier</param>
        /// <param name="keyGen">Content encryption key generator</param>
        /// <returns>Enveloped data object</returns>
        private CmsAuthEnvelopedData Generate(CmsProcessable content, string encryptionOid, CipherKeyGenerator keyGen)
        {
            try
            {
                byte[] encKeyBytes = keyGen.GenerateKey();

                KeyParameter encKey =
                    ParameterUtilities.CreateKeyParameter(encryptionOid, encKeyBytes);

                Asn1Object encAlgParams =
                    GenerateAsn1Parameters(encryptionOid, encKeyBytes).ToAsn1Object();

                AlgorithmIdentifier encAlgId = GetAlgorithmIdentifier(
                    encryptionOid, encKey, encAlgParams, out var cipherParameters);

                IBufferedCipher cipher = CreateCipher(encryptionOid, cipherParameters);

                byte[] encryptedBlock = EncryptContent(content, cipher);

                SplitEncryptedBlock(encryptedBlock, out byte[] encContent, out byte[] mac);

                return CreateEnvelopedDataObject(encAlgId, encKey, encContent, mac);
            }
            catch (SecurityUtilityException e)
            {
                throw new CmsException("couldn't create cipher.", e);
            }
            catch (InvalidKeyException e)
            {
                throw new CmsException("key invalid in message.", e);
            }
            catch (IOException e)
            {
                throw new CmsException("exception decoding algorithm parameters.", e);
            }
        }

        /// <summary>
        /// Creates a cipher engine used to encrypt the content.
        /// </summary>
        /// <param name="encryptionOid">Encryption algorithm oid</param>
        /// <param name="cipherParameters">Cipher parameters</param>
        /// <returns>Cipher engine for content encryption</returns>
        private IBufferedCipher CreateCipher(string encryptionOid, ICipherParameters cipherParameters)
        {
            IBufferedCipher cipher = CipherUtilities.GetCipher(encryptionOid);

            cipher.Init(forEncryption: true, new ParametersWithRandom(cipherParameters, m_random));

            return cipher;
        }

        /// <summary>
        /// Encrypts the incoming content data using the passed in cipher engine.
        /// </summary>
        /// <param name="content">Data to encrypt</param>
        /// <param name="cipher">Cipher engine used to encrypt the content data</param>
        /// <returns>Encrypted block as byte array</returns>
        private static byte[] EncryptContent(CmsProcessable content, IBufferedCipher cipher)
        {
            using (MemoryStream bOut = new MemoryStream())
            {
                using (CipherStream cOut = new CipherStream(bOut, null, cipher))
                {
                    content.Write(cOut);
                }

                return bOut.ToArray();
            }
        }

        /// <summary>
        /// Splits a encrypted block into its components.
        /// </summary>
        /// <param name="encBlock">Encrypted block coming from the cipher engine.</param>
        /// <param name="encContent">Encrypted content</param>
        /// <param name="MAC">Message authentication code</param>
        private void SplitEncryptedBlock(byte[] encBlock, out byte[] encContent, out byte[] MAC)
        {
            if (encBlock.Length > MacSize)
            {
                encContent = new byte[encBlock.Length - MacSize];

                MAC = new byte[MacSize];

                Array.Copy(encBlock, 0, encContent, 0, encContent.Length);

                Array.Copy(encBlock, encContent.Length, MAC, 0, MAC.Length);
            }
            else
            {
                throw new CmsException("Splitting the encrypted data into its components has failed.");
            }
        }

        /// <summary>
        /// Creates a enveloped data object.
        /// </summary>
        /// <param name="encAlgId">Content encryption algorithm</param>
        /// <param name="encKey">Content encryption key</param>
        /// <param name="encContent">Encrypted content</param>
        /// <param name="mac">Message authentication code</param>
        /// <returns>Enveloped data object</returns>
        private CmsAuthEnvelopedData CreateEnvelopedDataObject(
            AlgorithmIdentifier encAlgId, KeyParameter encKey, byte[] encContent, byte[] mac)
        {
            Asn1Set RecipientInfos =
                GenerateRecipientInfoSet(encKey);

            EncryptedContentInfo encryptedContentInfo =
                new EncryptedContentInfo(CmsObjectIdentifiers.Data, encAlgId, new BerOctetString(encContent));

            AuthEnvelopedData authEnvelopedData =
                new AuthEnvelopedData(null, RecipientInfos, encryptedContentInfo, null, new BerOctetString(mac), null);

            ContentInfo contentInfo =
                new ContentInfo(CmsObjectIdentifiers.AuthEnvelopedData, authEnvelopedData);

            CmsAuthEnvelopedData cmsAuthEnvelopedData =
                new CmsAuthEnvelopedData(contentInfo);

            return cmsAuthEnvelopedData;
        }
    }
}
