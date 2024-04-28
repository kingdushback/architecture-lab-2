using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Binders;
using Newtonsoft.Json;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WebApplication4
{
    [Route("api/dataEncryption")]
    [ApiController]
    public class ValuesController : ControllerBase
    {
        private static RSAParameters sharedParameters;

        private static Random random = new Random();

        [HttpGet]
        [Route("generate-random-message")]
        public JsonResult RandomString(int length)
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            var stringChars = new char[8];
            var random = new Random();

            for (int i = 0; i < stringChars.Length; i++)
            {
                stringChars[i] = chars[random.Next(chars.Length)];
            }
            string randomMessage = new String(stringChars);
            byte[] signedResult = InnerSignMessage(randomMessage);
            string signedMessage = Convert.ToBase64String(signedResult);
            var result = JsonConvert.SerializeObject( new Dictionary<string, string>()
            {
                { "randomMessage", randomMessage},
                { "signedRandom", signedMessage}
            });
            
            return new JsonResult(result);

        }

        private static string MakePem(byte[] ber, string header)
        {
            StringBuilder builder = new StringBuilder("-----BEGIN ");
            builder.Append(header);
            builder.AppendLine("-----");

            string base64 = Convert.ToBase64String(ber);
            int offset = 0;
            const int LineLength = 64;

            while (offset < base64.Length)
            {
                int lineEnd = Math.Min(offset + LineLength, base64.Length);
                builder.AppendLine(base64.Substring(offset, lineEnd - offset));
                offset = lineEnd;
            }

            builder.Append("-----END ");
            builder.Append(header);
            builder.AppendLine("-----");
            return builder.ToString();
        }

        private static byte[] InnerSignMessage(string message)
        {

            byte[] signedHash;
            try
            {
                using (SHA256 alg = SHA256.Create())
                {
                    byte[] data = Encoding.ASCII.GetBytes(message);
                    byte[] hash = alg.ComputeHash(data);
                    using (RSA rsa = RSA.Create())
                    {
                        sharedParameters = rsa.ExportParameters(false);

                        RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
                        rsaFormatter.SetHashAlgorithm(nameof(SHA256));

                        signedHash = rsaFormatter.CreateSignature(hash);

                    }
                }
            }
            catch (Exception ex)
            {
                return new byte[0];
            }

            return signedHash;

        }



        [HttpPost]
        [Route("sign-message")]
        public byte[] SignMessage(string message)
        {
            
            byte[] signedHash;
            try
            {
                using (SHA256 alg = SHA256.Create())
                {
                    byte[] data = Encoding.ASCII.GetBytes(message);
                    byte[] hash = alg.ComputeHash(data);
                    using (RSA rsa = RSA.Create())
                    {
                        sharedParameters = rsa.ExportParameters(false);

                        RSAPKCS1SignatureFormatter rsaFormatter = new(rsa);
                        rsaFormatter.SetHashAlgorithm(nameof(SHA256));

                        signedHash = rsaFormatter.CreateSignature(hash);

                    }
                }
            }
            catch(Exception ex)
            {
                return new byte[0];
            }


            return signedHash;
        }

        [HttpGet]
        [Route("get-public-key")]
        public string GetPublicKey()
        {
            string result = "";
            using (RSA rsa = RSA.Create())
            {
                result = MakePem(rsa.ExportSubjectPublicKeyInfo(), "PUBLIC KEY");
            }
            return result;
        }

        [HttpPost]
        [Route("verify-sign")]
        public string VerifySign(string message)
        {
            string signedHash = HttpContext.Request.Form["signedHash"];
            byte[] signedMessage = Convert.FromBase64String(signedHash);


            using (SHA256 alg = SHA256.Create())
            {
                using (RSA rsa = RSA.Create())
                {
                    
                    rsa.ImportParameters(sharedParameters);
                    byte[] data = Encoding.ASCII.GetBytes(message);
                    byte[] hash = alg.ComputeHash(data);
                    RSAPKCS1SignatureDeformatter rsaDeformatter = new(rsa);
                    rsaDeformatter.SetHashAlgorithm(nameof(SHA256));

                    if (rsaDeformatter.VerifySignature(hash, signedMessage))
                    {
                        return "The signature is valid.";
                    }
                    else
                    {
                        return "The signature is not valid.";
                    }
                }
            }
        }

        [HttpPost]
        [Route("verify-sign-with-public")]
        public string VerifySignUsingPublicKey(string message)
        {
            string pem = HttpContext.Request.Form["pemKey"];
            string signedHash = HttpContext.Request.Form["signedHash"];
            byte[] signedMessage = Convert.FromBase64String(signedHash);
            String publicKeyPEM = pem.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "");
            byte[] encoded = Convert.FromBase64String(publicKeyPEM);
            X509Certificate2 certificate = new X509Certificate2(encoded);


            using (SHA256 alg = SHA256.Create())
            {
                using (RSA rsa = certificate.GetRSAPublicKey())
                {

                    rsa.ImportParameters(sharedParameters);
                    byte[] data = Encoding.ASCII.GetBytes(message);
                    byte[] hash = alg.ComputeHash(data);
                    RSAPKCS1SignatureDeformatter rsaDeformatter = new(rsa);
                    rsaDeformatter.SetHashAlgorithm(nameof(SHA256));

                    if (rsaDeformatter.VerifySignature(hash, signedMessage))
                    {
                        return "The signature is valid.";
                    }
                    else
                    {
                        return "The signature is not valid.";
                    }
                }
            }
        }


    }
}
