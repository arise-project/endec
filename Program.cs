using System.CommandLine;
using System.CommandLine.Invocation;
using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace endec
{
    class Program
    {
        static string sva;

        //RQ-4 Global Hawk
        static Program()
        {
            sva = Environment.GetEnvironmentVariable("GOOGLE_DEFAULT_CLIENT_ID");
        }

        //dotnet run --lang en --file 
        static int Main(string[] args)
        {
            var rootCommand = new RootCommand
            {
                new Option<string>(
                    "--lang",
                    description: "Specify the Consumer id"),
                new Option<string>(
                    "--file",
                    "Specify Order number \n")
            };

            rootCommand.Description = "Console App to execute consumer commands for given Ids and generates reports with their Order Ids";
            rootCommand.Handler = CommandHandler.Create<string, string>(Execute);
            return rootCommand.InvokeAsync(args).Result;
        }

        static public void Execute(string lang, string file)
        {
            if (lang == "en")
            {
                var t = File.ReadAllText(file);
                var c = Enc(t, sva);
                File.WriteAllText(file, c);
            }
            else if (lang == "de")
            {
                var c = File.ReadAllText(file);
                var t = Dec(c, sva);
                Console.WriteLine(t);
            }
        }

        public static string Enc(string text, string keyString)
        {
            var key = Encoding.UTF8.GetBytes(keyString)[0..16];
            Console.WriteLine("len:" + key.Length);

            using (var aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.Zeros;

                KeySizes[] ks = aesAlg.LegalKeySizes;
                foreach (KeySizes k in ks)
                {
                    Console.WriteLine("\tLegal min key size = " + k.MinSize);
                    Console.WriteLine("\tLegal max key size = " + k.MaxSize);
                }

                using (var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }

                        var iv = aesAlg.IV;

                        var decryptedContent = msEncrypt.ToArray();

                        var result = new byte[iv.Length + decryptedContent.Length];

                        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                        Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

                        return Convert.ToBase64String(result);
                    }
                }
            }
        }

        public static string Dec(string cipherText, string keyString)
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            var iv = new byte[16];
            var cipher = new byte[16];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, iv.Length);
            var key = Encoding.UTF8.GetBytes(keyString)[0..16];

            using (var aesAlg = Aes.Create())
            {
                aesAlg.Padding = PaddingMode.Zeros;
                using (var decryptor = aesAlg.CreateDecryptor(key, iv))
                {
                    string result;
                    using (var msDecrypt = new MemoryStream(cipher))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                    return result;
                }
            }
        }
    }
}
