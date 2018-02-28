using System;
using System.Security.Policy;
using System.Text;
using System.Web;

using Newtonsoft.Json.Linq;



using System.Threading.Tasks;
using Ripple.Core.Crypto.Sjcljson;
using Ripple.Core.Tests.Unit.Crypto.SjclJson;
using System.IO;
using System.Collections.Generic;
using System.Threading;

namespace CrackRipple
{

    class Program
    {

        static string fixture_old = "";
        static void Main(string[] args)
        {

            JSONEncryptTest test = new JSONEncryptTest();
            int i = 1;
            System.Diagnostics.Stopwatch watch = new System.Diagnostics.Stopwatch();
            watch.Start();
            while (i-- > 0)
            {
                //test.testDecryption();
                test.myDecryption();
            }
            watch.Stop();  //停止监视
            TimeSpan timespan = watch.Elapsed;  //获取当前实例测量得出的总时间
            Console.WriteLine("打开窗口代码执行时间：(秒)" + timespan.TotalMilliseconds / 1000);  //总毫秒数


            //创建密码字典 关系：
            fixture_old = "{\"key\" : \"12|qwe949461747\",   \"raw\":{\"masterkey\":\"shPLmjWXmhpiFd7AFhh2rAmQTVLMj\",\"account_id\":\"r9us1jJnvg9LK9wF1DTUWJc4qpp7GVENm8\",\"contacts\":[],\"created\":\"2017-08-23T19:01:44.475Z\"},"
                + "\"encrypted\":{\"iv\":\"K0RLqbaVHsUNCEw3B4upNQ==\"," + "\"v\":1," + "\"iter\":1000,"
                + "\"ks\":256," + "\"ts\":64," + "\"mode\":\"ccm\"," + "\"adata\":\"\","
                + "\"cipher\":\"aes\"," + "\"salt\":\"5prWye2f3LM=\","
                + "\"ct\":\"451CMPdT6yvkw2sCXNdl1sHIbeVtAE0eqB9iPkIJlhIFs79JNlF/58tQKagF/60sqqap/7XH4S4gCjARWVh9Dglu3243Lo3MsqJHjRtLNs6h8FZFTrOlbuIwR9Lb9hblXYgyD3DxS6GlbfmBTLLKYhu56QLFNKcA0NCuyesSAr/pNl3O1KBMs7lSDkLXpitDDQxzvQ60v+aTAg==\"}}";

            if (File.Exists("./wallet.txt"))
            {

                fixture_old = File.ReadAllText("./wallet.txt");
                byte[] bpath = Convert.FromBase64String(fixture_old);
                fixture_old = System.Text.ASCIIEncoding.Default.GetString(bpath).Replace("\n", "").Replace(" ", "").Replace("\t", "").Replace("\r", "");

            }
            else
            {
                Console.WriteLine("正在以默认的加密字符串生成字典，不匹配会导致程序崩溃");
            }

            DirectoryInfo TheFolder = new DirectoryInfo("./pass");

            if (!TheFolder.Exists)
            {
                Console.WriteLine("请在程序当前目录创建pass文件夹，并把字典放进目录里面");
                return;
            }


            int join_count = 1;
            foreach (FileInfo NextFile in TheFolder.GetFiles())
            {
                Thread my_thread = new Thread(new ParameterizedThreadStart(MYThread_Parall));
                my_thread.Start(NextFile);

                if (join_count++ % 10 == 0)
                {
                    my_thread.Join();
                }


                if (false)
                {
                    if (NextFile.Name.Contains("txt"))
                    {
                        string[] all_pass = File.ReadAllLines(NextFile.FullName);


                        JObject parsed = JObject.Parse(fixture_old),
                    raw = parsed.GetValue("raw").ToObject<JObject>(),
                    encrypted = parsed.GetValue("encrypted").ToObject<JObject>();
                        int ks = 256, iter = 1000, ts = 64;

                        JsonEncrypt jsonEncrypt = new JsonEncrypt(ks, iter, ts);

                        //string key = "12|qwe949461747";

                        List<string> base64_pass = new List<string>();

                        foreach (string pass in all_pass)
                        {
                            Org.BouncyCastle.Crypto.Parameters.KeyParameter new_key = jsonEncrypt.CreateKey(pass.Length + "|" + pass, encrypted);
                            System.Text.Encoding encode = System.Text.Encoding.ASCII;
                            // string strPath = Convert.ToBase64String(new_key.GetKey());
                            base64_pass.Add(pass.Length + "|" + pass + "#" + Convert.ToBase64String(new_key.GetKey()));
                        }

                        string base64_pass_dir = "./base64_pass/";
                        if (!Directory.Exists(base64_pass_dir))
                        {
                            Directory.CreateDirectory(base64_pass_dir);
                        }

                        File.WriteAllLines(base64_pass_dir + NextFile.Name, base64_pass);

                    }

                }


            }

            Console.WriteLine("程序执行完毕，请检查目录中是否生成新的文件");
            Console.ReadKey();

        }



        static void MYThread(object obj)
        {

            FileInfo NextFile = (FileInfo)obj;
            if (NextFile.Name.Contains("txt"))
            {
                string[] all_pass = File.ReadAllLines(NextFile.FullName);


                JObject encrypted = JObject.Parse(fixture_old);
                int ks = 256, iter = 1000, ts = 64;

                JsonEncrypt jsonEncrypt = new JsonEncrypt(ks, iter, ts);

                //string key = "12|qwe949461747";

                List<string> base64_pass = new List<string>();

                foreach (string pass in all_pass)
                {
                    Org.BouncyCastle.Crypto.Parameters.KeyParameter new_key = jsonEncrypt.CreateKey(pass.Length + "|" + pass, encrypted);
                    System.Text.Encoding encode = System.Text.Encoding.ASCII;
                    // string strPath = Convert.ToBase64String(new_key.GetKey());
                    base64_pass.Add(pass.Length + "|" + pass + "#" + Convert.ToBase64String(new_key.GetKey()));
                }

                string base64_pass_dir = "./base64_pass/";
                if (!Directory.Exists(base64_pass_dir))
                {
                    Directory.CreateDirectory(base64_pass_dir);
                }

                File.WriteAllLines(base64_pass_dir + NextFile.Name, base64_pass);

            }



        }

        static void MYThread_Parall(object obj)
        {

            FileInfo NextFile = (FileInfo)obj;
            if (NextFile.Name.Contains("txt"))
            {
                string[] all_pass = File.ReadAllLines(NextFile.FullName);


                JObject encrypted = JObject.Parse(fixture_old);
               
                int ks = 256, iter = 1000, ts = 64;

                JsonEncrypt jsonEncrypt = new JsonEncrypt(ks, iter, ts);

                //string key = "12|qwe949461747";

                List<string> base64_pass = new List<string>();

                Parallel.For(0, all_pass.Length, (i) =>
                 {
                     Org.BouncyCastle.Crypto.Parameters.KeyParameter new_key = jsonEncrypt.CreateKey(all_pass[i].Length + "|" + all_pass[i], encrypted);
                     System.Text.Encoding encode = System.Text.Encoding.ASCII;
                     // string strPath = Convert.ToBase64String(new_key.GetKey());
                     base64_pass.Add(all_pass[i].Length + "|" + all_pass[i] + "#" + Convert.ToBase64String(new_key.GetKey()));
                     Console.WriteLine(encrypted["salt"] + ":" + Convert.ToBase64String(new_key.GetKey()));
                 });
                
                string base64_pass_dir = "./base64_pass/";
                if (!Directory.Exists(base64_pass_dir))
                {
                    Directory.CreateDirectory(base64_pass_dir);
                }

                File.WriteAllLines(base64_pass_dir + NextFile.Name, base64_pass);

            }
        }

    }
}
