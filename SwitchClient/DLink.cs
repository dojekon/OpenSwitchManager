using System;
using System.Net.Http.Json;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;


namespace SwitchClient {
    public class DLink {
        private string? Name;
        private readonly string IP;
        private readonly string Username;
        private readonly string Password;
        private string? AccessToken;
        public DLink(string ip, string username, string password) {
            this.IP = ip;
            this.Username = username;
            this.Password = password;

        }
        public async Task<bool> Auth() {
            string? sequence0 = null;
            string? remote = null;

            string loginJsUrl = $"http://{this.IP}/DataStore/login.js";
            string loginPostUrl = $"http://{this.IP}/form/Login";
            string referer = $"http://{this.IP}/www/login.html";

            using (var client = new HttpClient()) {
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");
                client.DefaultRequestHeaders.Add("Referer", referer);
                client.DefaultRequestHeaders.Add("Accept", "*/*");
                client.DefaultRequestHeaders.Add("Accept-Language", "ru,en;q=0.9,cy;q=0.8");
                client.DefaultRequestHeaders.Add("DNT", "1");

                var response = await client.GetStringAsync(loginJsUrl);

                if (String.IsNullOrEmpty(response)) { throw new ArgumentNullException("Incorrect server response while getting sequence"); }

                var seqMatch = Regex.Match(response, @"sequence='([^']+)'");
                var remMatch = Regex.Match(response, @"remote='([^']+)'");

                if (!seqMatch.Success || !remMatch.Success) {
                    throw new Exception("Error while getting sequence or remote from server response");
                }

                sequence0 = seqMatch.Groups[1].Value;
                remote = remMatch.Groups[1].Value;
            }

            string[] sequence = GetEncriptedRasswordSequence(sequence0 , remote);

            string postData = $"sequence0={Uri.EscapeDataString(sequence[0])}" +
                              $"&sequence1={Uri.EscapeDataString(sequence[1])}" +
                              $"&sequence2={Uri.EscapeDataString(sequence[2])}" +
                              $"&sequence3={Uri.EscapeDataString(sequence[3])}" +
                              $"&pn={this.Username}&btnLogin=Login";

            using (var handler = new HttpClientHandler { UseCookies = false, AllowAutoRedirect = false })
            using (var client = new HttpClient(handler)) {
                client.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0");
                client.DefaultRequestHeaders.Add("Referer", loginPostUrl);
                client.DefaultRequestHeaders.Add("Origin", $"http://{this.IP}");

                var content = new StringContent(postData, Encoding.UTF8, "application/x-www-form-urlencoded");
                var response = await client.PostAsync(loginPostUrl, content);

                if (response.StatusCode == System.Net.HttpStatusCode.RedirectMethod && !String.IsNullOrEmpty(response.Headers.Location?.ToString())) {
                    var location = response.Headers.Location.ToString();
                    this.AccessToken = string.Join(String.Empty, location.Split('?').Skip(1)).Split('=')[1];
                    return true;
                } else {
                    var responseBody = await response.Content.ReadAsStringAsync();
                    throw new Exception("Invalid HTTP response");
                }
            }
        }
        private string[] GetEncriptedRasswordSequence(string sequence, string remote) {
            ArgumentValidator.ValidateNotNullOrEmpty(
                (nameof(sequence), sequence),
                (nameof(remote), remote)
                );
            string[] seq = new string[4];
            seq[0] = sequence;
            switch (remote) {
                case "0": {
                        using var sha256 = SHA256.Create();
                        using var sha1 = SHA1.Create();
                        using var md5 = MD5.Create();

                        seq[1] = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(this.Password))) + sequence)));
                        seq[2] = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToBase64String(sha1.ComputeHash(Encoding.UTF8.GetBytes(this.Password))) + sequence)));
                        seq[3] = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(this.Password))) + sequence)));

                        break;
                    }
                case "1": {
                        byte[] key = Convert.FromBase64String(sequence);
                        byte[] iv = Encoding.UTF8.GetBytes("0123456789abcdef");
                        byte[] encrypted;

                        using var sha256 = SHA256.Create();
                        using var sha1 = SHA1.Create();
                        using var md5 = MD5.Create();

                        using (var aes = Aes.Create()) {
                            aes.Mode = CipherMode.CBC;
                            aes.Padding = PaddingMode.PKCS7;
                            aes.Key = key;
                            aes.IV = iv;

                            using var encryptor = aes.CreateEncryptor();
                            byte[] plainText = Encoding.UTF8.GetBytes(this.Password);
                            encrypted = encryptor.TransformFinalBlock(plainText, 0, plainText.Length);
                        }

                        seq[1] = Convert.ToBase64String(encrypted);
                        seq[2] = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToBase64String(sha1.ComputeHash(Encoding.UTF8.GetBytes(this.Password))) + sequence)));
                        seq[3] = Convert.ToBase64String(sha256.ComputeHash(Encoding.UTF8.GetBytes(Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(this.Password))) + sequence)));

                        break;
                    }
                default:
                    throw new ArgumentException("Argument remote: Invalid value - " + remote);
            }
            return seq;
        }
    }
}
