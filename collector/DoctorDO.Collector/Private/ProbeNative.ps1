#Requires -Version 5.1
# Native probe helper. Compiled once per session with Add-Type (C# 5 syntax so Windows PowerShell 5.1's compiler accepts
# it), and only in Full Language mode: Constrained Language Mode and application control (WDAC, AppLocker) refuse run-time
# compilation, and every caller then records the check as not collected. Every probe runs on its own thread with a hard
# timeout and returns a result object; none writes anything, downloads a payload, or sends credentials.
#   EndpointProbe.Run   - one endpoint row: DNS, TCP per port, a TLS handshake, HEAD, a byte range (below); also the peer
#                         probes (TCP 7680 to a peer, nothing else)
#   EndpointProbe.Fetch - one GET with normal certificate validation (the DO geo service, a PAC, the public IP probe)
#   WinHttpProxy        - the proxy WinHTTP would choose for a URL
# The TLS callback ACCEPTS any certificate on purpose: the point is to OBSERVE who issued it (TLS inspection detection), not
# to trust it. No data is exchanged on that connection.

Set-StrictMode -Version Latest

# Endpoint health (docs/07, Data/endpoints.json). One row = one host of the manifest, its stages run in order on one
# thread: DNS, TCP to each documented port, a TLS handshake (HTTPS ports), one HTTP request (HEAD /, or the documented
# probe path), and one byte-range request (Range: bytes=0-0) for a file the device itself downloaded. Rows run in
# parallel, at most MaxConcurrency at a time, inside a total budget. Through a proxy when WinHTTP would use one: CONNECT
# for HTTPS, an absolute-form request for HTTP; then a direct TCP connect to compare. Response bodies are never read: the
# status line and headers are read, then the connection is closed. The TLS callback records the certificate verdict and
# ACCEPTS the certificate, because no data is sent on that connection and the point is to observe, not to trust.
$script:DDEndpointSource = @'
#pragma warning disable 0618, 0612
namespace DoctorDO.Net
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.IO;
    using System.Net;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Runtime.InteropServices;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public class EndpointRowSpec
    {
        public string Tag;
        public string Host;
        public int[] Ports;
        public string[] Protocols;      // per port: http | https | udp (tcp: a plain connect, the peer probes)
        public bool Tls;                // handshake on the first https port
        public bool Http;               // HEAD / on the first http port (or https when there is no http port)
        public string RangeUrl;         // full URL (in memory only); GET with Range: bytes=0-0
        public string VerifyUrl;        // Connected Cache verification: one GET without a range; status line and headers only
        public string Proxy;            // host:port, or null for direct
        public bool WantAddresses;
    }

    public class PortOutcome
    {
        public int Port;
        public bool Ok;
        public bool TimedOut;
        public double Ms;
        public string Error;
        public bool ViaProxy;
        public int ProxyStatus;
        public bool ProxyOnly;          // an HTTP port through a proxy: the connection reached the proxy, not the host
    }

    public class EndpointOutcome
    {
        public string Tag;
        public string Host;
        public bool DnsAttempted; public bool DnsOk; public double DnsMs; public string DnsError; public string DnsTypes = ""; public string Addresses = "";
        public PortOutcome[] Ports = new PortOutcome[0];
        public bool TlsAttempted; public bool TlsHandshake; public double TlsMs; public string TlsError; public string TlsProtocol;
        public bool CertSeen; public string Issuer; public bool ChainMicrosoft; public bool NameOk; public bool ChainOk; public string PolicyErrors;
        public bool HttpAttempted; public int HttpStatus; public double HttpMs; public string HttpError; public bool HttpVia;
        public bool RangeAttempted; public int RangeStatus; public double RangeMs; public string RangeError; public string ContentRange; public string AcceptRanges;
        public long RangeContentLength = -1;
        public bool VerifyAttempted; public int VerifyStatus; public double VerifyMs; public string VerifyError; public string VerifyContentType;
        public long VerifyContentLength = -1;
        public bool ProxyUsed; public int ProxyStatus; public string ProxyError;
        public bool DirectAttempted; public bool DirectOk; public double DirectMs; public string DirectError;
        public bool TimedOut;
    }

    public class HttpFetchOutcome
    {
        public bool Attempted; public bool TimedOut; public string Error; public double Ms;
        public int Status; public string ContentType; public long ContentLength = -1; public bool Redirected;
        public bool CertSeen; public bool ChainOk; public bool NameOk; public bool ChainMicrosoft; public string Issuer;
        public bool ProxyUsed; public int ProxyStatus;
        public byte[] Body; public bool BodyTruncated; public bool BodyIncomplete;
    }

    public static class EndpointProbe
    {
        public const string UserAgent = "DoctorDO-Collector (endpoint health check)";

        static double Ms(Stopwatch sw) { return Math.Round(sw.Elapsed.TotalMilliseconds, 1); }

        static string Unwrap(Exception ex)
        {
            AggregateException ae = ex as AggregateException;
            while (ae != null && ae.InnerException != null) { ex = ae.InnerException; ae = ex as AggregateException; }
            // A read or write on a socket stream fails as an IOException around the SocketException: name the socket error,
            // which does not depend on the display language.
            SocketException se = ex as SocketException;
            if (se == null && ex is IOException) se = ex.InnerException as SocketException;
            if (se != null) return "SocketException " + se.SocketErrorCode.ToString();
            string m = ex.Message ?? "";
            if (m.Length > 160) m = m.Substring(0, 160);
            return ex.GetType().Name + ": " + m;
        }

        // A time-out: the probe's own (TimeoutException) or a socket read or write that hit its ReadTimeout / WriteTimeout.
        // A reset, a refusal or an answer that is not HTTP is a failure, not a time-out.
        static bool IsTimeout(Exception ex)
        {
            AggregateException ae = ex as AggregateException;
            while (ae != null && ae.InnerException != null) { ex = ae.InnerException; ae = ex as AggregateException; }
            if (ex is TimeoutException) return true;
            SocketException se = ex as SocketException;
            if (se == null && ex is IOException) se = ex.InnerException as SocketException;
            return se != null && se.SocketErrorCode == SocketError.TimedOut;
        }

        static TcpClient Connect(string host, int port, int timeoutMs, out string error, out bool timedOut)
        {
            error = null; timedOut = false;
            TcpClient c = new TcpClient();
            try
            {
                Task t = c.ConnectAsync(host, port);
                if (!t.Wait(timeoutMs)) { timedOut = true; error = "timeout"; c.Close(); return null; }
                if (!c.Connected) { error = "not connected"; c.Close(); return null; }
                c.ReceiveTimeout = timeoutMs; c.SendTimeout = timeoutMs;
                return c;
            }
            catch (Exception ex) { error = Unwrap(ex); try { c.Close(); } catch (Exception) { } return null; }
        }

        static void ParseProxy(string proxy, out string ph, out int pp)
        {
            ph = proxy; pp = 80;
            int i = proxy.LastIndexOf(':');
            if (i > 0 && proxy.IndexOf(']') < i) { int.TryParse(proxy.Substring(i + 1), out pp); ph = proxy.Substring(0, i); }
            ph = ph.Trim('[', ']');
        }

        // Reads the status line and headers (at most 16 KB), never the body.
        static int ReadHead(Stream s, Dictionary<string, string> headers, int timeoutMs)
        {
            byte[] buf = new byte[1];
            StringBuilder sb = new StringBuilder();
            Stopwatch sw = Stopwatch.StartNew();
            while (sb.Length < 16384)
            {
                if (sw.ElapsedMilliseconds > timeoutMs) throw new TimeoutException("response header timeout");
                int n = s.Read(buf, 0, 1);
                if (n <= 0) break;
                sb.Append((char)buf[0]);
                if (sb.Length >= 4 && sb[sb.Length - 1] == '\n' && sb[sb.Length - 2] == '\r' && sb[sb.Length - 3] == '\n' && sb[sb.Length - 4] == '\r') break;
            }
            string[] lines = sb.ToString().Split(new string[] { "\r\n" }, StringSplitOptions.None);
            if (lines.Length == 0 || !lines[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase)) throw new IOException("no HTTP status line");
            string[] parts = lines[0].Split(' ');
            int status = 0;
            if (parts.Length < 2 || !int.TryParse(parts[1], out status)) throw new IOException("malformed HTTP status line");
            for (int i = 1; i < lines.Length; i++)
            {
                int c = lines[i].IndexOf(':');
                if (c > 0) headers[lines[i].Substring(0, c).Trim().ToLowerInvariant()] = lines[i].Substring(c + 1).Trim();
            }
            return status;
        }

        static void Write(Stream s, string text)
        {
            byte[] b = Encoding.ASCII.GetBytes(text);
            s.Write(b, 0, b.Length); s.Flush();
        }

        static long ParseLength(string v)
        {
            long n;
            return long.TryParse((v ?? "").Trim(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out n) ? n : -1;
        }

        // Reads at most maxBytes of a response body: chunked, by Content-Length, or until the server closes. incomplete: the
        // server closed before the body it announced (Content-Length, or the last chunk) had arrived.
        static byte[] ReadBody(Stream s, Dictionary<string, string> headers, int maxBytes, int timeoutMs, out bool truncated, out bool incomplete)
        {
            truncated = false; incomplete = false;
            MemoryStream ms = new MemoryStream();
            Stopwatch sw = Stopwatch.StartNew();
            string te;
            bool chunked = headers.TryGetValue("transfer-encoding", out te) && te.IndexOf("chunked", StringComparison.OrdinalIgnoreCase) >= 0;
            byte[] buf = new byte[4096];
            if (chunked)
            {
                while (true)
                {
                    StringBuilder line = new StringBuilder();
                    while (line.Length < 64)
                    {
                        if (sw.ElapsedMilliseconds > timeoutMs) throw new TimeoutException("response body timeout");
                        int c = s.ReadByte();
                        if (c < 0) { incomplete = true; return ms.ToArray(); }
                        if (c == '\n') break;
                        if (c != '\r') line.Append((char)c);
                    }
                    string hex = line.ToString().Split(';')[0].Trim();
                    int size;
                    if (!int.TryParse(hex, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out size) || size < 0) { incomplete = true; return ms.ToArray(); }
                    if (size == 0) return ms.ToArray();   // the last chunk
                    int left = size;
                    while (left > 0)
                    {
                        if (sw.ElapsedMilliseconds > timeoutMs) throw new TimeoutException("response body timeout");
                        int n = s.Read(buf, 0, Math.Min(buf.Length, left));
                        if (n <= 0) { incomplete = true; return ms.ToArray(); }
                        left -= n;
                        int keep = (int)Math.Min(n, Math.Max(0, maxBytes - ms.Length));
                        ms.Write(buf, 0, keep);
                        if (keep < n) { truncated = true; return ms.ToArray(); }
                    }
                    s.ReadByte(); s.ReadByte(); // CRLF after the chunk
                }
            }
            string cl;
            long length = headers.TryGetValue("content-length", out cl) ? ParseLength(cl) : -1;
            long want = length >= 0 ? Math.Min(length, maxBytes) : maxBytes;
            if (length > maxBytes) truncated = true;
            while (ms.Length < want)
            {
                if (sw.ElapsedMilliseconds > timeoutMs) throw new TimeoutException("response body timeout");
                int n = s.Read(buf, 0, (int)Math.Min(buf.Length, want - ms.Length));
                if (n <= 0) { if (length >= 0) incomplete = true; break; }
                ms.Write(buf, 0, n);
            }
            if (length < 0 && ms.Length >= maxBytes) truncated = true;
            return ms.ToArray();
        }

        // One GET through the proxy WinHTTP would use, with the server certificate validated as normal (chain and name).
        // The body is read only when the caller asks and the response is what it expects (readBodyFor: a content-type
        // prefix such as "text/json"; "" is any type, or none); otherwise only the status line and headers are read. A
        // body cut short (the server closed before its Content-Length or its last chunk) is not returned: BodyIncomplete.
        // Redirects are not followed. Bounded: each stage (connect, CONNECT, handshake, headers, body) by timeoutMs, so
        // the whole request by about six times timeoutMs. Nothing is sent but the request.
        public static HttpFetchOutcome Fetch(string url, string proxy, int timeoutMs, int maxBody, string[] readBodyFor)
        {
            HttpFetchOutcome f = new HttpFetchOutcome();
            if (string.IsNullOrEmpty(proxy)) proxy = null;
            Stopwatch sw = Stopwatch.StartNew();
            TcpClient client = null;
            try
            {
                Uri u = new Uri(url);
                bool https = u.Scheme == "https";
                int ps; string err; bool to;
                Stream s = Open(u.DnsSafeHost, u.Port, proxy, https, timeoutMs, out client, out ps, out err, out to);
                f.Attempted = true;
                f.ProxyUsed = proxy != null; f.ProxyStatus = ps;
                if (s == null) { f.Error = err ?? "connect failed"; f.TimedOut = to; f.Ms = Ms(sw); return f; }
                Stream st = s;
                if (https)
                {
                    EndpointOutcome cert = new EndpointOutcome();
                    st = Handshake(s, u.DnsSafeHost, timeoutMs, cert, true);
                    f.CertSeen = cert.CertSeen; f.ChainOk = cert.ChainOk; f.NameOk = cert.NameOk; f.ChainMicrosoft = cert.ChainMicrosoft; f.Issuer = cert.Issuer;
                }
                st.ReadTimeout = timeoutMs; st.WriteTimeout = timeoutMs;
                string target = (proxy != null && !https) ? u.GetLeftPart(UriPartial.Query) : u.PathAndQuery;
                Write(st, "GET " + target + " HTTP/1.1\r\nHost: " + (u.IsDefaultPort ? u.DnsSafeHost : u.DnsSafeHost + ":" + u.Port) + "\r\nUser-Agent: " + UserAgent + "\r\nAccept: */*\r\nConnection: close\r\n\r\n");
                Dictionary<string, string> h = new Dictionary<string, string>();
                f.Status = ReadHead(st, h, timeoutMs);
                string v;
                if (h.TryGetValue("content-type", out v)) f.ContentType = v.Length > 64 ? v.Substring(0, 64) : v;
                if (h.TryGetValue("content-length", out v)) f.ContentLength = ParseLength(v);
                if (h.TryGetValue("location", out v)) f.Redirected = true;
                bool want = false;
                if (f.Status == 200 && readBodyFor != null)
                    foreach (string p in readBodyFor)
                        if (p == null || p.Length == 0 || (f.ContentType != null && f.ContentType.StartsWith(p, StringComparison.OrdinalIgnoreCase))) want = true;
                // Under normal validation only: a body from a certificate that does not validate is not read.
                if (want && (!https || (f.ChainOk && f.NameOk)))
                {
                    bool cut, shortBody;
                    byte[] body = ReadBody(st, h, maxBody, timeoutMs, out cut, out shortBody);
                    f.BodyTruncated = cut; f.BodyIncomplete = shortBody;
                    if (shortBody) f.Error = "the server closed the connection before the whole body arrived";
                    else f.Body = body;
                }
            }
            catch (Exception ex) { f.Error = Unwrap(ex); f.TimedOut = IsTimeout(ex); }
            finally { if (client != null) try { client.Close(); } catch (Exception) { } }
            f.Ms = Ms(sw);
            return f;
        }

        // A stream to host:port, direct or through the proxy (CONNECT when tunnel is true). proxyStatus is the CONNECT answer.
        static Stream Open(string host, int port, string proxy, bool tunnel, int timeoutMs, out TcpClient client, out int proxyStatus, out string error, out bool timedOut)
        {
            proxyStatus = 0; client = null;
            if (proxy == null)
            {
                client = Connect(host, port, timeoutMs, out error, out timedOut);
                return client == null ? null : client.GetStream();
            }
            string ph; int pp; ParseProxy(proxy, out ph, out pp);
            client = Connect(ph, pp, timeoutMs, out error, out timedOut);
            if (client == null) { error = "proxy " + error; return null; }
            NetworkStream ns = client.GetStream();
            ns.ReadTimeout = timeoutMs; ns.WriteTimeout = timeoutMs;
            if (!tunnel) return ns;
            try
            {
                Write(ns, "CONNECT " + host + ":" + port + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\nUser-Agent: " + UserAgent + "\r\n\r\n");
                Dictionary<string, string> h = new Dictionary<string, string>();
                proxyStatus = ReadHead(ns, h, timeoutMs);
                if (proxyStatus == 200) return ns;
                error = "proxy answered " + proxyStatus + " to CONNECT";
            }
            // Only a time-out is a time-out: a proxy that resets the connection or answers with something that is not HTTP
            // has refused, which is a different finding from a black hole.
            catch (Exception ex) { error = "proxy CONNECT " + Unwrap(ex); timedOut = IsTimeout(ex); }
            try { client.Close(); } catch (Exception) { }
            client = null;
            return null;
        }

        // Public roots that cross-sign Microsoft's own certification authorities (Microsoft TLS RSA Root G2 and the Microsoft
        // Azure TLS issuing CAs chain to them), by SHA-1 thumbprint: DigiCert Global Root CA, G2 and G3 (read from a
        // Windows 11 root store and from the chains the DO, Windows Update and Store endpoints served, 19 Oct 2026), and
        // Baltimore CyberTrust Root (its published thumbprint; expired May 2025, listed so an old chain is judged untrusted
        // rather than inspected).
        static readonly string[] CrossSigningRoots = {
            "A8985D3A65E5E5C4B2D7D66D40C6DD2FB19C5436", "DF3C24F9BFD666761B268073FE06D1CC8D4F82A4",
            "7E04DE896A3E666D00E687D33FFAD93BE83D349E", "D4DE20D05E66FC53FE1A50882C78DB2852CAE474" };

        // The first value of one attribute in a distinguished name as .NET writes it: CN=x, O="a, b", C=US.
        static string Rdn(string dn, string key)
        {
            int i = 0;
            while (i < dn.Length)
            {
                while (i < dn.Length && (dn[i] == ' ' || dn[i] == ',' || dn[i] == '+' || dn[i] == ';')) i++;
                int eq = dn.IndexOf('=', i);
                if (eq < 0) return null;
                string k = dn.Substring(i, eq - i).Trim();
                int j = eq + 1;
                StringBuilder v = new StringBuilder();
                if (j < dn.Length && dn[j] == '"')
                {
                    j++;
                    while (j < dn.Length)
                    {
                        if (dn[j] == '"') { if (j + 1 < dn.Length && dn[j + 1] == '"') { v.Append('"'); j += 2; continue; } j++; break; }
                        v.Append(dn[j]); j++;
                    }
                    while (j < dn.Length && dn[j] != ',' && dn[j] != '+' && dn[j] != ';') j++;
                }
                else
                {
                    while (j < dn.Length && dn[j] != ',' && dn[j] != '+' && dn[j] != ';') { v.Append(dn[j]); j++; }
                }
                if (string.Equals(k, key, StringComparison.OrdinalIgnoreCase)) return v.ToString().Trim();
                i = j;
            }
            return null;
        }

        // A Microsoft certification authority by name: O=Microsoft Corporation and a CN that starts with "Microsoft "
        // (Microsoft Azure RSA TLS Issuing CA 04, Microsoft ECC Content Distribution Secure Server CA 2.1, Microsoft Update
        // Secure Server CA 2.1, Microsoft TLS G2 RSA CA OCSP 04, ...).
        static bool IsMicrosoftCa(string dn)
        {
            if (string.IsNullOrEmpty(dn)) return false;
            string o = Rdn(dn, "O"), cn = Rdn(dn, "CN");
            return o != null && cn != null && string.Equals(o, "Microsoft Corporation", StringComparison.OrdinalIgnoreCase) && cn.StartsWith("Microsoft ", StringComparison.OrdinalIgnoreCase);
        }

        // Whether the certificate was issued by Microsoft, judged on the issuing chain only: the leaf's issuer and chain
        // elements 1 to n, never element 0's own subject, which a TLS-inspecting proxy controls and may copy from the
        // origin certificate (a genuine Microsoft leaf says O=Microsoft Corporation, and so can a substitute). A Microsoft
        // CA must issue the leaf or sit above its issuer, and the chain must end at a Microsoft root or at a public root
        // that cross-signs Microsoft's CAs: a substitute chain that only copies Microsoft's CA names, under the
        // inspector's own root, is not Microsoft's. Public for the tests, which build chains from throwaway certificates.
        public static bool IssuedByMicrosoft(X509Certificate cert, X509Chain chain)
        {
            if (cert == null) return false;
            bool named = IsMicrosoftCa(cert.Issuer);
            X509Certificate2 top = null;
            if (chain != null)
                for (int i = 1; i < chain.ChainElements.Count; i++)
                {
                    X509Certificate2 ca = chain.ChainElements[i].Certificate;
                    if (IsMicrosoftCa(ca.Subject)) named = true;
                    top = ca;
                }
            if (!named) return false;
            if (top == null) return true;   // no chain beyond the leaf: its issuer's name is all there is
            if (IsMicrosoftCa(top.Subject)) return true;
            return Array.IndexOf(CrossSigningRoots, (top.Thumbprint ?? "").ToUpperInvariant()) >= 0;
        }

        static SslStream Handshake(Stream inner, string host, int timeoutMs, EndpointOutcome o, bool record)
        {
            string issuer = null; bool msChain = false; SslPolicyErrors errs = SslPolicyErrors.None; bool seen = false;
            SslStream ssl = new SslStream(inner, false, delegate (object s, X509Certificate cert, X509Chain chain, SslPolicyErrors e)
            {
                errs = e;
                if (cert != null)
                {
                    seen = true; issuer = cert.Issuer;
                    msChain = IssuedByMicrosoft(cert, chain);
                }
                return true;
            });
            Task a = ssl.AuthenticateAsClientAsync(host, null, SslProtocols.Tls12, false);
            if (!a.Wait(timeoutMs)) { try { ssl.Close(); } catch (Exception) { } throw new TimeoutException("TLS handshake timeout"); }
            if (record)
            {
                o.TlsHandshake = true; o.TlsProtocol = ssl.SslProtocol.ToString();
                o.CertSeen = seen; o.Issuer = issuer; o.ChainMicrosoft = msChain; o.PolicyErrors = errs.ToString();
                o.NameOk = seen && (errs & SslPolicyErrors.RemoteCertificateNameMismatch) == 0;
                o.ChainOk = seen && (errs & SslPolicyErrors.RemoteCertificateChainErrors) == 0;
            }
            return ssl;
        }

        // One HTTP request; returns the status, or throws. The body is never read.
        static int Request(Uri u, string method, bool range, string proxy, int timeoutMs, EndpointOutcome o, Dictionary<string, string> headers)
        {
            bool https = u.Scheme == "https";
            int port = u.Port;
            TcpClient client; int ps; string err; bool to;
            Stream s = Open(u.DnsSafeHost, port, proxy, https, timeoutMs, out client, out ps, out err, out to);
            if (proxy != null) { o.ProxyUsed = true; if (ps != 0) o.ProxyStatus = ps; }
            if (s == null)
            {
                if (proxy != null && ps != 0 && ps != 200) return -ps;   // the proxy refused the tunnel: report its status
                throw new IOException(err ?? "connect failed");
            }
            try
            {
                Stream st = s;
                if (https) st = Handshake(s, u.DnsSafeHost, timeoutMs, o, false);
                st.ReadTimeout = timeoutMs; st.WriteTimeout = timeoutMs;
                string target = (proxy != null && !https) ? u.GetLeftPart(UriPartial.Query) : u.PathAndQuery;
                StringBuilder req = new StringBuilder();
                req.Append(method).Append(' ').Append(target).Append(" HTTP/1.1\r\n");
                req.Append("Host: ").Append(u.IsDefaultPort ? u.DnsSafeHost : u.DnsSafeHost + ":" + port).Append("\r\n");
                req.Append("User-Agent: ").Append(UserAgent).Append("\r\nAccept: */*\r\n");
                if (range) req.Append("Range: bytes=0-0\r\n");
                req.Append("Connection: close\r\n\r\n");
                Write(st, req.ToString());
                return ReadHead(st, headers, timeoutMs);
            }
            finally { try { client.Close(); } catch (Exception) { } }
        }

        public static EndpointOutcome Run(EndpointRowSpec r, int timeoutMs)
        {
            EndpointOutcome o = new EndpointOutcome(); o.Tag = r.Tag; o.Host = r.Host;
            // PowerShell hands $null to a string field as "": both mean "none".
            if (string.IsNullOrEmpty(r.Proxy)) r.Proxy = null;
            if (string.IsNullOrEmpty(r.RangeUrl)) r.RangeUrl = null;
            if (string.IsNullOrEmpty(r.VerifyUrl)) r.VerifyUrl = null;
            bool proxied = r.Proxy != null;
            Stopwatch sw;

            // DNS: record types, and addresses only where the caller asked (CDN and Connected Cache hosts).
            o.DnsAttempted = true; sw = Stopwatch.StartNew();
            try
            {
                Task<IPAddress[]> t = System.Net.Dns.GetHostAddressesAsync(r.Host);
                if (!t.Wait(timeoutMs)) o.DnsError = "timeout";
                else
                {
                    List<string> types = new List<string>(); List<string> addrs = new List<string>();
                    foreach (IPAddress ip in t.Result)
                    {
                        string ty = ip.AddressFamily == AddressFamily.InterNetworkV6 ? "AAAA" : "A";
                        if (!types.Contains(ty)) types.Add(ty);
                        if (r.WantAddresses && addrs.Count < 2) addrs.Add(ip.ToString());
                    }
                    types.Sort();
                    o.DnsOk = t.Result.Length > 0; o.DnsTypes = string.Join(",", types.ToArray()); o.Addresses = string.Join(",", addrs.ToArray());
                    if (!o.DnsOk) o.DnsError = "no addresses";
                }
            }
            catch (Exception ex) { o.DnsError = Unwrap(ex); }
            o.DnsMs = Ms(sw);
            // Without a proxy a name that does not resolve cannot be reached; with one, the proxy resolves it.
            if (!o.DnsOk && !proxied) return o;

            // TCP to every documented port (UDP ports cannot be confirmed by a connectionless probe and are skipped).
            List<PortOutcome> ports = new List<PortOutcome>();
            int firstHttps = -1, firstHttp = -1;
            for (int i = 0; i < r.Ports.Length; i++)
            {
                string proto = r.Protocols[i];
                if (proto == "udp") continue;
                if (proto == "https" && firstHttps < 0) firstHttps = r.Ports[i];
                if (proto == "http" && firstHttp < 0) firstHttp = r.Ports[i];
                PortOutcome p = new PortOutcome(); p.Port = r.Ports[i]; p.ViaProxy = proxied;
                sw = Stopwatch.StartNew();
                TcpClient c; int ps; string err; bool to;
                // Through a proxy: HTTPS ports are tested with CONNECT (the proxy reaches the host); HTTP ports by
                // connecting to the proxy only (ProxyOnly), and the HTTP request below shows whether the proxy reached the
                // host. CONNECT is not sent for an HTTP port: proxies commonly refuse CONNECT to any port but 443.
                Stream s = Open(r.Host, r.Ports[i], r.Proxy, proto == "https", timeoutMs, out c, out ps, out err, out to);
                p.Ms = Ms(sw); p.Ok = s != null; p.TimedOut = to; p.Error = err; p.ProxyStatus = ps;
                p.ProxyOnly = proxied && proto != "https" && s != null;
                if (proxied) { o.ProxyUsed = true; if (ps != 0) o.ProxyStatus = ps; if (!p.Ok && o.ProxyError == null) o.ProxyError = err; }
                if (c != null) try { c.Close(); } catch (Exception) { }
                ports.Add(p);
            }
            o.Ports = ports.ToArray();
            bool anyOk = false; foreach (PortOutcome p in ports) if (p.Ok) anyOk = true;

            // TLS: the handshake only; no request is sent on this connection.
            if (r.Tls && firstHttps > 0 && anyOk)
            {
                o.TlsAttempted = true; sw = Stopwatch.StartNew();
                TcpClient c = null; int ps; string err; bool to;
                try
                {
                    Stream s = Open(r.Host, firstHttps, r.Proxy, true, timeoutMs, out c, out ps, out err, out to);
                    if (s == null) o.TlsError = err ?? "connect failed";
                    else { SslStream ssl = Handshake(s, r.Host, timeoutMs, o, true); try { ssl.Close(); } catch (Exception) { } }
                }
                catch (Exception ex) { o.TlsError = Unwrap(ex); }
                finally { if (c != null) try { c.Close(); } catch (Exception) { } }
                o.TlsMs = Ms(sw);
            }

            // HTTP: any answer shows the endpoint (or the proxy) speaks HTTP on that port.
            if (r.Http && anyOk && (firstHttp > 0 || firstHttps > 0))
            {
                o.HttpAttempted = true; sw = Stopwatch.StartNew();
                Dictionary<string, string> h = new Dictionary<string, string>();
                try
                {
                    Uri u = firstHttp > 0 ? new Uri("http://" + r.Host + (firstHttp == 80 ? "" : ":" + firstHttp) + "/") : new Uri("https://" + r.Host + (firstHttps == 443 ? "" : ":" + firstHttps) + "/");
                    o.HttpStatus = Request(u, "HEAD", false, r.Proxy, timeoutMs, o, h);
                    o.HttpVia = h.ContainsKey("via");
                }
                catch (Exception ex) { o.HttpError = Unwrap(ex); }
                o.HttpMs = Ms(sw);
            }

            // Byte range: the smallest range of a file the device itself downloaded.
            if (r.RangeUrl != null && anyOk)
            {
                o.RangeAttempted = true; sw = Stopwatch.StartNew();
                Dictionary<string, string> h = new Dictionary<string, string>();
                try
                {
                    o.RangeStatus = Request(new Uri(r.RangeUrl), "GET", true, r.Proxy, timeoutMs, o, h);
                    string v;
                    if (h.TryGetValue("content-range", out v)) o.ContentRange = v.Length > 64 ? v.Substring(0, 64) : v;
                    if (h.TryGetValue("accept-ranges", out v)) o.AcceptRanges = v.Length > 32 ? v.Substring(0, 32) : v;
                    if (h.TryGetValue("content-length", out v)) o.RangeContentLength = ParseLength(v);
                    if (h.ContainsKey("via")) o.HttpVia = true;
                }
                catch (Exception ex) { o.RangeError = Unwrap(ex); }
                o.RangeMs = Ms(sw);
            }

            // Connected Cache verification (Microsoft's documented request): GET the object, read the status line and the
            // headers (Content-Type, Content-Length), then close. The body is never read.
            if (r.VerifyUrl != null && anyOk)
            {
                o.VerifyAttempted = true; sw = Stopwatch.StartNew();
                Dictionary<string, string> h = new Dictionary<string, string>();
                try
                {
                    o.VerifyStatus = Request(new Uri(r.VerifyUrl), "GET", false, r.Proxy, timeoutMs, o, h);
                    string v;
                    if (h.TryGetValue("content-type", out v)) o.VerifyContentType = v.Length > 64 ? v.Substring(0, 64) : v;
                    if (h.TryGetValue("content-length", out v)) o.VerifyContentLength = ParseLength(v);
                }
                catch (Exception ex) { o.VerifyError = Unwrap(ex); }
                o.VerifyMs = Ms(sw);
            }

            // With a proxy in the path: would a direct connection have worked? (TCP only, to the first port.)
            if (proxied && o.DnsOk && ports.Count > 0)
            {
                o.DirectAttempted = true; sw = Stopwatch.StartNew();
                string err; bool to;
                TcpClient c = Connect(r.Host, ports[0].Port, timeoutMs, out err, out to);
                o.DirectOk = c != null; o.DirectError = err;
                if (c != null) try { c.Close(); } catch (Exception) { }
                o.DirectMs = Ms(sw);
            }
            return o;
        }

        // Every row on its own thread, at most maxConcurrency at once, bounded by totalTimeoutMs overall.
        public static EndpointOutcome[] RunRows(EndpointRowSpec[] rows, int timeoutMs, int totalTimeoutMs, int maxConcurrency)
        {
            int n = rows.Length;
            EndpointOutcome[] results = new EndpointOutcome[n];
            Task[] tasks = new Task[n];
            SemaphoreSlim gate = new SemaphoreSlim(Math.Max(1, maxConcurrency));
            Stopwatch total = Stopwatch.StartNew();
            for (int i = 0; i < n; i++)
            {
                int idx = i;
                tasks[i] = Task.Factory.StartNew(delegate ()
                {
                    int left = (int)Math.Max(0, totalTimeoutMs - total.ElapsedMilliseconds);
                    if (!gate.Wait(left)) return;
                    try
                    {
                        if (total.ElapsedMilliseconds >= totalTimeoutMs) return;
                        try { results[idx] = Run(rows[idx], timeoutMs); }
                        catch (Exception ex) { EndpointOutcome o = new EndpointOutcome(); o.Tag = rows[idx].Tag; o.Host = rows[idx].Host; o.DnsError = Unwrap(ex); results[idx] = o; }
                    }
                    finally { gate.Release(); }
                }, TaskCreationOptions.LongRunning);
            }
            try { Task.WaitAll(tasks, totalTimeoutMs); } catch (AggregateException) { }
            for (int i = 0; i < n; i++)
            {
                if (results[i] == null)
                {
                    EndpointOutcome o = new EndpointOutcome(); o.Tag = rows[i].Tag; o.Host = rows[i].Host; o.TimedOut = true; results[i] = o;
                }
            }
            return results;
        }
    }

    public class ProxyDecision
    {
        public string Source = "none";   // none | netsh | wininet | pac | wpad | unresolved
        public string Proxy;             // host:port, or null for direct
        public string Error;
    }

    // The proxy WinHTTP would choose for a URL in the background context, as documented for Delivery Optimization with no
    // user signed in (NetworkService): a netsh winhttp proxy wins; otherwise the WinINET configuration (auto-detect, PAC,
    // static) of the account running the collector, which under SYSTEM is the device-wide one when ProxySettingsPerUser
    // is 0. A signed-in user's own proxy, which DoSvc uses for that user's downloads, is not modelled.
    public static class WinHttpProxy
    {
        [StructLayout(LayoutKind.Sequential)]
        struct ProxyInfo { public int AccessType; public IntPtr Proxy; public IntPtr Bypass; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct AutoProxyOptions { public int Flags; public int AutoDetectFlags; public string AutoConfigUrl; public IntPtr Reserved1; public int Reserved2; [MarshalAs(UnmanagedType.Bool)] public bool AutoLogon; }
        [StructLayout(LayoutKind.Sequential)]
        struct IeConfig { [MarshalAs(UnmanagedType.Bool)] public bool AutoDetect; public IntPtr AutoConfigUrl; public IntPtr Proxy; public IntPtr Bypass; }

        [DllImport("winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern IntPtr WinHttpOpen(string agent, int accessType, string proxy, string bypass, int flags);
        [DllImport("winhttp.dll", SetLastError = true)] static extern bool WinHttpCloseHandle(IntPtr h);
        [DllImport("winhttp.dll", SetLastError = true)] static extern bool WinHttpSetTimeouts(IntPtr h, int resolve, int connect, int send, int receive);
        [DllImport("winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool WinHttpGetProxyForUrl(IntPtr session, string url, ref AutoProxyOptions options, out ProxyInfo info);
        [DllImport("winhttp.dll", SetLastError = true)] static extern bool WinHttpGetDefaultProxyConfiguration(ref ProxyInfo info);
        [DllImport("winhttp.dll", SetLastError = true)] static extern bool WinHttpGetIEProxyConfigForCurrentUser(ref IeConfig config);
        [DllImport("kernel32.dll")] static extern IntPtr GlobalFree(IntPtr p);

        static string Take(IntPtr p) { if (p == IntPtr.Zero) return null; string s = Marshal.PtrToStringUni(p); GlobalFree(p); return s; }

        // When WPAD found nothing (12180) or timed out, later URLs of the same run skip it rather than wait again. The note
        // expires after ten minutes, so a long-lived session (an admin's console) tries WPAD again on its next run.
        static DateTime autoDetectFailedAt = DateTime.MinValue;
        static bool autoDetectFailed
        {
            get { return DateTime.UtcNow - autoDetectFailedAt < TimeSpan.FromMinutes(10); }
            set { autoDetectFailedAt = value ? DateTime.UtcNow : DateTime.MinValue; }
        }

        // "http=p:8080;https=q:8443" or "p:8080;q:8080" or "http://p:8080" -> the proxy for this scheme.
        public static string Pick(string list, string scheme)
        {
            if (string.IsNullOrEmpty(list)) return null;
            string generic = null;
            foreach (string raw in list.Split(new char[] { ';', ' ' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string e = raw.Trim(); string forScheme = null;
                int eq = e.IndexOf('=');
                if (eq > 0) { forScheme = e.Substring(0, eq).ToLowerInvariant(); e = e.Substring(eq + 1); }
                int sep = e.IndexOf("://", StringComparison.Ordinal);
                if (sep >= 0) e = e.Substring(sep + 3);
                e = e.TrimEnd('/');
                if (e.Length == 0) continue;
                if (e.IndexOf(':') < 0) e = e + ":80";
                if (forScheme == scheme) return e;
                if (forScheme == null && generic == null) generic = e;
            }
            return generic;
        }

        // WinINET/WinHTTP bypass list: "<local>" (names without a dot) and patterns with *.
        public static bool Bypassed(string host, string bypass)
        {
            if (string.IsNullOrEmpty(bypass)) return false;
            foreach (string raw in bypass.Split(new char[] { ';', ' ', ',' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string b = raw.Trim().ToLowerInvariant();
                if (b == "<local>") { if (host.IndexOf('.') < 0) return true; continue; }
                int sep = b.IndexOf("://", StringComparison.Ordinal);
                if (sep >= 0) b = b.Substring(sep + 3);
                if (Wild(host.ToLowerInvariant(), b)) return true;
            }
            return false;
        }

        static bool Wild(string s, string p)
        {
            int si = 0, pi = 0, star = -1, mark = 0;
            while (si < s.Length)
            {
                if (pi < p.Length && (p[pi] == s[si] || p[pi] == '?')) { si++; pi++; }
                else if (pi < p.Length && p[pi] == '*') { star = pi++; mark = si; }
                else if (star >= 0) { pi = star + 1; si = ++mark; }
                else return false;
            }
            while (pi < p.Length && p[pi] == '*') pi++;
            return pi == p.Length;
        }

        public static ProxyDecision ForUrl(string url, int timeoutMs)
        {
            ProxyDecision d = new ProxyDecision();
            Uri u = new Uri(url);
            try
            {
                ProxyInfo def = new ProxyInfo();
                if (WinHttpGetDefaultProxyConfiguration(ref def))
                {
                    string p = Take(def.Proxy), b = Take(def.Bypass);
                    if (def.AccessType == 3 && !string.IsNullOrEmpty(p))
                    {
                        d.Source = "netsh";
                        if (!Bypassed(u.Host, b)) d.Proxy = Pick(p, u.Scheme);
                        return d;
                    }
                }
                IeConfig ie = new IeConfig();
                if (!WinHttpGetIEProxyConfigForCurrentUser(ref ie)) return d;
                string pac = Take(ie.AutoConfigUrl), stat = Take(ie.Proxy), bypass = Take(ie.Bypass);
                if ((ie.AutoDetect && !autoDetectFailed) || !string.IsNullOrEmpty(pac))
                {
                    AutoProxyOptions opt = new AutoProxyOptions();
                    if (!string.IsNullOrEmpty(pac)) { opt.Flags |= 2; opt.AutoConfigUrl = pac; }
                    if (ie.AutoDetect && !autoDetectFailed) { opt.Flags |= 1; opt.AutoDetectFlags = 1 | 2; }
                    string source = !string.IsNullOrEmpty(pac) ? "pac" : "wpad";
                    ProxyInfo info; int err; bool timedOut;
                    bool ok = Evaluate(url, opt, timeoutMs, out info, out err, out timedOut);
                    if (timedOut) { d.Source = "unresolved"; d.Error = "proxy auto-configuration timed out"; autoDetectFailed = autoDetectFailed || string.IsNullOrEmpty(pac); return d; }
                    if (ok)
                    {
                        string p = Take(info.Proxy); Take(info.Bypass);
                        d.Source = source;
                        if (info.AccessType == 3 && !string.IsNullOrEmpty(p)) d.Proxy = Pick(p, u.Scheme);
                        return d;
                    }
                    // 12180 ERROR_WINHTTP_AUTODETECTION_FAILED: no WPAD on this network; fall through to a static proxy.
                    if (err == 12180) autoDetectFailed = true;
                    else if (!string.IsNullOrEmpty(pac)) { d.Source = "unresolved"; d.Error = "PAC evaluation failed (" + err + ")"; return d; }
                }
                if (!string.IsNullOrEmpty(stat))
                {
                    d.Source = "wininet";
                    if (!Bypassed(u.Host, bypass)) d.Proxy = Pick(stat, u.Scheme);
                }
            }
            catch (Exception ex) { d.Source = "unresolved"; d.Error = ex.GetType().Name; }
            return d;
        }

        // What one PAC answers for one URL (WINHTTP_AUTOPROXY_CONFIG_URL only, no auto-detection): WinHTTP downloads and
        // runs the script itself, as it does for DoSvc. Proxy is null when the script answers DIRECT.
        public static ProxyDecision ForPac(string url, string pacUrl, int timeoutMs)
        {
            ProxyDecision d = new ProxyDecision(); d.Source = "pac";
            try
            {
                Uri u = new Uri(url);
                AutoProxyOptions opt = new AutoProxyOptions(); opt.Flags = 2; opt.AutoConfigUrl = pacUrl;
                ProxyInfo info; int err; bool timedOut;
                if (!Evaluate(url, opt, timeoutMs, out info, out err, out timedOut))
                {
                    d.Source = "unresolved"; d.Error = timedOut ? "PAC evaluation timed out" : "PAC evaluation failed (" + err + ")";
                    return d;
                }
                string p = Take(info.Proxy); Take(info.Bypass);
                if (info.AccessType == 3 && !string.IsNullOrEmpty(p)) d.Proxy = Pick(p, u.Scheme);
            }
            catch (Exception ex) { d.Source = "unresolved"; d.Error = ex.GetType().Name; }
            return d;
        }

        // WinHttpGetProxyForUrl on its own thread, abandoned after timeoutMs: a PAC download or a WPAD lookup can hang.
        static bool Evaluate(string url, AutoProxyOptions opt, int timeoutMs, out ProxyInfo info, out int err, out bool timedOut)
        {
            ProxyInfo got = new ProxyInfo(); bool ok = false; int e = 0;
            Task t = Task.Factory.StartNew(delegate ()
            {
                IntPtr s = WinHttpOpen(EndpointProbe.UserAgent, 1, null, null, 0);
                if (s == IntPtr.Zero) { e = Marshal.GetLastWin32Error(); return; }
                try { WinHttpSetTimeouts(s, timeoutMs, timeoutMs, timeoutMs, timeoutMs); ok = WinHttpGetProxyForUrl(s, url, ref opt, out got); if (!ok) e = Marshal.GetLastWin32Error(); }
                finally { WinHttpCloseHandle(s); }
            });
            timedOut = !t.Wait(timeoutMs);
            info = timedOut ? new ProxyInfo() : got; err = e;
            return !timedOut && ok;
        }
    }
}
'@

function Initialize-DDNative {
    # Compiled once per session. Throws under Constrained Language Mode or application control (no Add-Type of source
    # code there), as Initialize-DDDhcpNative does; every caller runs inside Invoke-DDStep and records not-collected.
    [CmdletBinding()]
    param()
    if ('DoctorDO.Net.EndpointProbe' -as [type]) { return }
    if (-not (Test-DDFullLanguage)) { throw [System.NotSupportedException]::new('Constrained Language Mode or application control: runtime-compiled native code is not allowed (a precompiled, signed assembly is planned)') }
    $assemblies = @('System.dll')
    if ($PSVersionTable.PSVersion.Major -ge 6) { $assemblies = @('System.Net.Primitives', 'System.Net.Sockets', 'System.Net.Security', 'System.Net.NameResolution', 'System.Collections', 'System.Collections.Specialized', 'System.Linq', 'System.Threading.Tasks', 'System.Threading', 'System.Security.Cryptography', 'System.Security.Cryptography.X509Certificates', 'System.Diagnostics.Process', 'System.Runtime', 'System.Runtime.InteropServices', 'System.Text.Encoding.Extensions', 'System.Private.Uri', 'Microsoft.Win32.Primitives', 'netstandard') }
    Add-Type -Verbose:$false -TypeDefinition $script:DDEndpointSource -ReferencedAssemblies $assemblies -ErrorAction Stop
}

# DHCP client options (DhcpCApiInitialize / DhcpRequestParams / DhcpCApiCleanup in dhcpcsvc.dll, documented in the
# Win32 DHCP client API). One synchronous, non-persistent request for a few options on one adapter: the DHCP client
# answers from its cache, or sends a DHCPINFORM to the server when the option is not cached. Microsoft notes the call can
# take up to two minutes, so it runs on its own background thread and is abandoned after the caller's bound. Compiled
# separately from the probe helper (Initialize-DDDhcpNative) so a failure of one does not take the other down.
# Runtime compilation fails under application control (WDAC) or Constrained Language
# Mode, and a precompiled, signed assembly is the planned replacement; until then the caller degrades to not-collected.
$script:DDDhcpSource = @'
namespace DoctorDO.Net
{
    using System;
    using System.Runtime.InteropServices;
    using System.Threading;

    public class DhcpOptionValue
    {
        public int OptionId;
        public bool Present;
        public byte[] Data;
    }

    public class DhcpQueryOutcome
    {
        public bool Attempted;
        public bool TimedOut;
        public int Win32Error;
        public string Error;
        public DhcpOptionValue[] Options = new DhcpOptionValue[0];
    }

    public static class DhcpClient
    {
        const uint RequestSynchronous = 0x02;
        const uint ErrorMoreData = 234;
        const int MaxOptionBytes = 1024;

        [StructLayout(LayoutKind.Sequential)]
        struct ParamEntry { public uint Flags; public uint OptionId; public int IsVendor; public IntPtr Data; public uint nBytesData; }

        [StructLayout(LayoutKind.Sequential)]
        struct ParamArray { public uint nParams; public IntPtr Params; }

        [DllImport("dhcpcsvc.dll")] static extern uint DhcpCApiInitialize(out uint version);
        [DllImport("dhcpcsvc.dll")] static extern void DhcpCApiCleanup();
        [DllImport("dhcpcsvc.dll", CharSet = CharSet.Unicode)]
        static extern uint DhcpRequestParams(uint flags, IntPtr reserved, string adapterName, IntPtr classId, ParamArray sendParams, ParamArray recdParams, IntPtr buffer, ref uint size, string requestIdStr);

        static DhcpQueryOutcome Ask(string adapterId, int[] optionIds)
        {
            DhcpQueryOutcome o = new DhcpQueryOutcome();
            uint version;
            uint rc = DhcpCApiInitialize(out version);
            if (rc != 0) { o.Win32Error = (int)rc; o.Error = "DhcpCApiInitialize failed"; return o; }
            int entrySize = Marshal.SizeOf(typeof(ParamEntry));
            IntPtr entries = Marshal.AllocHGlobal(entrySize * optionIds.Length);
            IntPtr buffer = IntPtr.Zero;
            try
            {
                uint size = 4096;
                for (int attempt = 0; attempt < 2; attempt++)
                {
                    for (int i = 0; i < optionIds.Length; i++)
                    {
                        ParamEntry e = new ParamEntry();
                        e.OptionId = (uint)optionIds[i];
                        Marshal.StructureToPtr(e, IntPtr.Add(entries, i * entrySize), false);
                    }
                    if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                    buffer = Marshal.AllocHGlobal((int)size);
                    ParamArray none = new ParamArray();
                    ParamArray wanted = new ParamArray();
                    wanted.nParams = (uint)optionIds.Length;
                    wanted.Params = entries;
                    uint got = size;
                    rc = DhcpRequestParams(RequestSynchronous, IntPtr.Zero, adapterId, IntPtr.Zero, none, wanted, buffer, ref got, null);
                    if (rc == ErrorMoreData && attempt == 0 && got > size && got <= 65536) { size = got; continue; }
                    break;
                }
                o.Attempted = true;
                if (rc != 0) { o.Win32Error = (int)rc; o.Error = "DhcpRequestParams failed"; return o; }
                DhcpOptionValue[] values = new DhcpOptionValue[optionIds.Length];
                for (int i = 0; i < optionIds.Length; i++)
                {
                    ParamEntry e = (ParamEntry)Marshal.PtrToStructure(IntPtr.Add(entries, i * entrySize), typeof(ParamEntry));
                    DhcpOptionValue v = new DhcpOptionValue();
                    v.OptionId = optionIds[i];
                    v.Present = e.Data != IntPtr.Zero && e.nBytesData > 0;
                    if (v.Present)
                    {
                        int n = (int)Math.Min(e.nBytesData, (uint)MaxOptionBytes);
                        v.Data = new byte[n];
                        Marshal.Copy(e.Data, v.Data, 0, n);
                    }
                    values[i] = v;
                }
                o.Options = values;
                return o;
            }
            finally
            {
                if (buffer != IntPtr.Zero) Marshal.FreeHGlobal(buffer);
                Marshal.FreeHGlobal(entries);
                DhcpCApiCleanup();
            }
        }

        public static DhcpQueryOutcome Query(string adapterId, int[] optionIds, int timeoutMs)
        {
            DhcpQueryOutcome result = null;
            Thread t = new Thread(delegate ()
            {
                try { result = Ask(adapterId, optionIds); }
                catch (Exception ex) { DhcpQueryOutcome f = new DhcpQueryOutcome(); f.Error = ex.GetType().Name + ": " + ex.Message; result = f; }
            });
            t.IsBackground = true;
            t.Start();
            if (!t.Join(timeoutMs))
            {
                DhcpQueryOutcome o = new DhcpQueryOutcome();
                o.Attempted = true; o.TimedOut = true; o.Error = "no answer within " + timeoutMs + " ms";
                return o;
            }
            return result;
        }
    }
}
'@

function Initialize-DDDhcpNative {
    # Compiled once per session, like the probe helper. Throws under Constrained Language Mode or WDAC (no Add-Type of
    # source code there); the caller records not-collected.
    [CmdletBinding()]
    param()
    if ('DoctorDO.Net.DhcpClient' -as [type]) { return }
    if (-not (Test-DDFullLanguage)) { throw [System.NotSupportedException]::new('Constrained Language Mode or application control: runtime-compiled native code is not allowed (a precompiled, signed assembly is planned)') }
    $assemblies = @('System.dll')
    if ($PSVersionTable.PSVersion.Major -ge 6) { $assemblies = @('System.Runtime', 'System.Runtime.InteropServices', 'System.Threading', 'System.Threading.Thread', 'netstandard') }
    Add-Type -Verbose:$false -TypeDefinition $script:DDDhcpSource -ReferencedAssemblies $assemblies -ErrorAction Stop
}

function Invoke-DDDhcpRequest {
    <#
    .SYNOPSIS
        Ask the DHCP client for options on one adapter. Mockable seam. Returns DoctorDO.Net.DhcpQueryOutcome-shaped data.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $AdapterId, [Parameter(Mandatory)][int[]] $OptionIds, [int] $TimeoutMs = 8000)
    if (-not (Test-DDWindows)) { throw [System.PlatformNotSupportedException]::new('The DHCP client API is Windows only.') }
    Initialize-DDDhcpNative
    [DoctorDO.Net.DhcpClient]::Query($AdapterId, $OptionIds, $TimeoutMs)
}

function Invoke-DDHttpFetch {
    <#
    .SYNOPSIS
        One GET with normal certificate validation, reading the body only for the expected content types. Mockable seam.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Uri, [string] $Proxy, [int] $TimeoutMs = 6000, [int] $MaxBody = 16384, [string[]] $ReadBodyFor = @())
    Initialize-DDNative
    [DoctorDO.Net.EndpointProbe]::Fetch($Uri, $Proxy, $TimeoutMs, $MaxBody, [string[]]$ReadBodyFor)
}

function Resolve-DDUrlProxy {
    # The proxy WinHTTP would use for one URL in DoSvc's background context (as Resolve-DDProbeProxy does per row).
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Uri, [int] $TimeoutMs = 4000)
    if (-not (Test-DDWindows)) { return $null }
    Initialize-DDNative
    $d = [DoctorDO.Net.WinHttpProxy]::ForUrl($Uri, $TimeoutMs)
    [pscustomobject]@{ Source = $d.Source; Proxy = $d.Proxy; Error = $d.Error }
}

function Resolve-DDPacProxy {
    # What one PAC answers for one URL, evaluated by WinHTTP as DoSvc's would be (Get-DDPacFacts). Mockable seam.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Uri, [Parameter(Mandatory)][string] $PacUrl, [int] $TimeoutMs = 4000)
    if (-not (Test-DDWindows)) { return $null }
    Initialize-DDNative
    $d = [DoctorDO.Net.WinHttpProxy]::ForPac($Uri, $PacUrl, $TimeoutMs)
    [pscustomobject]@{ Proxy = $d.Proxy; Error = $d.Error }
}

function Invoke-DDNetProbeBatch {
    <#
    .SYNOPSIS
        Run a set of TCP connect probes (the peer probes, TCP 7680) in parallel with per-probe and total time bounds, on the
        endpoint probe engine: a connect, then close; no proxy, nothing sent. Mockable seam for the tests.
    .PARAMETER Specs
        Objects with Kind (tcp), Target, Port, Tag. Returns one result per spec: Kind, Target, Port, Tag, Ok, TimedOut, Ms,
        Error. A spec of another kind is not probed (Error 'unknown probe kind').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()] $Specs,
        [int] $ProbeTimeoutMs = 5000,
        [int] $TotalTimeoutMs = 60000
    )
    $list = @($Specs)
    if ($list.Count -eq 0) { return @() }
    $result = { param($s, $ok, $timedOut, $ms, $err) [pscustomobject]@{ Kind = [string]$s.Kind; Target = [string]$s.Target; Port = [int]$s.Port; Tag = [string]$s.Tag; Ok = [bool]$ok; TimedOut = [bool]$timedOut; Ms = $ms; Error = $err } }
    $tcp = @($list | Where-Object { [string]$_.Kind -eq 'tcp' })
    $by = @{}
    if ($tcp.Count -gt 0) {
        Initialize-DDNative
        $arr = New-Object 'DoctorDO.Net.EndpointRowSpec[]' $tcp.Count
        for ($i = 0; $i -lt $tcp.Count; $i++) {
            $r = New-Object DoctorDO.Net.EndpointRowSpec
            $r.Tag = [string]$i; $r.Host = [string]$tcp[$i].Target; $r.Ports = [int[]]@([int]$tcp[$i].Port); $r.Protocols = [string[]]@('tcp')
            $arr[$i] = $r
        }
        foreach ($o in @([DoctorDO.Net.EndpointProbe]::RunRows($arr, $ProbeTimeoutMs, $TotalTimeoutMs, 8))) { $by[[string]$o.Tag] = $o }
    }
    $n = 0
    foreach ($s in $list) {
        if ([string]$s.Kind -ne 'tcp') { & $result $s $false $false $null 'unknown probe kind'; continue }
        $o = $by[[string]$n]; $n++
        $p = @($o.Ports) | Select-Object -First 1
        if ($o.TimedOut) { & $result $s $false $true $null 'total probe budget exhausted' }
        elseif ($null -eq $p) { & $result $s $false $false ([double]$o.DnsMs) $(if ($o.DnsError) { [string]$o.DnsError } else { 'not connected' }) }
        else { & $result $s ([bool]$p.Ok) ([bool]$p.TimedOut) ([double]$p.Ms) $(if ($p.Ok) { $null } else { [string]$p.Error }) }
    }
}

function Invoke-DDPublicIpProbe {
    # Optional: ask a tenant-chosen HTTPS endpoint for the egress address. Never called unless -PublicIpProbeUri is given.
    # One GET through EndpointProbe.Fetch (Invoke-DDHttpFetch), through the proxy WinHTTP would use, as the DO geo request
    # is: the certificate validated as normal, no redirect followed, at most 65 bytes of body read, and every stage bounded
    # by -TimeoutMs, so the whole request by about six times it.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string] $Uri, [int] $TimeoutMs = 3000)
    if ($Uri -notmatch '^https://') { throw 'PublicIpProbeUri must be https.' }
    $px = $null
    try { $px = Resolve-DDUrlProxy -Uri $Uri -TimeoutMs $TimeoutMs } catch { Write-Verbose "public IP probe: proxy not resolved ($($_.Exception.GetType().Name))" }
    $f = Invoke-DDHttpFetch -Uri $Uri -Proxy $(if ($px -and $px.Proxy) { [string]$px.Proxy } else { $null }) -TimeoutMs $TimeoutMs -MaxBody 65 -ReadBodyFor @('')
    if ($null -eq $f -or [int]$f.Status -ne 200 -or $f.Redirected -or $f.BodyTruncated -or $null -eq $f.Body -or @($f.Body).Count -gt 64) { return $null }
    $t = [System.Text.Encoding]::ASCII.GetString([byte[]]@($f.Body)).Trim()
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($t, [ref]$ip)) { return $ip.ToString() }
    $null
}

function Get-DDListeningTcpPorts {
    [CmdletBinding()]
    param()
    @([System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().GetActiveTcpListeners() | ForEach-Object { $_.Port })
}

function Get-DDTeredoStateRaw {
    # Teredo's configured type and its active state from the classes behind Get-NetTeredoConfiguration and
    # Get-NetTeredoState (root/StandardCimv2 MSFT_NetTeredoConfiguration, MSFT_NetTeredoState), which do not depend on the
    # display language. Type is the class's number (NetTeredoConfiguration.Type: 0 Default ... 7 Natawareclient). Microsoft:
    # "If Teredo is not active, then this cmdlet does not return an object", so StatePresent is then $false. Throws when
    # the classes cannot be read (the caller falls back to netsh).
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { throw [System.PlatformNotSupportedException]::new('The Teredo classes are Windows only.') }
    $cfg = @(Get-CimInstance -Verbose:$false -Namespace 'root/StandardCimv2' -ClassName 'MSFT_NetTeredoConfiguration' -ErrorAction Stop | Where-Object { -not $_.PolicyStore -or [string]$_.PolicyStore -eq 'ActiveStore' }) | Select-Object -First 1
    $st = @(Get-CimInstance -Verbose:$false -Namespace 'root/StandardCimv2' -ClassName 'MSFT_NetTeredoState' -ErrorAction Stop) | Select-Object -First 1
    [pscustomobject]@{ Type = $(if ($null -ne $cfg) { $cfg.Type } else { $null }); ServerName = $(if ($null -ne $cfg) { [string]$cfg.ServerName } else { $null })
        StatePresent = ($null -ne $st); State = $(if ($st) { [string]$st.State } else { $null }); Error = $(if ($st) { [string]$st.Error } else { $null }) }
}

function Get-DDTeredoStateText {
    # netsh interface teredo show state: the fallback when the Teredo classes cannot be read. English output only.
    [CmdletBinding()]
    param()
    if (-not (Test-DDWindows)) { throw [System.PlatformNotSupportedException]::new('netsh teredo is Windows only.') }
    @(& (Join-Path $env:SystemRoot 'System32\netsh.exe') interface teredo show state 2>&1 | ForEach-Object { [string]$_ })
}
