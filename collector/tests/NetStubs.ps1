# Loopback network stubs for the probe and transport tests: a small TCP server that plays a proxy (tunnelling, inspecting,
# refusing) or a slow or short HTTP server, and throwaway certificates (a CA, a leaf it signs) built in memory. Nothing is
# installed in a certificate store and nothing leaves the loopback interface. C# 5, so Windows PowerShell 5.1 compiles it.

function Initialize-NetStubType {
    if ('DDNetStub' -as [type]) { return }
    $src = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

public class DDNetStub
{
    // Modes: tunnel (CONNECT to 127.0.0.1:TargetPort, then relay), inspect (CONNECT answered 200, then TLS with Cert),
    // reset (read the request, then reset the connection), html (answer with a web page, not HTTP), silent (accept, never
    // answer), proxy407 (answer CONNECT with 407), dribble-tls (TLS with Cert, then the status line one byte every
    // DribbleMs), dribble-body (HTTP 200 announcing 100 MB, then one byte every DribbleMs), short-body (Content-Length
    // 1000, Body, then close), no-type (HTTP 200 with Body and no Content-Type).
    TcpListener listener; Thread loop; volatile bool stop;
    public string Mode; public int Port; public int TargetPort; public X509Certificate2 Cert; public int DribbleMs = 1500; public string Body = "";
    public List<string> FirstLines = new List<string>(); public string Failure;
    public DDNetStub(string mode) { Mode = mode; }
    public void Start() { listener = new TcpListener(IPAddress.Loopback, 0); listener.Start(); Port = ((IPEndPoint)listener.LocalEndpoint).Port; loop = new Thread(Loop); loop.IsBackground = true; loop.Start(); }
    public void Stop() { stop = true; try { listener.Stop(); } catch (Exception) { } }
    public string[] Lines() { lock (FirstLines) { return FirstLines.ToArray(); } }

    void Loop()
    {
        while (!stop)
        {
            try { TcpClient c = listener.AcceptTcpClient(); Thread h = new Thread(delegate () { Handle(c); }); h.IsBackground = true; h.Start(); }
            catch (Exception) { if (stop) break; }
        }
    }

    static string ReadHead(Stream s)
    {
        MemoryStream m = new MemoryStream(); int state = 0;
        while (state < 4) { int b = s.ReadByte(); if (b < 0) break; m.WriteByte((byte)b); if ((state % 2 == 0 && b == 13) || (state % 2 == 1 && b == 10)) state++; else state = (b == 13) ? 1 : 0; }
        return Encoding.ASCII.GetString(m.ToArray());
    }
    static void Send(Stream s, string text) { byte[] b = Encoding.ASCII.GetBytes(text); s.Write(b, 0, b.Length); s.Flush(); }
    static string First(string head) { int i = head.IndexOf("\r\n", StringComparison.Ordinal); return i < 0 ? head : head.Substring(0, i); }
    void Note(string head) { lock (FirstLines) { FirstLines.Add(First(head)); } }
    static void Pump(Stream from, Stream to) { byte[] b = new byte[8192]; try { int n; while ((n = from.Read(b, 0, b.Length)) > 0) { to.Write(b, 0, n); to.Flush(); } } catch (Exception) { } try { to.Close(); } catch (Exception) { } }
    bool ClientGone(TcpClient c) { try { return c.Client.Poll(100000, SelectMode.SelectRead) && c.Available == 0; } catch (Exception) { return true; } }

    void Handle(TcpClient c)
    {
        try
        {
            NetworkStream ns = c.GetStream();
            if (Mode == "silent") { while (!stop && !ClientGone(c)) { } return; }
            if (Mode == "dribble-tls")
            {
                SslStream tls = new SslStream(ns, false);
                tls.AuthenticateAsServer(Cert, false, SslProtocols.Tls12, false);
                Note(ReadHead(tls));
                foreach (char ch in "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n") { if (stop) return; tls.WriteByte((byte)ch); tls.Flush(); Thread.Sleep(DribbleMs); }
                return;
            }
            string head = ReadHead(ns);
            Note(head);
            if (Mode == "reset") { c.Client.LingerState = new LingerOption(true, 0); c.Client.Close(); return; }
            if (Mode == "html") { Send(ns, "<html><body>Blocked by policy</body></html>"); return; }
            if (Mode == "proxy407") { Send(ns, "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"stub\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"); return; }
            if (Mode == "inspect")
            {
                Send(ns, "HTTP/1.1 200 Connection established\r\n\r\n");
                SslStream tls = new SslStream(ns, false);
                tls.AuthenticateAsServer(Cert, false, SslProtocols.Tls12, false);
                while (!stop && !ClientGone(c)) { }
                return;
            }
            if (Mode == "tunnel")
            {
                TcpClient up = new TcpClient(); up.Connect(IPAddress.Loopback, TargetPort);
                Send(ns, "HTTP/1.1 200 Connection established\r\n\r\n");
                NetworkStream us = up.GetStream();
                Thread a = new Thread(delegate () { Pump(ns, us); }); a.IsBackground = true; a.Start();
                Pump(us, ns);
                try { up.Close(); } catch (Exception) { }
                return;
            }
            if (Mode == "dribble-body")
            {
                Send(ns, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 100000000\r\n\r\n");
                for (int i = 0; i < 100000 && !stop; i++) { ns.WriteByte((byte)'1'); ns.Flush(); if (DribbleMs > 0) Thread.Sleep(DribbleMs); }
                return;
            }
            if (Mode == "short-body") { Send(ns, "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: 1000\r\nConnection: close\r\n\r\n" + Body); return; }
            if (Mode == "no-type") { Send(ns, "HTTP/1.1 200 OK\r\nContent-Length: " + Encoding.ASCII.GetByteCount(Body) + "\r\nConnection: close\r\n\r\n" + Body); return; }
        }
        catch (Exception ex) { Failure = ex.GetType().Name + ": " + ex.Message; }
        finally { try { c.Close(); } catch (Exception) { } }
    }
}
'@
    if ($PSVersionTable.PSEdition -eq 'Core') {
        Add-Type -ReferencedAssemblies 'System.Net.Primitives', 'System.Net.Sockets', 'System.Net.Security', 'System.Security.Cryptography', 'System.Security.Cryptography.X509Certificates', 'System.Collections', 'System.Threading', 'System.Threading.Thread', 'System.Runtime', 'System.Linq', 'System.Memory', 'netstandard' -TypeDefinition $src
    } else {
        Add-Type -TypeDefinition $src
    }
}

function New-NetStub {
    # A started stub; stop it with .Stop().
    param([Parameter(Mandatory)][string] $Mode, [int] $TargetPort, $Cert, [int] $DribbleMs = 1500, [string] $Body = '')
    Initialize-NetStubType
    $s = New-Object DDNetStub($Mode)
    $s.TargetPort = $TargetPort; $s.DribbleMs = $DribbleMs; $s.Body = $Body
    if ($Cert) { $s.Cert = $Cert }
    $s.Start()
    $s
}

function New-StubCertificate {
    <#
      A throwaway RSA certificate with its private key: self-signed, or signed by -Issuer (a certificate with a private key).
      -Ca makes it a certification authority; -DnsName adds a subject alternative name. Built in memory only.
    #>
    param([Parameter(Mandatory)][string] $Subject, $Issuer, [switch] $Ca, [string] $DnsName)
    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $req = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest($Subject, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension([bool]$Ca, $false, 0, $true)))
    if ($Ca) {
        $usage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::CrlSign
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension($usage, $true)))
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension($req.PublicKey, $false)))
    }
    if ($DnsName) {
        $san = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
        $san.AddDnsName($DnsName)
        $req.CertificateExtensions.Add($san.Build())
        $oids = New-Object System.Security.Cryptography.OidCollection
        [void]$oids.Add((New-Object System.Security.Cryptography.Oid('1.3.6.1.5.5.7.3.1')))
        $req.CertificateExtensions.Add((New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oids, $false)))
    }
    $from = [System.DateTimeOffset]::UtcNow.AddDays(-1); $to = [System.DateTimeOffset]::UtcNow.AddDays($(if ($Ca) { 365 } else { 30 }))
    # A certificate cannot outlive its issuer.
    if ($Issuer -and $to -gt [System.DateTimeOffset]$Issuer.NotAfter.ToUniversalTime().AddHours(-1)) { $to = [System.DateTimeOffset]$Issuer.NotAfter.ToUniversalTime().AddHours(-1) }
    if ($Issuer) {
        $serial = New-Object byte[] 8
        (New-Object System.Random).NextBytes($serial); $serial[0] = $serial[0] -band 0x7F
        $plain = $req.Create($Issuer, $from, $to, $serial)
        $cert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::CopyWithPrivateKey($plain, $rsa)
    } else {
        $cert = $req.CreateSelfSigned($from, $to)
    }
    # Round-trip through PFX so SslStream can use the key on every platform.
    New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, 'x'), 'x', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
}

function New-StubChain {
    # The chain Windows (or .NET) builds for -Leaf with -Extra certificates available, trusted or not: no store is touched.
    param([Parameter(Mandatory)] $Leaf, [object[]] $Extra = @())
    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
    foreach ($c in $Extra) { [void]$chain.ChainPolicy.ExtraStore.Add($c) }
    [void]$chain.Build($Leaf)
    , $chain
}
