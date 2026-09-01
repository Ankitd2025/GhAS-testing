using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using System.Data.SqlClient;
using Microsoft.AspNetCore.Mvc;

namespace DemoApi.Controllers;

/// <summary>
/// GHAS Demo Controller — Intentional vulnerabilities for CodeQL taint tracking.
/// All endpoints here are structured as traditional MVC controllers so CodeQL
/// can fully trace taint flow from HTTP request source to vulnerable sinks.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class VulnerableController : ControllerBase
{
    private readonly ILogger<VulnerableController> _logger;
    private const string DbPassword  = "SuperSecret@1234";       // CWE-259: hardcoded password
    private const string EncKey      = "12345678";               // CWE-321: hardcoded crypto key
    private const string InternalUrl = "http://192.168.1.100:8080"; // CWE-547: hardcoded IP

    public VulnerableController(ILogger<VulnerableController> logger)
    {
        _logger = logger;
    }

    // ---- 1. SQL Injection (CWE-89) — HIGH ----
    [HttpGet("users")]
    public IActionResult GetUsers([FromQuery] string name)
    {
        // VULNERABLE: taint flows from 'name' (HTTP param) → SQL string → SqlCommand
        string connStr  = $"Server=myserver;Database=mydb;User Id=sa;Password={DbPassword};";
        string query    = "SELECT * FROM Users WHERE Name = '" + name + "'";

        using var conn  = new SqlConnection(connStr);
        using var cmd   = new SqlCommand(query, conn);
        return Ok(new { query, message = "SQL Injection vulnerability" });
    }

    // ---- 2. Command Injection (CWE-78) — HIGH ----
    [HttpGet("ping")]
    public IActionResult Ping([FromQuery] string host)
    {
        // VULNERABLE: taint flows from 'host' → ProcessStartInfo.Arguments → shell
        var psi = new ProcessStartInfo
        {
            FileName        = "cmd.exe",
            Arguments       = $"/c ping {host}",
            UseShellExecute = false,
            RedirectStandardOutput = true
        };
        using var proc = Process.Start(psi);
        return Ok($"Pinging {host}");
    }

    // ---- 3. Path Traversal (CWE-22) — HIGH ----
    [HttpGet("file")]
    public IActionResult ReadFile([FromQuery] string filename)
    {
        // VULNERABLE: taint flows from 'filename' → File.ReadAllText path
        string path    = Path.Combine("/var/www/files/", filename);
        string content = System.IO.File.ReadAllText(path);
        return Ok(content);
    }

    // ---- 4. Reflected XSS (CWE-79) — HIGH ----
    [HttpGet("search")]
    public ContentResult Search([FromQuery] string q)
    {
        // VULNERABLE: taint flows from 'q' → HTML response without encoding
        string html = $"<html><body><h1>Results for: {q}</h1></body></html>";
        return base.Content(html, "text/html");
    }

    // ---- 5. SSRF (CWE-918) — HIGH ----
    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch([FromQuery] string url)
    {
        // VULNERABLE: taint flows from 'url' → HttpClient.GetStringAsync
        using var client   = new HttpClient();
        var response = await client.GetStringAsync(url);
        return Ok(response);
    }

    // ---- 6. Open Redirect (CWE-601) — MEDIUM ----
    [HttpGet("redirect")]
    public IActionResult Redirect([FromQuery] string returnUrl)
    {
        // VULNERABLE: taint flows from 'returnUrl' → Redirect() without validation
        return Redirect(returnUrl);
    }

    // ---- 7. LDAP Injection (CWE-90) — HIGH ----
    [HttpGet("ldap")]
    public IActionResult LdapSearch([FromQuery] string username)
    {
        // VULNERABLE: taint flows from 'username' → LDAP filter string
        string filter = "(&(objectClass=user)(sAMAccountName=" + username + "))";
        return Ok(new { filter, message = "LDAP Injection vulnerability" });
    }

    // ---- 8. XPath Injection (CWE-643) — HIGH ----
    [HttpGet("finduser")]
    public IActionResult FindUser([FromQuery] string username)
    {
        // VULNERABLE: taint flows from 'username' → XPath expression
        string xmlData = @"<?xml version='1.0'?>
        <users>
          <user><name>admin</name><password>admin@123</password><role>admin</role></user>
          <user><name>guest</name><password>guest123</password><role>user</role></user>
        </users>";

        var doc = new XmlDocument();
        doc.LoadXml(xmlData);

        // Attacker payload: ' or '1'='1  →  dumps all records
        string xpath = "//user[name='" + username + "']";
        var nodes    = doc.SelectNodes(xpath);

        var results = new List<string>();
        if (nodes != null)
            foreach (XmlNode node in nodes)
                results.Add(node.InnerXml);

        return Ok(results);
    }

    // ---- 9. XXE Injection (CWE-611) — HIGH ----
    [HttpPost("xml")]
    public IActionResult ParseXml([FromBody] string xmlInput)
    {
        // VULNERABLE: XmlUrlResolver enables external entity processing
        var doc = new XmlDocument();
        doc.XmlResolver = new XmlUrlResolver();
        doc.LoadXml(xmlInput);
        return Ok(doc.InnerText);
    }

    // ---- 10. HTTP Response Splitting (CWE-113) — HIGH ----
    [HttpGet("setheader")]
    public IActionResult SetHeader([FromQuery] string value)
    {
        // VULNERABLE: taint flows from 'value' → HTTP response header
        // Attacker injects \r\n to split response and forge new headers
        Response.Headers.Append("X-Custom-Header", value);
        return Ok($"Header set to: {value}");
    }

    // ---- 11. Log Injection (CWE-117) — MEDIUM ----
    [HttpGet("log")]
    public IActionResult Log([FromQuery] string input)
    {
        // FIX: remove CR/LF from user input before logging to prevent log forging
        var sanitizedInput = (input ?? string.Empty)
            .Replace("\r", string.Empty)
            .Replace("\n", string.Empty);
        _logger.LogInformation("User input: " + sanitizedInput);
        return Ok("Logged");
    }

    // ---- 12. Weak Encryption — DES + hardcoded key (CWE-327/321) — HIGH ----
    [HttpGet("encrypt")]
    public IActionResult Encrypt([FromQuery] string data)
    {
        // VULNERABLE: DES is broken + hardcoded key
        using var des = DES.Create();
        des.Key       = Encoding.UTF8.GetBytes(EncKey);
        des.IV        = Encoding.UTF8.GetBytes(EncKey);
        var encryptor = des.CreateEncryptor();
        var bytes     = Encoding.UTF8.GetBytes(data);
        var encrypted = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
        return Ok(Convert.ToBase64String(encrypted));
    }

    // ---- 13. Cleartext credentials returned in response (CWE-312) — HIGH ----
    [HttpGet("admin/users")]
    public IActionResult GetAdminUsers()
    {
        // VULNERABLE: No auth + returns plaintext passwords
        var users = new[]
        {
            new { Id = 1, Username = "admin", Password = "admin@123"  },
            new { Id = 2, Username = "guest", Password = "guest123"   },
            new { Id = 3, Username = "sa",    Password = "P@ssw0rd!"  }
        };
        return Ok(users);
    }

    // ---- 14. Sensitive data in query string (CWE-598) — MEDIUM ----
    [HttpGet("login")]
    public IActionResult Login([FromQuery] string username, [FromQuery] string password)
    {
        // VULNERABLE: credentials in URL get logged by proxy/web servers
        if (username == "admin" && password == DbPassword)
            return Ok("Login successful");
        return Unauthorized();
    }

    // ---- 15. Unvalidated file upload + path traversal (CWE-434) — HIGH ----
    [HttpPost("upload")]
    public async Task<IActionResult> Upload(IFormFile file)
    {
        // VULNERABLE: filename from user, no type check, no size limit
        if (file != null)
        {
            string path = Path.Combine("/tmp/uploads/", file.FileName); // path traversal
            using var stream = System.IO.File.Create(path);
            await file.CopyToAsync(stream);
        }
        return Ok("File uploaded");
    }
}
