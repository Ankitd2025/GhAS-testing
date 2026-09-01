using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.XPath;
using System.Xml.Xsl;
using System.Runtime.Serialization.Formatters.Binary;
using System.Data.SqlClient;
using System.Net;

var builder = WebApplication.CreateBuilder(args);

// Add services to the  container.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddControllers(); // Enable MVC controllers for CodeQL taint tracking

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// app.UseHttpsRedirection(); // Disabled for GHAS demo — run on plain HTTP

app.MapControllers(); // Map all controller routes (VulnerableController)

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool",
    "Mild", "Warm", "Balmy", "Hot",
    "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast = Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast")
.WithOpenApi();

app.MapGet("/welcome", () => "Welcome to the Demo API! V1")
   .WithName("WelcomeApi");

   
// ====================================================
// GHAS DEMO - Maximum Vulnerability Coverage
// ====================================================

// ============================================================
// SECRET SCANNING — Hardcoded secrets (exact pattern dummies)
// ============================================================

// AWS Credentials (Access Key: AKIA + 16 chars | Secret Key: 40 base64  chars)
// AWS test credentials
var github_personal_access_token = ""

var aws_access_key_id = "AKIAIOSFODNN7EXAMPLE";
var aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// Azure Storage Connection String (AccountKey: 86 base64 chars + ==)
var azureConnStr       = "DefaultEndpointsProtocol=https;AccountName=demostorage;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;EndpointSuffix=core.windows.net";

// Hardcoded DB Password
var dbPassword         = "SuperSecret@1234";

// Slack Bot Token (xoxb- + 12 digits + - + 13 digits + - + 24 alphanumeric)
var slackToken         = "xoxb-123456789012-1234567890123-456789012345678901234567";

// Stripe Live Secret Key (sk_live_ + 24 alphanumeric chars)
var stripeKey          = "sk_live_5123456789abcdefghijklmnopqrst";

// Google API Key (AIzaSy + 33 chars)
var googleApiKey       = "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q";

// Twilio Account SID (AC + 32 hex chars) + Auth Token (32 hex chars)
var twilioSid          = "AC1234567890abcdef1234567890abcdef";
var twilioToken        = "1234567890abcdef1234567890abcdef";

// SendGrid API Key (SG. + 22 chars + . + 43 chars)
var sendgridKey        = "SG.1234567890abcdefghijkl.1234567890abcdefghijklmnopqrstuvwxyz1234567";

// Docker Hub Personal Access Token (dckr_pat_ + 27 chars)
var dockerPassword     = "dckr_pat_1234567890abcdefghijklmno12";

// Hardcoded internal IP
var internalServer     = "http://192.168.1.100:8080/internal-api";

// Hardcoded Private Key (Standard PEM structure with base64 blocks)
var privateKey = @"-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3Z89+1234567890abcdefghijklmnopqrstuvwxyzABCDE
FGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFG
HIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFG01
23456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTU012345678
90abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
-----END RSA PRIVATE KEY-----";

// ---- VULNERABLE: Exposes all secrets over unauthenticated HTTP endpoint ----
app.MapGet("/config", () =>
{
    return Results.Ok(new
    {
        GitHubToken    = githubToken,
        AwsKey         = awsAccessKey,
        AwsSecret      = awsSecretKey,
        AzureConnStr   = azureConnStr,
        DbPassword     = dbPassword,
        SlackToken     = slackToken,
        StripeKey      = stripeKey,
        GoogleApiKey   = googleApiKey,
        TwilioSid      = twilioSid,
        TwilioToken    = twilioToken,
        SendGridKey    = sendgridKey,
        DockerPassword = dockerPassword,
        InternalServer = internalServer
    });
});

// ============================================================
// CODE SCANNING (CodeQL) — Vulnerabilities
// =============================================gh auth status===============

// ---- 1. SQL Injection ----
app.MapGet("/users", (string name) =>
{
    // VULNERABLE: Direct string concatenation into SQL query
    string query = "SELECT * FROM Users WHERE Name = '" + name + "'";
    var conn = new SqlConnection($"Server=myserver;Database=mydb;User Id=admin;Password={dbPassword};");
    return Results.Ok(query);
});

// ---- 2. Command Injection ----
app.MapGet("/ping", (string host) =>
{
    // VULNERABLE: User input passed directly to shell
    var proc = Process.Start(new ProcessStartInfo
    {
        FileName        = "cmd.exe",
        Arguments       = $"/c ping {host}",
        UseShellExecute = false
    });
    return Results.Ok($"Pinging {host}");
});

// ---- 3. Path Traversal ----
app.MapGet("/file", (string filename) =>
{
    // VULNERABLE: No path sanitization
    var content = File.ReadAllText("/tmp/" + filename);
    return content;
});

// ---- 4. Weak Encryption (DES + hardcoded key) ----
app.MapGet("/encrypt", (string data) =>
{
    // VULNERABLE: DES is broken, key hardcoded
    using var des = DES.Create();
    des.Key = Encoding.UTF8.GetBytes("12345678");
    des.IV  = Encoding.UTF8.GetBytes("12345678");
    var encryptor = des.CreateEncryptor();
    var bytes     = Encoding.UTF8.GetBytes(data);
    var encrypted = encryptor.TransformFinalBlock(bytes, 0, bytes.Length);
    return Results.Ok(Convert.ToBase64String(encrypted));
});

// ---- 5. SSRF (Server-Side Request Forgery) ----
app.MapGet("/fetch", async (string url) =>
{
    // VULNERABLE: Fetches any user-supplied URL
    using var client   = new HttpClient();
    var response = await client.GetStringAsync(url);
    return Results.Ok(response);
});

// ---- 6. Open Redirect ----
app.MapGet("/redirect", (string returnUrl) =>
{
    // VULNERABLE: No validation on redirect target
    return Results.Redirect(returnUrl);
});

// ---- 7. Reflected XSS ----
app.MapGet("/search", (string q) =>
{
    // VULNERABLE: User input reflected into HTML without encoding
    var html = $"<html><body><h1>Search results for: {q}</h1></body></html>";
    return Results.Content(html, "text/html");
});

// ---- 8. XXE (XML External Entity) ----
app.MapPost("/xml", async (HttpContext ctx) =>
{
    // VULNERABLE: DTD processing enabled, allows XXE
    var body = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
    var doc  = new XmlDocument();
    doc.XmlResolver = new XmlUrlResolver(); // allows external entities
    doc.LoadXml(body);
    return Results.Ok(doc.InnerText);
});

// ---- 9. Insecure Deserialization ----
app.MapPost("/deserialize", async (HttpContext ctx) =>
{
    // VULNERABLE: BinaryFormatter is unsafe
#pragma warning disable SYSLIB0011
    var formatter = new BinaryFormatter();
    var obj       = formatter.Deserialize(ctx.Request.Body);
#pragma warning restore SYSLIB0011
    return Results.Ok(obj?.ToString());
});

// ---- 10. Missing Authentication on sensitive endpoint ----
app.MapGet("/admin/users", () =>
{
    // VULNERABLE: No auth — exposes usernames and passwords
    var users = new[] {
        new { Id = 1, Username = "admin",  Password = "admin@123"  },
        new { Id = 2, Username = "guest",  Password = "guest123"   },
        new { Id = 3, Username = "sa",     Password = "P@ssw0rd!"  }
    };
    return Results.Ok(users);
});

// ---- 11. LDAP Injection ----
app.MapGet("/ldap", (string username) =>
{
    // VULNERABLE: user input injected into LDAP filter
    var filter = $"(&(objectClass=user)(sAMAccountName={username}))";
    return Results.Ok($"LDAP filter: {filter}");
});

// ---- 12. Weak Randomness (predictable token) ----
app.MapGet("/token", () =>
{
    // VULNERABLE: System.Random with fixed seed — predictable
    var rng   = new Random(42);
    var token = rng.Next(100000, 999999).ToString();
    return Results.Ok(new { token });
});

// ---- 13. Log Injection ----
app.MapGet("/log", (string input, ILogger<Program> logger) =>
{
    // VULNERABLE: unsanitized user input written to logs
    logger.LogInformation("User input received: " + input);
    return Results.Ok("Logged");
});

// ---- 14. ReDoS (Regex Denial of Service) ----
app.MapGet("/validate-email", (string email) =>
{
    // VULNERABLE: catastrophic backtracking regex
    var regex = new Regex(@"^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$");
    var isValid = regex.IsMatch(email);
    return Results.Ok(new { email, isValid });
});

// ---- 15. Cleartext storage of sensitive info ----
app.MapPost("/register", (UserRegistration user) =>
{
    // VULNERABLE: Password stored in plaintext (no hashing)
    var stored = new { user.Username, user.Password, CreatedAt = DateTime.UtcNow };
    return Results.Ok(stored);
});

// ---- 16. Hardcoded IP Address ----
app.MapGet("/internal", async () =>
{
    // VULNERABLE: Hardcoded internal IP
    using var client   = new HttpClient();
    var response = await client.GetStringAsync("http://192.168.1.100:8080/api/data");
    return Results.Ok(response);
});

// ---- 17. CSRF — no anti-forgery token ----
app.MapPost("/transfer", (TransferRequest req) =>
{
    // VULNERABLE: No CSRF protection on state-changing endpoint
    return Results.Ok($"Transferred {req.Amount} to {req.ToAccount}");
});

// ---- 18. Sensitive data in URL (query param) ----
app.MapGet("/login", (string username, string password) =>
{
    // VULNERABLE: Credentials passed in query string (logged by web servers)
    if (username == "admin" && password == dbPassword)
        return Results.Ok("Login successful");
    return Results.Unauthorized();
});

// ---- 19. Directory listing / info disclosure ----
app.MapGet("/debug", (HttpContext ctx) =>
{
    // VULNERABLE: Exposes server internals
    return Results.Ok(new
    {
        MachineName  = Environment.MachineName,
        OSVersion    = Environment.OSVersion.ToString(),
        DotnetVersion= Environment.Version.ToString(),
        CurrentDir   = Directory.GetCurrentDirectory(),
        EnvVars      = Environment.GetEnvironmentVariables()
    });
});

// ---- 20. Unvalidated file upload ----
app.MapPost("/upload", async (HttpContext ctx) =>
{
    // VULNERABLE: No file type or size validation
    var form = await ctx.Request.ReadFormAsync();
    var file = form.Files.FirstOrDefault();
    if (file != null)
    {
        var path = Path.Combine("/tmp/uploads", file.FileName); // path traversal via filename
        using var stream = File.Create(path);
        await file.CopyToAsync(stream);
    }
    return Results.Ok("Uploaded");
});

// ---- 21. HTTP Response Splitting (HIGH — CWE-113) ----
app.MapGet("/setheader", (string value, HttpContext ctx) =>
{
    // VULNERABLE: User input injected directly into HTTP response header
    // Attacker can inject \r\n to split the response and inject new headers/body
    ctx.Response.Headers.Append("X-Custom-Header", value);
    return Results.Ok($"Header set to: {value}");
});

// ---- 22. XPath Injection (HIGH — CWE-643) ----
app.MapGet("/finduser", (string username) =>
{
    var xml = @"<?xml version='1.0'?>
    <users>
      <user><name>admin</name><password>admin@123</password><role>admin</role></user>
      <user><name>guest</name><password>guest123</password><role>user</role></user>
    </users>";

    var doc = new XmlDocument();
    doc.LoadXml(xml);

    var expr = XPathExpression.Compile("//user[name=$username]");
    var argsList = new XsltArgumentList();
    argsList.AddParam("username", string.Empty, username);
    expr.SetContext(new CustomXsltContext(argsList));

    var nav = doc.CreateNavigator();
    var iterator = nav.Select(expr);

    var results = new List<string>();
    while (iterator.MoveNext())
    {
        var current = iterator.Current;
        if (current != null)
        {
            var node = ((IHasXmlNode)current).GetNode();
            results.Add(node.InnerXml);
        }
    }

    return Results.Ok(results);
});

app.Run();

sealed class CustomXsltContext : XsltContext
{
    private readonly XsltArgumentList _args;

    public CustomXsltContext(XsltArgumentList args)
    {
        _args = args;
    }

    public override bool Whitespace => true;
    public override int CompareDocument(string baseUri, string nextbaseUri) => 0;
    public override bool PreserveWhitespace(XPathNavigator node) => true;

    public override IXsltContextVariable ResolveVariable(string prefix, string name)
    {
        return new XsltContextVariable(_args, prefix, name);
    }

    public override IXsltContextFunction ResolveFunction(string prefix, string name, XPathResultType[] ArgTypes)
    {
        throw new NotSupportedException();
    }
}

sealed class XsltContextVariable : IXsltContextVariable
{
    private readonly XsltArgumentList _args;
    private readonly string _prefix;
    private readonly string _name;

    public XsltContextVariable(XsltArgumentList args, string prefix, string name)
    {
        _args = args;
        _prefix = prefix;
        _name = name;
    }

    public bool IsLocal => false;
    public bool IsParam => true;
    public XPathResultType VariableType => XPathResultType.Any;

    public object Evaluate(XsltContext xsltContext)
    {
        return _args.GetParam(_name, _prefix) ?? string.Empty;
    }
}

record WeatherForecast(
    DateOnly Date,
    int TemperatureC,
    string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

record UserRegistration(string Username, string Password);
record TransferRequest(string ToAccount, decimal Amount);