using NLipsum.Core;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;

var builder = WebApplication.CreateBuilder(args);

// Look for the section "Clients" in appsettings.json
// and bind it to a list of Client objects
var clients = builder.Configuration.GetSection("Clients").Get<List<Client>>() ?? [];
var clientReg = builder.Configuration.GetSection("ClientReg").Get<List<ClientRegistrationDetails>>() ?? [];
var clientUsage = builder.Configuration.GetSection("ClientUsage").Get<List<ClientUsageDetails>>() ?? [];
var requestHistory = builder.Configuration.GetSection("RequestHistory").Get<Dictionary<int,List<RequestHistoryEntry>>>() ?? [];
var encryptionDetails = builder.Configuration.GetSection("Enc").Get<EncryptionDetails>() ?? throw new Exception("Enc section not found in appsettings.json");

const string masterKey = "XE3kSJJRPNY9zDqyGpsNH2kAapZbYko1OqNYqp0voSw=";
const string masterIv = "7l++7FEGWs+tjCGxz8RGYQ==";

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// Keep .NET property names as-is (PascalCase) in JSON responses
// so JavaScript clients receive `AccountName` instead of `accountName`.
builder.Services.ConfigureHttpJsonOptions(opts =>
{
    opts.SerializerOptions.PropertyNamingPolicy = null;
});

var app = builder.Build();
var lgen = new LipsumGenerator();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

// Serve static files from the "www" directory at the application root (no prefix).
app.UseStaticFiles(new StaticFileOptions
{
    FileProvider = new PhysicalFileProvider(Path.Combine(Directory.GetCurrentDirectory(), "www")),
    RequestPath = ""
});

app.MapGet("/getWords", (int count, int appCode) =>
{
    // Validate appCode
    var client = clients.FirstOrDefault(c => c.AppCode == appCode);
    if (client == null)
    {
        return Results.Unauthorized();
    }

    // Reset client requests if it's a new day
    ResetClientRequestsOnNewDay(clientUsage);

    // Make sure the client is allowed to make this request
    if (!APIRequestAllowed(appCode, count, clients, clientReg, clientUsage, requestHistory))
    {
        return Results.StatusCode(429); // Too Many Requests
    }

    var words = lgen.GenerateWords(count);

    // Record the request in the client's request history
    RecordRequestHistory(client, count, words, requestHistory);
    UpdateClientsFile(clients, clientReg, clientUsage, requestHistory);
    return Results.Ok(words);
})
.WithName("GetWords");

app.MapGet("/getParagraphs", (int count, int appCode) =>
{
    // Validate appCode
    var client = clients.FirstOrDefault(c => c.AppCode == appCode);
    if (client == null)
    {
        return Results.Unauthorized();
    }

    // Reset client requests if it's a new day
    ResetClientRequestsOnNewDay(clientUsage);

    // Make sure the client is allowed to make this request
    // Paragraph requests count as 5 requests per paragraph.
    if (!APIRequestAllowed(appCode, count * 5, clients, clientReg, clientUsage, requestHistory))
    {
        return Results.StatusCode(429); // Too Many Requests
    }

    var paragraphs = lgen.GenerateParagraphs(count);

    // Record the request in the client's request history
    RecordRequestHistory(client, count * 5, [.. paragraphs.SelectMany(p => p.Split(' '))], requestHistory);
    UpdateClientsFile(clients, clientReg, clientUsage, requestHistory);
    return Results.Ok(paragraphs);
})
.WithName("GetParagraphs");

app.MapPost("/registerClient", ([FromBody] RegisterClientRequest client) =>
{
    // Check if client with same account name already exists
    // If so, return conflict
    if (clients.Any(c => c.AccountName == client.AccountName))
    {
        return Results.Conflict("Client with same account name already exists.");
    }

    // Remove entries where RegistrationCodeExpiresAt is in the past.
    clientReg.RemoveAll(r => r.RegistrationCodeExpiresAt < DateTime.UtcNow);

    // Create a new Client Registration Details entry
    var appCode = GenerateAppCode();
    var regCode = GenerateAppCode();
    var regDetails = new ClientRegistrationDetails
    {
        AccountName = client.AccountName,
        AccountEmail = EncryptString(client.AccountEmail, masterKey, masterIv),
        AccountPassword = EncryptString(client.AccountPassword, masterKey, masterIv),
        RegistrationCode = regCode,
        RegistrationCodeExpiresAt = DateTime.UtcNow.AddMinutes(15)
    };
    clientReg.Add(regDetails);

    // Save to appsettings.json
    UpdateClientsFile(clients, clientReg, clientUsage, requestHistory);

    return Results.Ok(new RegisterClientConfirmation { Code = regCode });
}).WithName("RegisterClient");

app.MapGet("/updateRegistrationCode", (int oldCode) =>
{
    // Find the registration details with the given old code
    var regDetails = clientReg.FirstOrDefault(r => r.RegistrationCode == oldCode);
    if (regDetails == null)
    {
        return Results.NotFound("Registration code not found.");
    }

    // Generate a new registration code
    var newCode = GenerateAppCode();
    regDetails.RegistrationCode = newCode;
    regDetails.RegistrationCodeExpiresAt = DateTime.UtcNow.AddMinutes(15);

    // Save to appsettings.json
    UpdateClientsFile(clients, clientReg, clientUsage, requestHistory);

    return Results.Ok(new RegisterClientConfirmation { Code = newCode });
}).WithName("UpdateRegistrationCode");

app.MapPost("/confirmClientRegistration", ([FromBody] RegisterClientConfirmation conf) =>
{
    // Remove entries where RegistrationCodeExpiresAt is in the past.
    clientReg.RemoveAll(r => r.RegistrationCodeExpiresAt < DateTime.UtcNow);

    // Find the registration details with the given code
    var regDetails = clientReg.FirstOrDefault(r => r.RegistrationCode == conf.Code);
    if (regDetails == null || regDetails.RegistrationCodeExpiresAt < DateTime.UtcNow)
    {
        // Save to appsettings.json
        UpdateClientsFile(clients, clientReg, clientUsage, requestHistory);

        return Results.NotFound("Invalid or expired registration code.");
    }

    // Create a new Client entry
    var client = new Client
    {
        AccountName = regDetails.AccountName,
        AccountEmail = regDetails.AccountEmail,
        AccountPassword = regDetails.AccountPassword,
        AppCode = GenerateAppCode(),
        RegistrationDate = DateTime.UtcNow
    };
    clients.Add(client);

    // Remove the registration details as they are no longer needed
    clientReg.Remove(regDetails);

    // Save to appsettings.json
    UpdateClientsFile(clients, clientReg, clientUsage, requestHistory);

    return Results.Ok(new { AppCode = client.AppCode });

}).WithName("ConfirmClientRegistration");

app.MapGet("/enc", () =>
{
    using Aes aes = Aes.Create();
    aes.GenerateKey();
    aes.GenerateIV();

    var encDetails = new EncryptionDetails
    {
        key = EncryptString(Convert.ToBase64String(aes.Key), masterKey, masterIv),
        iv = EncryptString(Convert.ToBase64String(aes.IV), masterKey, masterIv)
    };

    return Results.Ok(encDetails);
}).WithName("GetEnc");

app.MapPost("/deregisterClient", ([FromBody] DeregisterClientRequest req) =>
{
    var client = clients.FirstOrDefault(c => c.AppCode == req.AppCode);
    if (client == null)
    {
        return Results.NotFound("Client not found.");
    }

    var decryptedPassword = DecryptString(client.AccountPassword, masterKey, masterIv);
    if (decryptedPassword != req.Password)
    {
        return Results.Unauthorized();
    }

    clients.Remove(client);

    // Also remove usage details
    var usageDetails = clientUsage.FirstOrDefault(cu => cu.AppCode == req.AppCode);
    if (usageDetails != null)
    {
        clientUsage.Remove(usageDetails);
    }

    // Save to appsettings.json
    UpdateClientsFile(clients, clientReg, clientUsage, requestHistory);

    return Results.Ok("Client deregistered successfully.");
}).WithName("DeregisterClient");

app.MapPost("/webClientLoginAllowed", ([FromBody] WebClientLogin login) =>
{
    // Find the client with the given account name
    var client = clients.FirstOrDefault(c => string.Equals(c.AccountName, login.AccountName, StringComparison.OrdinalIgnoreCase));
    // If not found, return unauthorized
    if (client == null)
    {
        return Results.Unauthorized();
    }
    // Generate the web code for the given account details
    var expectedWebCode = GetWebCode(client.AccountName,
                                          DecryptString(client.AccountEmail, masterKey, masterIv),
                                          DecryptString(client.AccountPassword, masterKey, masterIv)
                                      );
    // Compare the expected web code with the provided web code
    if (expectedWebCode != login.WebCode)
    {
        return Results.Unauthorized();
    }

    // If they match, return OK
    return Results.Ok("Login allowed.");
}).WithName("WebClientLoginAllowed");

// Add an endpoint that will open the clientlogin.html file in the browser
app.MapGet("/clientLogin", () =>
{
    var filePath = Path.Combine(Directory.GetCurrentDirectory(), "www/clientlogin.html");
    if (!System.IO.File.Exists(filePath))
    {
        return Results.NotFound("clientlogin.html file not found.");
    }

    return Results.File(filePath, "text/html");
}).WithName("ClientLogin");

// Add an endpoint that get's client info by web code.
app.MapPost("/getClientInfo", ([FromBody] ClientInfoRequest request) =>
{
    // Reset client requests if it's a new day
    ResetClientRequestsOnNewDay(clientUsage);

    // Find the client with the given account name
    var client = clients.FirstOrDefault(c => string.Equals(c.AccountName, request.AccountName, StringComparison.OrdinalIgnoreCase));
    // If not found, return unauthorized
    if (client == null)
    {
        return Results.Unauthorized();
    }
    // Generate the web code for the given account details
    var expectedWebCode = GetWebCode(client.AccountName,
                                          DecryptString(client.AccountEmail, masterKey, masterIv),
                                          DecryptString(client.AccountPassword, masterKey, masterIv)
                                      );
    // Compare the expected web code with the provided web code
    if (expectedWebCode != request.WebCode)
    {
        return Results.Unauthorized();
    }

    // Get the client usage details for the client.
    var usageDetails = clientUsage.FirstOrDefault(cu => cu.AppCode == client.AppCode);
    var usedTokens = usageDetails != null ? usageDetails.CurrentDailyRequests : 0;

    // Get the request history list for th client.
    var requests = requestHistory.ContainsKey(client.AppCode) ? requestHistory[client.AppCode] : [];

    // Get the average tokens per request from the client usage history.
    int totalTokens = requests.Sum(rh => rh.TokensUsed);
    int totalRequests = requests.Count;
    float averageTokensPerRequest = totalRequests > 0 ? (float)totalTokens / totalRequests : 0;

    var clientInfo = new ClientInfo
    {
        AccountName = client.AccountName,
        AccountEmail = DecryptString(client.AccountEmail, masterKey, masterIv),
        AppCode = client.AppCode,
        RegistrationDate = client.RegistrationDate,
        RequestHistory = requests,
        UsedTokens = usedTokens,
        MaxDailyTokens = usageDetails != null ? usageDetails.MaxAllowedDailyRequests: 0,
        AverageTokensPerRequest = averageTokensPerRequest
    };

    return Results.Ok(clientInfo);
}).WithName("GetClientInfo");

app.Run();

static (string key, string iv) DecryptEncryptionDetails(EncryptionDetails encDetails, string masterKey, string masterIv)
{
    ArgumentNullException.ThrowIfNull(encDetails);
    ArgumentNullException.ThrowIfNull(masterKey);
    ArgumentNullException.ThrowIfNull(masterIv);

    var key = DecryptString(encDetails.key, masterKey, masterIv);
    var iv = DecryptString(encDetails.iv, masterKey, masterIv);
    return (key, iv);
}

static string EncryptString(string str, string key, string iv, EncryptionDetails? encDetails = null)
{
    ArgumentNullException.ThrowIfNull(str);
    ArgumentNullException.ThrowIfNull(key);
    ArgumentNullException.ThrowIfNull(iv);

    // If encDetails is provided, decrypt key and iv from it
    if (encDetails != null)
    {
        (key, iv) = DecryptEncryptionDetails(encDetails, masterKey, masterIv);
    }

    using Aes aes = Aes.Create();
    aes.Key = Convert.FromBase64String(key);
    aes.IV = Convert.FromBase64String(iv);
    using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
    using var ms = new MemoryStream();
    using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
    {
        using var sw = new StreamWriter(cs);
        sw.Write(str);
    }
    return Convert.ToBase64String(ms.ToArray());
}

static string DecryptString(string cipherText, string key, string iv, EncryptionDetails? encDetails = null)
{
    ArgumentNullException.ThrowIfNull(cipherText);
    ArgumentNullException.ThrowIfNull(key);
    ArgumentNullException.ThrowIfNull(iv);

    // If encDetails is provided, decrypt key and iv from it
    if (encDetails != null)
    {
        (key, iv) = DecryptEncryptionDetails(encDetails, masterKey, masterIv);
    }

    using Aes aes = Aes.Create();
    aes.Key = Convert.FromBase64String(key);
    aes.IV = Convert.FromBase64String(iv);
    using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
    using var ms = new MemoryStream(Convert.FromBase64String(cipherText));
    using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
    using var sr = new StreamReader(cs);
    return sr.ReadToEnd();
}

static void UpdateClientsFile(List<Client> clients, List<ClientRegistrationDetails> clientReg, List<ClientUsageDetails> clientUsage, Dictionary<int, List<RequestHistoryEntry>> requestHistory)
{
    var configFile = "appsettings.json";
    var json = System.IO.File.ReadAllText(configFile);
    var jObject = JObject.Parse(json);
    jObject["Clients"] = JArray.FromObject(clients);
    jObject["ClientUsage"] = JArray.FromObject(clientUsage);
    jObject["ClientReg"] = JArray.FromObject(clientReg);
    jObject["RequestHistory"] = JObject.FromObject(requestHistory);
    System.IO.File.WriteAllText(configFile, jObject.ToString(Formatting.Indented));
}

static int GenerateAppCode()
{
    var rand = new Random();
    return rand.Next(100000, 999999);
}

static bool APIRequestAllowed(int appCode, int tokensToUse, List<Client> clients, List<ClientRegistrationDetails> clientReg, List<ClientUsageDetails> clientUsage, Dictionary<int, List<RequestHistoryEntry>> requestHistory)
{
    // Get the client usage details for the given appCode
    // If not found, create a new entry with default values
    var clientUsageDetails = clientUsage.FirstOrDefault(cu => cu.AppCode == appCode);
    if (clientUsageDetails == null)
    {
        clientUsageDetails = new ClientUsageDetails
        {
            AppCode = appCode,
            FirstRequest = null,
            MaxAllowedDailyRequests = 50, // Default limit
            CurrentDailyRequests = 0
        };
        clientUsage.Add(clientUsageDetails);
    }


    // Check if it's the first request of the day
    var today = DateTime.UtcNow.Date;
    if (clientUsageDetails.FirstRequest == null || clientUsageDetails.FirstRequest.Value.Date < today.AddDays(-1))
    {
        clientUsageDetails.FirstRequest = DateTime.UtcNow;
        clientUsageDetails.CurrentDailyRequests = 0;
    }

    // Make sure the client has not exceeded their daily request limit
    if (clientUsageDetails.CurrentDailyRequests + tokensToUse > clientUsageDetails.MaxAllowedDailyRequests)
    {
        return false; // Too Many Requests
    }
    else
    {
        clientUsageDetails.CurrentDailyRequests += tokensToUse;
        // Update the clients file with the new request count
        UpdateClientsFile(clients, clientReg, clientUsage, requestHistory);
    }

    return true;
}

static int GetWebCode(string accountName, string email, string password)
{
    // Make sure all parameters are non-null.
    // If any are null, throw an exception.
    if (accountName == null) throw new ArgumentNullException(nameof(accountName));
    if (email == null) throw new ArgumentNullException(nameof(email));
    if (password == null) throw new ArgumentNullException(nameof(password));

    // Get the combined string containing the given parameters.
    var combined = $"{accountName.ToLower()}:{email.ToLower()}:{password.ToLower()}";

    // Return a hash code that can be re-created in JavaScript using the same string.
    // This is done by getting the SHA256 hash of the string, then taking the first 4 bytes
    // and converting them to an integer.
    using var sha256 = SHA256.Create();
    var hash = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(combined));
    return BitConverter.ToInt32(hash, 0);
}

static void RecordRequestHistory(Client client, int tokensUsed, string[] words, Dictionary<int, List<RequestHistoryEntry>> requestHistory)
{
    // Break the firstWords into a list of strings. Remove any punctuation.
    var firstWords = words.Take(5).ToList();

    var reqHist = new RequestHistoryEntry
    {
        RequestTime = DateTime.UtcNow,
        TokensUsed = tokensUsed,
        FirstWords = firstWords
    };
    
    var clientAppCode = client.AppCode;
    requestHistory.TryGetValue(clientAppCode, out var historyList);
    if (historyList == null)
    {
        historyList = [];
        requestHistory[clientAppCode] = historyList;
    }

    historyList.Insert(0, reqHist);
    if (historyList.Count > 5)
    {
        historyList.RemoveRange(5, historyList.Count - 5);
    }
}

static void ResetClientRequestsOnNewDay(List<ClientUsageDetails> clientUsage)
{
    var today = DateTime.UtcNow.Date;
    foreach (var usage in clientUsage)
    {
        if (usage.FirstRequest == null || usage.FirstRequest.Value.Date < today)
        {
            usage.FirstRequest = DateTime.UtcNow;
            usage.CurrentDailyRequests = 0;
        }
    }
}

public record RegisterClientRequest
{
    public required string AccountName { get; set; }
    public required string AccountEmail { get; set; }
    public required string AccountPassword { get; set; }
    public DateTime RegistrationDate { get; set; } = DateTime.UtcNow;
}

public record RegisterClientConfirmation
{
    public int Code { get; set; }
    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddMinutes(15);
}

public record Client : RegisterClientRequest
{
    public int AppCode { get; set; }
}

public record ClientRegistrationDetails : RegisterClientRequest
{
    public int RegistrationCode { get; set; }
    public DateTime RegistrationCodeExpiresAt { get; set; }
}

public record ClientUsageDetails
{
    public int AppCode { get; set; }
    public DateTime? FirstRequest { get; set; }
    public int MaxAllowedDailyRequests { get; set; }
    public int CurrentDailyRequests { get; set; }
}

public record EncryptionDetails
{
    public required string key { get; set; }
    public required string iv { get; set; }
}

public record DeregisterClientRequest
{
    public required int AppCode { get; set; }
    public required string Password { get; set; }
}

public record WebClientLogin
{
    public required string AccountName { get; set; }
    public int WebCode { get; set; }
}

public record RequestHistoryEntry
{
    public DateTime RequestTime { get; set; }
    public int TokensUsed { get; set; }
    public List<string> FirstWords { get; set; } = [];
}

public record ClientInfo {
    public required string AccountName { get; set; }
    public required string AccountEmail { get; set; }
    public int AppCode { get; set; }
    public DateTime RegistrationDate { get; set; }
    public List<RequestHistoryEntry> RequestHistory { get; set; } = [];
    public int UsedTokens { get; set; } = 0;
    public int MaxDailyTokens { get; set; } = 0;
    public float AverageTokensPerRequest { get; set; } = 0;
}

public record ClientInfoRequest
{
    public required string AccountName { get; set; }
    public int WebCode { get; set; }
}
