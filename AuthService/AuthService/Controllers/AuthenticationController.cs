using System.Net.Http.Headers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;

namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthenticationController : ControllerBase
{
    private string _KEYCLOAK_URL = Environment.GetEnvironmentVariable("KEYCLOAK_URL");
    private string _CLIENT_SECRET = Environment.GetEnvironmentVariable("CLIENT_SECRET");
    private string _API_URL = Environment.GetEnvironmentVariable("API_URL");

    private readonly ILogger<AuthenticationController> _logger;


    public AuthenticationController(ILogger<AuthenticationController> logger)
    {
        _logger = logger;
    }

    //http://localhost:8180/realms/zanzibar-dev/protocol/openid-connect/auth?client_id=auth-service&redirect_uri=https%3A%2F%2Flocalhost%3A7206%2FAuthentication%2Fexternal-callback&response_type=code&scope=openid%20profile%20email%20offline_access&kc_idp_hint=google
    [HttpGet("external-login/{provider}")]
    public IActionResult ExternalLogin(string provider)
    {
        string url =
            _KEYCLOAK_URL + "realms/zanzibar-dev/protocol/openid-connect/auth" +
            "?client_id=auth-service" +
            "&redirect_uri=" + _API_URL + "/Authentication/external-callback" +
            "&response_type=code" +
            "&scope=openid%20profile%20email%20offline_access%20roles" +
            "&kc_idp_hint=" + provider;

        return Redirect(url);
    }

    [HttpGet("external-callback")]
    public async Task<IActionResult> ExternalCallback(string code)
    {
        if (string.IsNullOrEmpty(code))
        {
            return BadRequest();
        }

        // Exchange authorization code for access token
        var tokenResponse = await ExchangeCodeForTokenAsync(code);

        if (tokenResponse != null && !string.IsNullOrEmpty(tokenResponse.AccessToken))
        {
            return Ok(tokenResponse);
        }
        else
        {
            return BadRequest();
        }
    }

    [HttpGet("userinfo")]
    public async Task<IActionResult> GetUserInfo()
    {
        if (HttpContext.Request.Headers.TryGetValue("Authorization", out var authHeader))
        {
            var accessToken =
                authHeader.ToString().Split(' ')[1]; // Extract the access token from the Authorization header

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                try
                {
                    var response =
                        await client.GetAsync(
                            _KEYCLOAK_URL + "realms/zanzibar-dev/protocol/openid-connect/userinfo");

                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync();
                        dynamic jsonObject = JsonConvert.DeserializeObject(content);
          
                        Response.ContentType = "application/json";
    
                        return Ok(jsonObject);
                    }
                    else
                    {
                        return Unauthorized(new
                            { message = "Failed to retrieve user information.", statusCode = response.StatusCode });
                    }
                }
                catch (Exception ex)
                {
                    // Handle exception
                    return StatusCode(500, new { message = "Internal server error.", error = ex.Message });
                }
            }
        }
        else
        {
            // Handle missing Authorization header
            return BadRequest(new { message = "Authorization header is missing." });
        }
    }

    private async Task<TokenResponse> ExchangeCodeForTokenAsync(string code)
    {
        var client = new HttpClient();

        var tokenEndpoint = _KEYCLOAK_URL + "/realms/zanzibar-dev/protocol/openid-connect/token";

        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("code", code), // The authorization code received in the callback
            new KeyValuePair<string, string>("client_id", "auth-service"), // Your client ID
            new KeyValuePair<string, string>("client_secret",
                _CLIENT_SECRET), // Your client secret
            new KeyValuePair<string, string>("redirect_uri",
                _API_URL + "/Authentication/external-callback"), // Your redirect URI
            new KeyValuePair<string, string>("scope", "openid profile email roles")
        });

        var response = await client.PostAsync(tokenEndpoint, content);

        if (response.IsSuccessStatusCode)
        {
            var responseContent = await response.Content.ReadAsStringAsync();
            var tokenResponse = JsonConvert.DeserializeObject<dynamic>(responseContent); 

            return new TokenResponse
            {
                AccessToken = tokenResponse.access_token,
                TokenType = tokenResponse.token_type,
                ExpiresIn = tokenResponse.expires_in,
                RefreshToken = tokenResponse.refresh_token,
            };
        }
        else
        {
            // Handle error
            return null;
        }
    }

    [HttpGet("RefreshToken")]
    public async Task<IActionResult> RefreshAccessTokenAsync()
    {
        // Retrieve the 'refresh_token' header value
        if (HttpContext.Request.Headers.TryGetValue("refresh_token", out var refreshToken))
        {
            // Extract and process the refresh token value
            var refreshTokenValue = refreshToken.ToString();
            var client = new HttpClient();
            var tokenEndpoint =
                 _KEYCLOAK_URL + "realms/zanzibar-dev/protocol/openid-connect/token"; // Replace with your Keycloak token endpoint
            var content = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "refresh_token"),
                new KeyValuePair<string, string>("refresh_token", refreshTokenValue),
                new KeyValuePair<string, string>("client_id", "auth-service"),
                new KeyValuePair<string, string>("client_secret", _CLIENT_SECRET),
                new KeyValuePair<string, string>("scope", "openid profile email roles")
            });

            var response = await client.PostAsync(tokenEndpoint, content);

            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonConvert.DeserializeObject<dynamic>(responseContent);

                TokenResponse token = new TokenResponse
                {
                    AccessToken = tokenResponse.access_token,
                    TokenType = tokenResponse.token_type,
                    ExpiresIn = tokenResponse.expires_in,
                    RefreshToken = tokenResponse.refresh_token
                };
                return Ok(token);
            }
        }
        return BadRequest();
    }


public class TokenResponse
    {
        public string AccessToken { get; set; }
        public string TokenType { get; set; }
        public int ExpiresIn { get; set; }
        public string RefreshToken { get; set; }
      
    }
}

