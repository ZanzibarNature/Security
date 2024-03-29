using System.Net.Http.Headers;
using AuthService.Models;
using AuthService.service.Interface;
using Newtonsoft.Json;


namespace AuthService.Service;

public class KeycloakService : IKeycloakService
{
    private readonly string _keycloakUrl = Environment.GetEnvironmentVariable("KEYCLOAK_URL");
    private readonly string _clientSecret = Environment.GetEnvironmentVariable("CLIENT_SECRET");
    private readonly string _apiUrl = Environment.GetEnvironmentVariable("API_URL");
    private readonly string _loginUrl = Environment.GetEnvironmentVariable("LOGIN_URL");

    public string GetLoginUrl(string provider)
    {
        string url =
            _loginUrl +
            "&redirect_uri=" + _apiUrl + "/Authentication/external-callback" +
            "&response_type=code" +
            "&scope=openid%20profile%20email%20offline_access%20roles" +
            "&kc_idp_hint=" + provider;
        return url;
    }
    public async Task<User> GetUserInfo(string accessToken)
    {
        var client = new HttpClient();

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        try
        {
            var response =
                await client.GetAsync(
                    _keycloakUrl + "userinfo");

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();
                User user = JsonConvert.DeserializeObject<User>(content);
                return user;
            }
        }
        catch (Exception e)
        {
            return null;
        }
        return null;
    }

    public async Task<Token> RefreshToken(string refreshToken)
    {
        var client = new HttpClient();
        var tokenEndpoint =
            _keycloakUrl +
            "token"; 
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new KeyValuePair<string, string>("refresh_token", refreshToken),
            new KeyValuePair<string, string>("client_id", "auth-service"),
            new KeyValuePair<string, string>("client_secret", _clientSecret),
            new KeyValuePair<string, string>("scope", "openid profile email roles")
        });
        try
        {
            var response = await client.PostAsync(tokenEndpoint, content);
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonConvert.DeserializeObject<dynamic>(responseContent);

                Token token = new Token()
                {
                    AccessToken = tokenResponse.access_token,
                    TokenType = tokenResponse.token_type,
                    ExpiresIn = tokenResponse.expires_in,
                    RefreshToken = tokenResponse.refresh_token
                };
                return token;
            }
        }
        catch (Exception e)
        {
            return null;
        }
        return null;
    }

    public async Task<string> Logout(string refreshToken)
    {
        var client = new HttpClient();
        var tokenEndpoint =
            _keycloakUrl +
            "revoke"; // Replace with your Keycloak token endpoint
        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("token", refreshToken),
            new KeyValuePair<string, string>("client_id", "auth-service"),
            new KeyValuePair<string, string>("client_secret", _clientSecret),
        });
        try
        { 
            var response = await client.PostAsync(tokenEndpoint, content);
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                return responseContent;
            }
        }
        catch (Exception e)
        {
            return null;
        }
        return null;
    }
    
    public async Task<Token> ExchangeCodeForTokenAsync(string code)
    {
        var client = new HttpClient();

        var tokenEndpoint = _keycloakUrl + "token";

        var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string, string>("grant_type", "authorization_code"),
            new KeyValuePair<string, string>("code", code), // The authorization code received in the callback
            new KeyValuePair<string, string>("client_id", "auth-service"), // Your client ID
            new KeyValuePair<string, string>("client_secret",
                _clientSecret), // Your client secret
            new KeyValuePair<string, string>("redirect_uri",
                _apiUrl + "/Authentication/external-callback"), // Your redirect URI
            new KeyValuePair<string, string>("scope", "openid profile email roles")
        });
        try
        { 
            var response = await client.PostAsync(tokenEndpoint, content);
            if (response.IsSuccessStatusCode)
            {
                var responseContent = await response.Content.ReadAsStringAsync();
                var tokenResponse = JsonConvert.DeserializeObject<dynamic>(responseContent);

                return new Token()
                {
                    AccessToken = tokenResponse.access_token,
                    TokenType = tokenResponse.token_type,
                    ExpiresIn = tokenResponse.expires_in,
                    RefreshToken = tokenResponse.refresh_token,
                };
            }
        }
        catch (Exception e)
        {
            return null;
        }
        return null;
    }
}