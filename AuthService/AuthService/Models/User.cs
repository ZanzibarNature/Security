namespace AuthService.Models;

public class User
{
    public string email_verified { get; set; }
    public string [] roles { get; set; }
    public string given_name { get; set; }
    public string family_name { get; set; }
    public string email { get; set; }
}