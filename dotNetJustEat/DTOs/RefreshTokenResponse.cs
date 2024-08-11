namespace dotNetJustEat.DTOs
{
    public class RefreshTokenResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public int Duration { get; set; }
    }
}
