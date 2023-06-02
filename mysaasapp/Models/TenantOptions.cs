namespace mysaasapp.Models
{
    public class TenantOptions
    {
        public string? Domain { get; set; }
        public Dictionary<string, string>? TenantSubDomainMap { get; set; }
    }
}
