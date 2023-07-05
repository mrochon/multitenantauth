namespace mysaasapp.Models
{
    public class TenantOptions
    {
        public TenantOptions()
        {
            Domain = String.Empty;
        }
        public string Domain { get; set; }
        public Dictionary<string, string>? TenantSubDomainMap { get; set; }
    }
}
