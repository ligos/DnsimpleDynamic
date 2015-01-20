using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MurrayGrant.DnsimpleDynamic
{
    public class Config
    {
        public IDictionary<string, DnsName> names { get; set; }

        public string readPublicIpv4AddressFrom { get; set; }

        public string routerUser { get; set; }
        public string routerPassword { get; set; }
        public string routerAddress { get; set; }
        public IEnumerable<string> routerPublicInterfaces { get; set; }

        public string dnsimpleUsername { get; set; }
        public string dnsimpleApiToken { get; set; }


        public string randomString { get; set; }
        
        
    }

    public class DnsName
    {
        public bool? updatePublicIPv4 { get; set; }
        public bool? updatePrivateIPv4 { get; set; }
        public bool? updateIPv6 { get; set; }
        public int? ttl_ipv4 { get; set; }
        public int? ttl_ipv6 { get; set; }

        public IEnumerable<IPAddress> FilterAddresses(IEnumerable<IPAddress> addresses)
        {
            var includePublicIpv4 = this.updatePublicIPv4.GetValueOrDefault(true);
            var includePrivateIpv4 = this.updatePrivateIPv4.GetValueOrDefault(false);
            var includePublicIpv6 = this.updateIPv6.GetValueOrDefault(true);

            foreach (var a in addresses)
            {
                if (includePublicIpv6 && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    yield return a;
                else if (includePrivateIpv4 && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && a.IsIpv4PrivateAddress())
                    yield return a;
                else if (includePublicIpv4 && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !a.IsIpv4PrivateAddress())
                    yield return a;
            }
        }
    }
}
