using System;
using System.Collections.Generic;
using System.Dynamic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MurrayGrant.DnsimpleDynamic
{
    public class DnsimpleRecord
    {
        public int id { get; set; }
        public int domain_id { get; set; }
        public string record_type { get; set; }
        public string name { get; set; }
        public string content { get; set; }
        public int ttl { get; set; }
        
        public System.Net.IPAddress ContentAsIpAddress()
        {
            System.Net.IPAddress result;
            if (System.Net.IPAddress.TryParse(this.content, out result))
                return result;
            else
                return null;
        }

        public DnsimpleRecord(dynamic r)
        {
            var rec = (IDictionary<string, object>)r.record;
            this.id = Convert.ToInt32(rec["id"]);
            this.domain_id = Convert.ToInt32(rec["domain_id"]);
            this.record_type = (string)rec["record_type"];
            this.name = (string)rec["name"];
            this.content = (string)rec["content"];
            this.ttl = Convert.ToInt32(rec["ttl"]);
        }

        public override string ToString()
        {
            return this.record_type + ": " + this.content + " (id=" + this.id + ")";
        }
    }
}
