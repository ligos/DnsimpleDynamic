using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace MurrayGrant.DnsimpleDynamic
{
    public static class Helpers
    {
        public static byte[] ParseFromHexString(string s)
        {
            var result = new byte[s.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = Byte.Parse(s.Substring(i*2, 2), System.Globalization.NumberStyles.HexNumber);
            }
            return result;
        }

        public static bool IsIpv4PrivateAddress(this IPAddress ip)
        {
            if (ip == null)
                throw new ArgumentNullException("ip");
            if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                return false;

            var addr = ip.GetAddressBytes();
            if (addr[0] == 192 && addr[1] == 168)
                return true;
            else if (addr[0] == 10)
                return true;
            else if (addr[0] == 172 && (addr[1] >= 16 || addr[1] <= 31))
                return true;
            else
                return false;

        }

        public static HashSet<T> ToHashSet<T>(this IEnumerable<T> collection)
        {
            return new HashSet<T>(collection, EqualityComparer<T>.Default);
        }
        public static HashSet<T> ToHashSet<T>(this IEnumerable<T> collection, IEqualityComparer<T> comparer)
        {
            return new HashSet<T>(collection, comparer);
        }
    }
}
