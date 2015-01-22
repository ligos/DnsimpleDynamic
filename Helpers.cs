// Copyright 2015 Murray Grant
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


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
