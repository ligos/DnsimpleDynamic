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
using System.Dynamic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Net;
using System.Net.NetworkInformation;
using Newtonsoft.Json;
using System.IO;
using Tik4Net;
using DNSimple;

namespace MurrayGrant.DnsimpleDynamic
{
    class Program
    {
        private static readonly byte[] _BaseEntropy = Helpers.ParseFromHexString("c33125b1645ef008c915d9fb0f2dedfb3d3b3c8de0edc5056b66b4693e5b7191");
        private static readonly NLog.Logger Log = NLog.LogManager.GetCurrentClassLogger();
        private static readonly int _DefaultTTL = 10 * 60;       // 10 minute TTL by default (the minimum in Dnsimple UI).

        static void Main(string[] args)
        {
            var t = DoIt();
            try
            {
                t.Wait(TimeSpan.FromMinutes(4));        // 4 minutes assumes this runs every ~5 minutes on a scheduled task.
            }
            catch (AggregateException ex)
            {
                Log.Fatal("Unhandled exception when updating Dnsimple address.", ex);
            }
            finally
            {
                NLog.LogManager.Flush(TimeSpan.FromSeconds(15));
                NLog.LogManager.Shutdown();
            }

            if (Environment.UserInteractive)
            {
                Console.WriteLine("Press enter to end.");
                Console.ReadLine();
            }
        }

        private static async Task DoIt()
        {
            if (Environment.UserInteractive)
                Console.WriteLine("Dnsimple Dynamic DNS updater\nCopyright (c) Murray Grant 2015");

            // Load file with config.
            var config = await Task.Run(() =>
            {
                var configFile = "config.json";
                Log.Trace("Loading configuration file '{0}'...", configFile);
                var str = File.ReadAllText(configFile);
                var conf = JsonConvert.DeserializeObject<Config>(str);
                Log.Debug("Loaded configuration file '{0}' OK.", configFile);
                if (conf.names == null)
                    conf.names = new Dictionary<string, DnsName>();
                return conf;
            });

            // Ensure we have required credentials.
            if (String.Equals(config.readPublicIpv4AddressFrom, "MikrotikRouter", StringComparison.OrdinalIgnoreCase) && (String.IsNullOrEmpty(config.routerPassword) || !CanUnprotectSecret("routerPassword", config.routerPassword, config.randomString) ))
            {
                Log.Debug("Mikrotik Router password is required but is not available. Requesting from user.");
                config.routerPassword = ReadSecret("Enter router password", config.randomString);
                Log.Debug("Mikrotik Router password read from user and encrypted OK. Will save config file.");
                await UpdateConfigValue("routerPassword", config.routerPassword);
            }
            if (String.IsNullOrEmpty(config.dnsimpleApiToken))
            {
                Log.Debug("Dnsimple Token is required but is not available. Requesting from user.");
                config.dnsimpleApiToken = ReadSecret("Enter Dnsimple API token", config.randomString);
                Log.Debug("Dnsimple Token password read from user and encrypted OK. Will save config file.");
                await UpdateConfigValue("dnsimpleApiToken", config.dnsimpleApiToken);
            }

            // Obtain public IP addresses.
            var ipv6AddrTask = GetPublicIpv6Addresses();
            var ipv4PrivateAddrTask = GetPrivateIpv4Addresses();
            var ipv4PublicAddrTask = GetPublicIpv4Addresses(config);
            await Task.WhenAll(ipv4PublicAddrTask, ipv6AddrTask, ipv4PrivateAddrTask);
            var preferredIpv6 = ipv6AddrTask.Result.FirstOrDefault();
            var allAddresses = ipv6AddrTask.Result.Concat(ipv4PrivateAddrTask.Result).Concat(ipv4PublicAddrTask.Result);
            Log.Debug("All IP addresses found: {0}.", String.Join(", ", allAddresses));

            // Lookup hosts and update if they do not match.
            Log.Debug("Checking DNS addresses for {0:N0} name(s).", config.names.Count());
            foreach (var domain in config.names)
            {
                // Filter all candidate addresses for this domain down to allowed addresses based on config.
                if (domain.Value.updatePrivateIPv4.GetValueOrDefault(false) && domain.Value.updatePublicIPv4.GetValueOrDefault(true))
                    Log.Warn("Updating public and private IPv4 addresses against the same DNS name is not recommended.");
                var possibleAddresses = domain.Value.FilterAddresses(allAddresses).ToHashSet();

                // Lookup.
                Log.Trace("Doing DNS lookup on '{0}'...", domain.Key);
                var dnsAddresses = (await LookupDns(domain.Key)).ToHashSet();
                Log.Trace("Found {0:N0} address(es) for '{1}': {2}", dnsAddresses.Count, domain.Key, String.Join(", ", dnsAddresses.Select(x => x.ToString())));
                
                // Compare with addresses we found above.
                var anyNotFound = possibleAddresses.Except(dnsAddresses)
                          .Concat(dnsAddresses.Except(possibleAddresses))
                          .Any();

                // If either doesn't match...
                if (anyNotFound)
                {
                    Log.Debug("Current address(es) do not match DNS records for '{0}': querying Dnsimple to update...", domain.Key);
                    // Fetch records for the domain such that we can update them.
                    var records = await LoadDnsimpleRecords(config, domain.Key);

                    // Update.
                    await UpdateDnsimpleRecord(config, domain, records, possibleAddresses);
                }
                else
                {
                    Log.Debug("Current addres(es) match DNS records for '{0}': no update required.", domain.Key);
                }
            }
            Log.Debug("Finished checking DNS addresses for {0:N0} name(s).", config.names.Count());
        }


        private static string ReadSecret(string prompt, string random)
        {
            if (!Environment.UserInteractive)
                throw new Exception("Unable to read secret data in non-interactive session (eg: scheduled task). Please re-run from a command prompt to enter passwords.");

            var sb = new StringBuilder();
            Console.Write(prompt + ": ");

            var hPos = Console.CursorLeft;
            var key = Console.ReadKey(false);
            while (key.Key != ConsoleKey.Enter && key.Key != ConsoleKey.Escape)
            {
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (sb.Length > 0)
                        sb.Remove(sb.Length - 1, 1);
                }
                else
                    sb.Append(key.KeyChar);

                Console.CursorLeft = hPos;
                Console.Write("     ");
                Console.CursorLeft = hPos;
                Console.Write(sb.Length);

                key = Console.ReadKey(false);
            }
            Console.WriteLine();

            if (key.Key == ConsoleKey.Escape)
                throw new Exception(String.Format("Aborted entry of secret with prompt '{0}'", prompt));
                

            // Encrypt with per-user DPAPI.
            var unencrypted = Encoding.UTF8.GetBytes(sb.ToString());
            var entropy = new SHA256Managed().ComputeHash(_BaseEntropy.Concat(Encoding.UTF8.GetBytes(random)).ToArray());
            var encrypted = ProtectedData.Protect(unencrypted, entropy, DataProtectionScope.CurrentUser);

            return Convert.ToBase64String(encrypted);
        }

        private static string UnprotectSecret(string protectedValue, string random)
        {
            var encrypted = Convert.FromBase64String(protectedValue);
            var entropy = new SHA256Managed().ComputeHash(_BaseEntropy.Concat(Encoding.UTF8.GetBytes(random)).ToArray());
            var unencrypted = ProtectedData.Unprotect(encrypted, entropy, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(unencrypted);
        }
        private static bool CanUnprotectSecret(string key, string protectedValue, string random)
        {
            try
            {
                var encrypted = Convert.FromBase64String(protectedValue);
                var entropy = new SHA256Managed().ComputeHash(_BaseEntropy.Concat(Encoding.UTF8.GetBytes(random)).ToArray());
                var unencrypted = ProtectedData.Unprotect(encrypted, entropy, DataProtectionScope.CurrentUser);
                var result = Encoding.UTF8.GetString(unencrypted);
                return true;
            }
            catch (Exception ex)
            {
                Log.Debug(String.Format("Unable to unprotect secret '{0}'.", key), ex);
                return false;
            }
        }

        public static Task UpdateConfigValue(string key, string value)
        {
            Log.Debug("Saving configuration value '{0}': starting background task.", key);
            return Task.Run(() =>
            {
                var configFile = "config.json";
                Log.Trace("Starting to save key '{1}' in configuration file '{0}'.", configFile, key);
                // Rather than using JsonConvert.SerializeObject(), we load the file and do a string replace.
                // This way, we preserve comments.
                var lines = File.ReadAllLines(configFile);
                var keyWithQuotes = "\"" + key + "\"";
                var l = lines.FirstOrDefault(x => x.Contains(keyWithQuotes));
                var idx = Array.IndexOf(lines, l);
                if (l == null || idx == -1)
                    throw new Exception(String.Format("Unable to find configuration key '{0}': not in config file.", key));
                var separatorIdx = l.IndexOf(':');
                if (separatorIdx == -1)
                    throw new Exception(String.Format("Unable to parse configuration key '{0}': cannot find ':'.", key));
                l = l.Substring(0, separatorIdx) + " : \"" + value + "\",";
                lines[idx] = l;
                File.WriteAllLines(configFile, lines, Encoding.UTF8);
                Log.Debug("Successfully saved key '{1}' in configuration file '{0}'.", configFile, key);
            });
        }

        public static Task<IEnumerable<IPAddress>> LookupDns(string hostName)
        {
            return Task.Run(() =>
            {
                try
                {
                    return Dns.GetHostAddresses(hostName).AsEnumerable();
                }
                catch (System.Net.Sockets.SocketException ex)
                {
                    Log.Trace(String.Format("Got exception when doing DNS lookup: no addresses found for host '{0}'.", hostName), ex);
                    return Enumerable.Empty<IPAddress>();
                }
            });
        }

        public static Task<IEnumerable<IPAddress>> GetPublicIpv6Addresses()
        {
            return Task.Run(() => 
                {
                    Log.Trace("Enumerating public IPv6 addresses...");
                    var result = IPGlobalProperties.GetIPGlobalProperties().GetUnicastAddresses()
                                                .Where(x => x.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                                                        && !x.Address.IsIPv6LinkLocal
                                                        && !x.Address.IsIPv6Teredo
                                                        && !x.Address.IsIPv6SiteLocal
                                                        && x.IsDnsEligible)
                                                .OrderBy(x => x.AddressPreferredLifetime)
                                                .Select(x => x.Address)
                                                .ToList()
                                                .AsEnumerable();
                    Log.Debug("Enumerated {0:N0} public IPv6 address(es): {1}", result.Count(), String.Join(", ", result.Select(x => x.ToString())));
                    return result;
                });
        }

        public static Task<IEnumerable<IPAddress>> GetPrivateIpv4Addresses()
        {
            return Task.Run(() =>
            {
                Log.Trace("Enumerating private IPv4 addresses...");
                var result = IPGlobalProperties.GetIPGlobalProperties().GetUnicastAddresses()
                                            .Where(x => x.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                                                    && x.Address.IsIpv4PrivateAddress()
                                                    && x.IsDnsEligible)
                                            .OrderBy(x => x.AddressPreferredLifetime)
                                            .Select(x => x.Address)
                                            .ToList()
                                            .AsEnumerable();
                Log.Debug("Enumerated {0:N0} private IPv4 address(es): {1}", result.Count(), String.Join(", ", result.Select(x => x.ToString())));
                return result;
            });
        }

        public static Task<IEnumerable<IPAddress>> GetPublicIpv4Addresses(Config config)
        {
            if (String.Equals(config.readPublicIpv4AddressFrom, "MikrotikRouter", StringComparison.OrdinalIgnoreCase))
                return ReadPublicIpv4AddressesFromMikrotikRouter(config);
            else if (String.Equals(config.readPublicIpv4AddressFrom, "Ipify", StringComparison.OrdinalIgnoreCase))
                return Task.Run(() => new [] { ReadPublicIpv4AddressFromIpify(config).Result }.AsEnumerable());
            else
                throw new Exception("Unknown method of getting public IPv4 address: " + config.readPublicIpv4AddressFrom);
        }
        public static Task<IEnumerable<IPAddress>> ReadPublicIpv4AddressesFromMikrotikRouter(Config config)
        {
            return Task.Run(() =>
                {
                    Log.Trace("Reading public IPv4 addresses from Mikrotik Router ({0})...", config.routerAddress);
                    using (var session = new TikSession(TikConnectorType.Api))
                    {
                        var password = UnprotectSecret(config.routerPassword, config.randomString);
                        session.Open(config.routerAddress, config.routerUser, password);
                        Log.Trace("Connected to router OK.");
                        var conn = (Tik4Net.Connector.Api.IApiConnector)session.Connector;
                        var result = new List<IPAddress>();
                        foreach (var iface in config.routerPublicInterfaces)
                        {
                            var publicIp = conn.ApiExecuteReader("/ip/address/print\n?interface=" + iface).FirstOrDefault();
                            if (publicIp == null)
                            {
                                Log.Warn("Unable to find interface in router: " + iface);
                                continue;
                            }
                            var ipAndMask = publicIp.GetStringValueOrNull("address", true);
                            var ip = ipAndMask.Substring(0, ipAndMask.LastIndexOf('/'));
                            Log.Debug("Read public IPv4 address '{0}' from Mikrotik Router OK.", ip);
                            result.Add(IPAddress.Parse(ip));
                        }
                        return result.AsEnumerable();
                    }
                });
        }
        public static async Task<IPAddress> ReadPublicIpv4AddressFromIpify(Config config)
        {
            Log.Trace("Reading public IPv4 address using ipify.org...");
            var response = await new WebClient().DownloadStringTaskAsync("http://api.ipify.org/");
            Log.Debug("Read public IPv4 address '{0}' from ipify.org OK.", response);
            return IPAddress.Parse(response);
        }

        public static Task<IEnumerable<DnsimpleRecord>> LoadDnsimpleRecords(Config config, string fqDomainName)
        {
            return Task.Run(() =>
                {
                    var domainName = DeriveBaseDomainName(fqDomainName);
                    Log.Trace("Loading DNS records for '{0}' (for '{1}').", domainName, fqDomainName);
                    var token = UnprotectSecret(config.dnsimpleApiToken, config.randomString);
                    var client = new DNSimpleRestClient(config.dnsimpleUsername, token: token);

                    var records = client.ListRecords(domainName);
                    int recordCount;
                    try 
                    { 
                        recordCount = (int)records.Length;
                    }
                    catch (Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
                    {
                        // Length property does not exist: probably because of a failure.
                        throw new Exception("Error when loading Dnsimple records: " + records.message);
                    }
                    Log.Debug("Loaded {0:N0} DNS record(s) for '{1}' (for '{2}').", recordCount, domainName, fqDomainName);
                    return ((ExpandoObject[])records).Select(x => new DnsimpleRecord(x)).ToList().AsEnumerable();
                });
        }


        public static Task UpdateDnsimpleRecord(Config config, KeyValuePair<string, DnsName> domain, IEnumerable<DnsimpleRecord> records, IEnumerable<IPAddress> addresses)
        {
            return Task.Run(() =>
            {
                var token = UnprotectSecret(config.dnsimpleApiToken, config.randomString);
                var client = new DNSimpleRestClient(config.dnsimpleUsername, token: token);
                var fqDomainName = domain.Key;
                var domainName = DeriveBaseDomainName(domain.Key);
                var subName = DeriveSubDomainName(domain.Key);

                // It is possible for a computer to have multiple IP addresses (much more common with IPv6, but with multiple NICs, quite possible with IPv4 as well).
                // So we maintain them in multiple records.
                // When a record changes, a new record is added and the old one removed (no in-place updates).

                Log.Trace("Checking addresses for '{0}'...", fqDomainName);
                foreach (var addrGrp in addresses.GroupBy(x => x.AddressFamily))
                {
                    var v4orv6 = addrGrp.Key == System.Net.Sockets.AddressFamily.InterNetwork ? "IPv4" : "IPv6";
                    var recordType = addrGrp.Key == System.Net.Sockets.AddressFamily.InterNetwork ? "A" : "AAAA";
                    var ttl = addrGrp.Key == System.Net.Sockets.AddressFamily.InterNetwork ? domain.Value.ttl_ipv4.GetValueOrDefault(_DefaultTTL) : domain.Value.ttl_ipv6.GetValueOrDefault(_DefaultTTL);

                    
                    Log.Trace("Checking {0} addresses to add for '{1}'...", v4orv6, fqDomainName);
                    foreach (var address in addrGrp)
                    {
                        // Check address.
                        var record = records.FirstOrDefault(x => x.record_type == recordType && x.ContentAsIpAddress().Equals(address) && String.Equals(x.name, subName, StringComparison.InvariantCultureIgnoreCase));

                        if (record == null)
                        {
                            // A new address.
                            Log.Debug("Adding '{0}' record for '{1}' (domain '{2}'): {3}.", recordType, fqDomainName, domainName, address);
                            client.AddRecord(domainName, subName, recordType, address.ToString(), ttl: ttl);
                            Log.Info("New {0} address detected for '{1}' - added '{2}' OK.", v4orv6, fqDomainName, address);
                        }
                        else
                        {
                            // Address has not changed: no action required.
                            Log.Trace("Address '{0}' is correct in DNS: unchanged.", address);
                        }

                    }


                    // Now, check for addresses which need to be removed.
                    Log.Trace("Checking for {0} addresses to remove for '{1}'...", v4orv6, fqDomainName);
                    foreach (var record in records.Where(x => x.record_type == recordType && String.Equals(x.name, subName, StringComparison.InvariantCultureIgnoreCase)))
                    {
                        if (!addrGrp.Contains(record.ContentAsIpAddress()))
                        {
                            // Address has changed / been released and needs to be removed.
                            Log.Debug("Deleting stale '{0}' record for '{1}' (domain '{2}'): {3}.", recordType, fqDomainName, domainName, record.ContentAsIpAddress());
                            client.DeleteRecord(domainName, record.id);
                            Log.Info("Stale {0} address detected for '{1}' - removed '{2}' OK.", v4orv6, fqDomainName, record.ContentAsIpAddress());
                        }
                        else
                        {
                            // Address remains: no action required.
                            Log.Trace("Address '{0}' is correct in DNS: unchanged.", record.ContentAsIpAddress());
                        }

                    }
                }
            });
        }

        private static string DeriveBaseDomainName(string fqDomainName)
        {
            var secondSegmentIdx = fqDomainName.LastIndexOf('.', fqDomainName.LastIndexOf('.')-1);
            var domainName = fqDomainName;
            if (secondSegmentIdx != -1)
                domainName = fqDomainName.Substring(secondSegmentIdx+1);
            return domainName;
        }
        private static string DeriveSubDomainName(string fqDomainName)
        {
            var secondSegmentIdx = fqDomainName.LastIndexOf('.', fqDomainName.LastIndexOf('.')-1);
            var subDomainName = "";
            if (secondSegmentIdx != -1)
                subDomainName = fqDomainName.Substring(0, secondSegmentIdx);
            return subDomainName;

        }
    }
}
