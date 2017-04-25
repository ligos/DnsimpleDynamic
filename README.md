# DnsimpleDynamic #

A Dynamic DNS client for [Dnsimple](http://dnsimple.com) in C#. Console program for Windows, designed to run as a scheduled task.

** IMPORTANT **

DnsimpleDynamic was coded for an older version of the Dnsimple API.
It will not work with the new API without modification.
When the old API is turned off, it will not work, period.

I no longer have need for dynamic IP updates, so have no plans to update to the new API.

** IMPORTANT **

## Features ##
* Multiple Domain Names
* Internal / private IPv4 addresses (eg: 192.168.x.x)
* Public IPv6 addresses
* Multiple IP addresses (the DNS record is updated with all addresses found)
* Can read public IPv4 from local network adapter, [ipify.org](ipify.org) or a [Mikrotik](http://routerboard.com/) router
* Passwords stored securely using [DPAPI](http://en.wikipedia.org/wiki/Data_Protection_API) (no plain text passwords in config files)
* Only queries the Dnsimple API if local DNS is out of date
* Apache License
* Should work with Mono on Linux (in theory, untested)
* No admin rights required; run as any user with network access
* Minimal file logging; by default only logs when IP addresses change

## Requirements ##
* A Windows computer (any version Vista / Server 2008 or newer should be fine)
* .NET 4.5
* Text editor
* Account with [Dnsimple](dnsimple.com)

## Setup ##
1. Download latest release from the [Downloads](https://bitbucket.org/ligos/dnsimpledynamic/downloads) section (on the left)
2. Unzip to a folder of your choosing (eg: c:\Program Files\DnsimpleDynamic)
3. Edit config.json to set your Dnsimple username (but not API token, enter it in step 5).
4. Add domain names to config.json (see below for sample configuration).
5. Run DnsimpleDynamic.exe once, it will ask you for you for your API token.
6. Create a scheduled task to run DnsimpleDynamic.exe every 5 minutes.
7. Reset your internet connection and get a different IP address to test the update.

## Configuration Examples ##

Configuration examples to get you up and running. Configuration file is in JSON format. The default `config.json` has all options available with comments.

### Minimal Config ###

This will get you started!

```
#!Javascript
{
    // One or more domain names to update with address information.
    // These will update IPv4 addresses (A records) and IPv6 addresses (AAAA records).
    // By default, this will update with public IPv4 and IPv6 (if available).
    "names": {
        "domain.com": { }
    },

    // Username and Account API token for Dnsimple.
    "dnsimpleUsername": "dnsimple@domain.com",
    "dnsimpleApiToken": null, // This will be read on first run from the console and saved in encrypted form.
}
```

### Multiple Domains ###

Note that this will read all IP addresses from the current computer. So all DNS entries will point to the same IP. You will need to run DnsimpleDynamic on **each computer** if you want different IP addresses.

```
#!Javascript
{
    // One or more domain names to update with address information.
    // These will update IPv4 addresses (A records) and IPv6 addresses (AAAA records).
    // By default, this will update with public IPv4 and IPv6 (if available).
    "names": {
        "domain.com": { },
        "sub.domain.com": { },
        "server.org": { }
    },

    // Username and Account API token for Dnsimple.
    "dnsimpleUsername": "dnsimple@domain.com",
    "dnsimpleApiToken": null, // This will be read on first run from the console and saved in encrypted form.
}
```

### Internal Addresses ###

Use Dnsimple to keep records of your internal devices / computers / servers. Useful to make sure SSL certificates are valid for internal servers.

Note, you only need one device to maintain your public IPv4 address, so you can remove the public address on all other devices. Note that IPv6 doesn't really have the concept of private addresses (well, technically it does, but there's no reason to use them), so you can't update private or link local IPv6 addresses with this.

```
#!Javascript
{
    // One or more domain names to update with address information.
    // These will update IPv4 addresses (A records) and IPv6 addresses (AAAA records).
    "names": {
        // This will have the public IPv4 address (and IPv6 if available)
        // Remove this if you're only interested in the private address.
        "computer.domain.com": { },
        // This will have the private IPv4 address (and public IPv6 if available)
        // I'm using the convention 'in' to group internal addresses.
        "computer.in.domain.com": { 
            "updatePublicIPV4": false,        // Disable updates for public IPv4 address
            "updatePrivateIPV4": true,        // Update with private address instead (eg: 192.168.1.2 or 10.1.2.3)
        }
    },

    // Username and Account API token for Dnsimple.
    "dnsimpleUsername": "dnsimple@domain.com",
    "dnsimpleApiToken": null, // This will be read on first run from the console and saved in encrypted form.
}
```

### Custom TTLs ###

DNS records all have a TTL (time to live), which affects how long they are cached for. By default, DnsimpleDynamic uses a 10 minute TTL (the minimum possible on the Dnsimple web control panel), but you can set any value you want. If you know your IP rarely (or never) changes and are happy to live for a period of time when your DNS name will be wrong, you can set your TTL to be 1 hour.

IPv6 addresses work differently to IPv4 ones. It's common for a computer to have a *preferred* IPv6 address, and multiple *temporary* IPv6 addresses, which are still valid for the computer. So, you can safely set IPv6 TTLs higher. DnsimpleDynamic will maintain the preferred IPv6 address, but if DNS servers are still using the older temporary IPv6 address, your computer will still be reachable. (On a side note, IPv6 rocks)!

```
#!Javascript
{
    // One or more domain names to update with address information.
    // These will update IPv4 addresses (A records) and IPv6 addresses (AAAA records).
    // To update with 
    "names": {
        // This will have the public IPv4 address (and IPv6 if available)
        "domain.com": { 
            "ttl_ipv6": 3600,    // 1 hour TTL
            "ttl_ipv4": 300,      // 5 minute TTL
        },
        // This will have the public IPv4 address (and IPv6 if available)
        "server.domain.com": { 
            "ttl_ipv6": 7200,    // 2 hour TTL
            "ttl_ipv4": 7200,    // 2 hour TTL
        }
    },

    // Username and Account API token for Dnsimple.
    "dnsimpleUsername": "dnsimple@domain.com",
    "dnsimpleApiToken": null, // This will be read on first run from the console and saved in encrypted form.
}
```


### Additional Security ###

A random string will add to the entropy used by the password encryption function. This does not have to be the same if you're running DnsimpleDynamic on multiple computers.

```
#!Javascript
{
   ....

    // Add a random string here to add additional security to the encrypted secret values.
    "randomString": "some random string"
}
```