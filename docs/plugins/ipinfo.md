# IpInfo

Get geolocation and network information on an IP address from the local
[ip66.dev](https://ip66.dev/) MaxMind database.

## Usage

```
harpoon ipinfo IP
```

Prints the AS number and organization (when available) and the country for
the given IP. Use `--json` / `-j` to get the full record (continent,
country, registered country, RIR, and anonymous-IP/hosting/proxy/Tor
flags).

## Configuration

No credentials are required, but the local database must be present. It is
downloaded to the Harpoon config directory by
`harpoon.cli.download_needed_files()` and refreshed automatically once it is
more than a month old. If it hasn't been downloaded yet, `harpoon ipinfo`
fails with a `FileNotFoundError` pointing at the missing file.
