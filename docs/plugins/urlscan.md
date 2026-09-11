# UrlScan

Search and view scans from [urlscan.io](https://urlscan.io/).

## Usage

Search urlscan.io for a domain, IP, or other query:

```
harpoon urlscan search QUERY
```

View a specific analysis by its UID:

```
harpoon urlscan view UID
```

Search a list of domains/IPs read from a file, one per line (automatically
waits out urlscan.io's rate limit if the quota is exceeded):

```
harpoon urlscan list FILE
```

## Configuration

An API key is optional but recommended (unauthenticated requests are more
limited):

```ini
[UrlScan]
key = <urlscan.io api key>
intel = true
```

## Intel integration

When enabled, `urlscan` implements `intel_ip()` and `intel_domain()`: it
searches urlscan.io for the indicator and adds each matching scan as a URL
entry in the aggregated [`intel`](intel.md) results.
