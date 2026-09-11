# Tor

Check if an IP address is a Tor exit node, using the public list at
<https://check.torproject.org/torbulkexitlist>.

## Usage

```
harpoon tor IP
```

Prints whether the given IP is currently listed as a Tor exit node.

## Configuration

No credentials are required. To include this plugin's results in
[`harpoon intel ip`](intel.md), add to the config file:

```ini
[Tor]
intel = true
```

## Intel integration

When enabled, `tor` implements `intel_ip()`: if the IP is currently a Tor
exit node, a report entry is added to the aggregated intel results.
