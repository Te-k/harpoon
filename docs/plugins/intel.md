# Intel

Gather intelligence on an IP address or a domain by querying every other
configured plugin that supports intel lookups, and merging the results.

## Usage

```
harpoon intel ip IP
harpoon intel domain DOMAIN
```

For each configured plugin with `intel = true` set in its configuration
section, `intel` calls that plugin's `intel_ip()` or `intel_domain()` method
and aggregates:

- **Passive DNS** records
- **Threat intelligence reports**
- **URLs** seen for the indicator

Results are printed grouped by category (reports, then passive DNS, then
URLs), sorted by date, each line tagged with the source plugin.

## Enabling a plugin for intel

A plugin only participates in `intel` if:

1. Its own configuration is valid (`is_config_valid()`), and
2. Its config section sets `intel = true`.

For example, to include [Circl](circl.md) and [Tor](tor.md) in intel
lookups:

```ini
[Circl]
user = <circl username>
pass = <circl password>
intel = true

[Tor]
intel = true
```
