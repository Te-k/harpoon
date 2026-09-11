# Circl

Query the [CIRCL passive DNS database](https://www.circl.lu/services/passive-dns/).

## Usage

```
harpoon circl DOMAIN
```

Prints, for the given domain, every passive DNS record known to CIRCL:
first seen date, last seen date, record name, record type, and record data.

## Configuration

The `[Circl]` section of the config file requires:

```ini
[Circl]
user = <circl username>
pass = <circl password>
intel = true
```

`user` and `pass` are your CIRCL passive DNS credentials. Set `intel = true`
to have this plugin's passive DNS records included when running
[`harpoon intel domain`](intel.md).

## Intel integration

When enabled, `circl` implements `intel_domain()`: it queries CIRCL for the
domain and adds every match to the aggregated passive DNS results shown by
`harpoon intel domain`.
