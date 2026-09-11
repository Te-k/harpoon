# Shodan

Get information on an IP address from [Shodan](https://www.shodan.io/).

## Usage

```
harpoon shodan IP
```

Prints, for the given IP, each banner Shodan has on record: timestamp,
module (e.g. `http`, `https`, `dns-tcp`), transport/port, and the raw
service data. Use `--json` / `-j` to get the full raw host record from the
Shodan API instead.

## Configuration

The `[Shodan]` section of the config file requires an API key:

```ini
[Shodan]
key = <shodan api key>
```

Get a key by [registering on Shodan](https://account.shodan.io/register).
