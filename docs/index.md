# Harpoon

Harpoon is an OSINT / Threat Intel CLI tool. It queries a range of security
and intelligence services (passive DNS, URL scanning, Tor exit node lists,
and more) through a single `harpoon` command, and lets you correlate
information about an IP address or a domain across all of them at once.

## Installation

```
pip install harpoon
```

Or from source:

```
git clone https://github.com/Te-k/harpoon.git
cd harpoon
pip3 install .
```

## Configuration

Harpoon stores its configuration in an INI file managed with:

```
harpoon config
```

This opens the config file (created from a template on first run) in your
`$EDITOR`. Each plugin that needs credentials or settings has its own
section in that file, named after the plugin's class (e.g. `[Circl]`,
`[UrlScan]`).

Check which plugins are fully configured with:

```
harpoon config --check
```

## Usage

```
harpoon COMMAND [ARGS...]
```

Get help on any command with:

```
harpoon help COMMAND
```

Add `--json` / `-j` to any command to get machine-readable JSON output
instead of the default text rendering.

## Architecture

Harpoon is built around a small plugin system:

- Every command (`circl`, `urlscan`, `tor`, ...) is a plugin: a class that
  subclasses `HarpoonPlugin` and is registered in the plugin list.
- A plugin's lifecycle is `fetch()` (do the work, populate `self.results`)
  followed by `display()` (render `self.results` as text or JSON).
- Plugins can expose subcommands (e.g. `urlscan search`, `urlscan view`) and
  can optionally implement `intel_ip()` / `intel_domain()` to participate in
  the cross-plugin `intel` command, which aggregates passive DNS records,
  reports, and URLs from every configured plugin for a given indicator.

See the [Plugins](plugins/circl.md) section for one page per available
plugin, and the project's `CLAUDE.md` for more implementation detail.

## License

Harpoon is released under the [GPLv3](https://github.com/Te-k/harpoon/blob/main/LICENSE) license.
