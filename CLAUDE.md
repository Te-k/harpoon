# Harpoon

## Architecture

Harpoon is a plugin-based OSINT CLI. Source lives under `src/harpoon/` (src layout).

- **Entry point**: `harpoon.cli:cli` (registered as the `harpoon` console script). It loads
  the config file, builds an `argparse` parser with one subparser per plugin, dispatches to
  the matching plugin, and calls `prerun()` then `run()` on it.
- **Plugin registry**: `harpoon/plugins/__init__.py` exposes a flat `PLUGINS` list. Adding a
  plugin means implementing a class and appending it there.
- **`HarpoonPlugin` base class** (`harpoon/plugins/base.py`) drives every plugin's lifecycle:
  `run()` → `is_config_valid()` → `fetch()` → `display()`. `fetch()` does the actual work and
  sets `self.results`; `display()` renders it via `display_txt()` (plugin-specific, e.g. Rich
  tables or plain prints) or falls back to `display_json()` when `--json`/`-j` is passed or
  `display_txt()` isn't implemented.
- **Subcommands**: a plugin can nest child plugins with `add_subcommand()` (e.g.
  `urlscan search|view|list`, `intel ip|domain`). Each subcommand is itself a
  `HarpoonPlugin`, and `fetch()`/`display()` delegate to the active subcommand.
- **Intel aggregation**: the `intel` plugin (`plugins/intel.py`) iterates over every other
  registered plugin and calls its `intel_ip()`/`intel_domain()` hook when the plugin has
  valid config and `is_intel_enabled()` (an `intel = true` flag in its config section).
  Plugins that support this append findings to `self.passive_dns`, `self.reports`, and
  `self.urls`, which `intel` merges and prints via the `IntelSubcommand` mixin.
- **`harpoon/api/`**: thin HTTP client wrappers around external services (e.g.
  `api/urlscan.py`'s `UrlScanLibrary`), kept separate from the CLI/plugin logic in
  `plugins/`. Plugins call into these clients rather than making requests directly.
- **Configuration**: an INI file at `appdirs.user_config_dir("harpoon")/config`, one section
  per plugin class name (e.g. `[Circl]`, `[UrlScan]`). `HarpoonPlugin.config` resolves to
  that section; `config_structure` on a plugin lists required keys for `is_config_valid()`.
  `harpoon config` (edits) and `harpoon config --check` (validates) manage this file;
  `data/example.conf` is the template copied on first run.
- **`harpoon/utils.py`**: small shared helpers (e.g. `json_serial` for JSON-encoding
  `datetime`/`date` in `display_json()`).

## Formatting

Using ruff

## Tests

Using pytest
