# Config

Manage Harpoon's configuration file.

## Usage

Create or edit the configuration file in your `$EDITOR` (creating it from the
bundled template on first run):

```
harpoon config
```

Print the current configuration file:

```
harpoon config --show
```

Check which plugins are correctly configured:

```
harpoon config --check
```

## Configuration file

The configuration file lives at the OS-specific user config directory for
`harpoon` (e.g. `~/.config/harpoon/config` on Linux), as an INI file with one
section per plugin, named after the plugin's class (e.g. `[Circl]`,
`[UrlScan]`).
