# Changelog

## [Unreleased]

- Upgrade lxml to 4.6.2 and pycrtsh to 0.3.4 following a security issue in lxml

## 0.1.6 - 2020-12-17

- Added the [Koodous plugin](https://github.com/Te-k/harpoon/issues/116)
- Added the [PulseDive plugin](https://github.com/Te-k/harpoon/issues/140)
- Added the [Cisco Umbrella plugin](https://github.com/Te-k/harpoon/issues/138)
- Reworked the high level plugins under the intel plugin : `intel ip`, `intel domain` and `intel hash`
- Added the [IMB X-Force Exchange plugin](https://github.com/Te-k/harpoon/issues/65)
- Added the [urlhaus plugin](https://github.com/Te-k/harpoon/issues/125) by @christalib
- Migrated update code from `harpoon config -u` to `harpoon update`
- Added the [ThreatCrowd plugin](https://github.com/Te-k/harpoon/pull/139) by @christalib
- Migrated the GreyNoise plugin to the [GreyNoise v2 API](https://github.com/Te-k/harpoon/pull/135) by @christalib
- Added the [ThreatMinor plugin](https://github.com/Te-k/harpoon/issues/13)
- Added the [Tor Exit Node plugin](https://github.com/Te-k/harpoon/issues/129)
- Migrated the MISP plugin to pymisp instead of mispy
- Removed the Bitly plugin following deprecation of Bitly V3 API
- Added a Zetalytics plugin
- Added more documentation
