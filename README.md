# Check Unbound

## Table of Contents
- [Overview](#overview)
- [Usage examples](#usage-examples)
- [Configuration](#configuration)
  - [Asset registration](#asset-registration)
  - [Check definition](#check-definition)
- [Installation from source](#installation-from-source)
- [Additional notes](#additional-notes)
- [Contributing](#contributing)

## Overview

The Check Unbound is a [Sensu Check][6] that report unbound statistics.
The implementation of the pioneer https://github.com/letsencrypt/unbound_exporter is diverted.

## Usage examples

```
Simple cross-platform Unbound checks

Usage:
  check-unbound [flags]
  check-unbound [command]

Available Commands:
  help        Help about any command
  version     Print the version number of this plugin

Flags:
  -b, --binary string   Location of the unbound-control binary (default "/usr/sbin/unbound-control")
  -c, --config string   Location of the Unbound config file
  -h, --help            help for check-unbound
  -s, --sudo            Execute with root privileges

Use "check-unbound [command] --help" for more information about a command.
```

## Configuration

### Asset registration

[Sensu Assets][10] are the best way to make use of this plugin. If you're not using an asset, please
consider doing so! If you're using sensuctl 5.13 with Sensu Backend 5.13 or later, you can use the
following command to add the asset:

```
sensuctl asset add jadiunr/check-unbound
```

If you're using an earlier version of sensuctl, you can find the asset on the [Bonsai Asset Index][https://bonsai.sensu.io/assets/jadiunr/check-unbound].

### Check definition

```yml
---
type: CheckConfig
api_version: core/v2
metadata:
  name: check-unbound
  namespace: default
spec:
  command: check-unbound --sudo
  subscriptions:
  - system
  runtime_assets:
  - jadiunr/check-unbound
```

## Installation from source

The preferred way of installing and deploying this plugin is to use it as an Asset. If you would
like to compile and install the plugin from source or contribute to it, download the latest version
or create an executable script from this source.

From the local path of the check-unbound repository:

```
go build
```

## Additional notes

## Contributing

For more information about contributing to this plugin, see [Contributing][1].

[1]: https://github.com/sensu/sensu-go/blob/master/CONTRIBUTING.md
[2]: https://github.com/sensu-community/sensu-plugin-sdk
[3]: https://github.com/sensu-plugins/community/blob/master/PLUGIN_STYLEGUIDE.md
[4]: https://github.com/sensu-community/check-plugin-template/blob/master/.github/workflows/release.yml
[5]: https://github.com/sensu-community/check-plugin-template/actions
[6]: https://docs.sensu.io/sensu-go/latest/reference/checks/
[7]: https://github.com/sensu-community/check-plugin-template/blob/master/main.go
[8]: https://bonsai.sensu.io/
[9]: https://github.com/sensu-community/sensu-plugin-tool
[10]: https://docs.sensu.io/sensu-go/latest/reference/assets/
