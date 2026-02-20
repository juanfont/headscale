# Upgrade an existing installation

!!! tip "Required update path"

    Its required to update from one stable version to the next (e.g. 0.26.0 → 0.27.1 → 0.28.0) without skipping minor
    versions in between. You should always pick the latest available patch release.

Update an existing Headscale installation to a new version:

- Read the announcement on the [GitHub releases](https://github.com/juanfont/headscale/releases) page for the new
  version. It lists the changes of the release along with possible breaking changes and version-specific upgrade
  instructions.
- Stop Headscale
- **[Create a backup of your installation](#backup)**
- Update Headscale to the new version, preferably by following the same installation method.
- Compare and update the [configuration](../ref/configuration.md) file.
- Start Headscale

## Backup

Headscale applies database migrations during upgrades and we highly recommend to create a backup of your database before
upgrading. A full backup of Headscale depends on your individual setup, but below are some typical setup scenarios.

=== "Standard installation"

    A installation that follows our [official releases](install/official.md) setup guide uses the following paths:

    - [Configuration file](../ref/configuration.md): `/etc/headscale/config.yaml`
    - Data directory: `/var/lib/headscale`
    - SQLite as database: `/var/lib/headscale/db.sqlite`

    ```console
    TIMESTAMP=$(date +%Y%m%d%H%M%S)
    cp -aR /etc/headscale /etc/headscale.backup-$TIMESTAMP
    cp -aR /var/lib/headscale /var/lib/headscale.backup-$TIMESTAMP
    ```

=== "Container"

    A installation that follows our [container](install/container.md) setup guide uses a single source volume directory
    that contains the configuration file, data directory and the SQLite database.

    ```console
    cp -aR /path/to/headscale /path/to/headscale.backup-$(date +%Y%m%d%H%M%S)
    ```

=== "PostgreSQL"

    Please follow PostgreSQL's [Backup and Restore](https://www.postgresql.org/docs/current/backup.html) documentation
    to create a backup of your PostgreSQL database.
