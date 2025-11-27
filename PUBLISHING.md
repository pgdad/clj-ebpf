# Publishing to Clojars

This document describes how to publish clj-ebpf to [Clojars](https://clojars.org).

## Prerequisites

1. **Clojars Account**: Create an account at https://clojars.org
2. **Deploy Token**: Generate a deploy token (not your account password)
   - Log in to Clojars
   - Go to your profile → Settings → Deploy Tokens
   - Create a new token with appropriate permissions
3. **Java 21+**: Required for building and running clj-ebpf
4. **Clojure CLI**: Install from https://clojure.org/guides/install_clojure

## Setup

### Environment Variables

Set these environment variables before deploying:

```bash
export CLOJARS_USERNAME="your-clojars-username"
export CLOJARS_PASSWORD="your-deploy-token"
```

> **Important**: `CLOJARS_PASSWORD` should be your deploy token, not your account password.

### Optional: Store credentials securely

You can store credentials in `~/.m2/settings.xml`:

```xml
<settings>
  <servers>
    <server>
      <id>clojars</id>
      <username>your-clojars-username</username>
      <password>your-deploy-token</password>
    </server>
  </servers>
</settings>
```

## Build Commands

### Clean build artifacts

```bash
clj -T:build clean
```

### Build JAR file

```bash
clj -T:build jar
```

This creates `target/clj-ebpf-{version}.jar` where version is based on git commit count.

### Install to local Maven repository

```bash
clj -T:build install
```

Useful for testing the library locally before publishing.

### Deploy to Clojars

```bash
clj -T:build deploy
```

This will:
1. Build the JAR
2. Generate POM with metadata
3. Upload to Clojars

## Version Numbering

The version is automatically generated as `0.1.{git-commit-count}`.

For example:
- After 100 commits: `0.1.100`
- After 150 commits: `0.1.150`

To use a different versioning scheme, edit `build.clj`:

```clojure
;; Fixed version
(def version "1.0.0")

;; Or semantic versioning with git tags
(def version (or (System/getenv "RELEASE_VERSION") "0.1.0-SNAPSHOT"))
```

## Library Coordinates

After publishing, users can add the dependency:

```clojure
;; deps.edn
{:deps {io.github.esa/clj-ebpf {:mvn/version "0.1.100"}}}

;; Leiningen
[io.github.esa/clj-ebpf "0.1.100"]
```

## Troubleshooting

### Authentication Failed

- Verify CLOJARS_USERNAME and CLOJARS_PASSWORD are set
- Ensure you're using a deploy token, not your password
- Check the token has not expired
- Verify token has deploy permissions

### Version Already Exists

Clojars does not allow overwriting existing versions. You must:
1. Make a new commit to increment the version
2. Or manually change the version in `build.clj`

### Missing POM Data

If the POM is missing required fields:
1. Check `build.clj` for the `:pom-data` configuration
2. Ensure all required fields are present (groupId, artifactId, version)

## CI/CD Integration

### GitHub Actions

Create `.github/workflows/release.yml`:

```yaml
name: Release to Clojars

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history for git-count-revs

      - name: Setup Java
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '21'

      - name: Setup Clojure
        uses: DeLaGuardo/setup-clojure@12.5
        with:
          cli: latest

      - name: Deploy to Clojars
        env:
          CLOJARS_USERNAME: ${{ secrets.CLOJARS_USERNAME }}
          CLOJARS_PASSWORD: ${{ secrets.CLOJARS_PASSWORD }}
        run: clj -T:build deploy
```

Add `CLOJARS_USERNAME` and `CLOJARS_PASSWORD` as repository secrets.

### Creating a Release

```bash
# Tag the release
git tag v0.1.100
git push origin v0.1.100
```

The GitHub Action will automatically deploy to Clojars.

## Group ID

The library uses `io.github.esa` as the group ID. This follows Clojars' verified group policy:
- `io.github.{username}` for GitHub users
- `io.gitlab.{username}` for GitLab users
- Or verify a custom domain

To change the group ID, edit `build.clj`:

```clojure
(def lib 'com.example/clj-ebpf)
```

## See Also

- [Clojars Wiki](https://github.com/clojars/clojars-web/wiki)
- [tools.build Guide](https://clojure.org/guides/tools_build)
- [deps-deploy](https://github.com/slipset/deps-deploy)
