# Sonatype Central Portal Setup for Primust JVM Packages

Instructions for publishing `com.primust` artifacts to Maven Central via the
Sonatype Central Portal (used by `central-publishing-maven-plugin` v0.7.0).

## 1. Create a Sonatype Central Portal Account

1. Go to [central.sonatype.com](https://central.sonatype.com) and sign in (or
   create an account) using your GitHub identity.
2. Accept the publisher terms of service.

## 2. Claim the `com.primust` Namespace

The Central Portal verifies namespace ownership via GitHub.

1. Navigate to **Namespaces** in the portal dashboard.
2. Click **Add Namespace** and enter `com.primust`.
3. Select **GitHub repository verification** as the verification method.
4. The portal will ask you to create a temporary public repo (or add a
   verification key to an existing repo) under the `primust-dev` GitHub
   organization. Since the monorepo lives at `github.com/primust-dev/primust`,
   you can use that repo directly.
5. Follow the on-screen instructions (typically creating a file or repo with a
   specific verification code) and click **Verify**.
6. Once verified, the namespace is permanently claimed for your account.

## 3. Generate a Publishing Token

1. In the Central Portal, go to your account settings and generate a **User Token**.
2. This gives you a username/password pair (not your login credentials).
3. Keep these values safe -- you will need them for `settings.xml`.

## 4. Configure `~/.m2/settings.xml`

Create or update `~/.m2/settings.xml` with your Central Portal credentials.
The `<id>` must match the `<publishingServerId>` in each pom.xml (`central`).

```xml
<settings>
  <servers>
    <server>
      <id>central</id>
      <username>YOUR_TOKEN_USERNAME</username>
      <password>YOUR_TOKEN_PASSWORD</password>
    </server>
  </servers>
</settings>
```

## 5. GPG Key Generation and Distribution

Maven Central requires all artifacts to be signed with GPG.

### Generate a key

```bash
gpg --full-generate-key
# Select: RSA and RSA, 4096 bits, does not expire
# Name: Primust Engineering
# Email: engineering@primust.com
```

### List your key

```bash
gpg --list-keys --keyid-format SHORT
# Note the 8-character key ID (e.g., ABCD1234)
```

### Distribute the public key to a keyserver

```bash
gpg --keyserver keyserver.ubuntu.com --send-keys ABCD1234
gpg --keyserver keys.openpgp.org --send-keys ABCD1234
```

Maven Central validators check multiple keyservers. Distribute to at least
`keyserver.ubuntu.com` and `keys.openpgp.org`.

### Configure Maven to use the key

If you have multiple GPG keys, specify which one Maven should use in
`~/.m2/settings.xml`:

```xml
<settings>
  <profiles>
    <profile>
      <id>gpg</id>
      <properties>
        <gpg.keyname>ABCD1234</gpg.keyname>
      </properties>
    </profile>
  </profiles>
  <activeProfiles>
    <activeProfile>gpg</activeProfile>
  </activeProfiles>
</settings>
```

If the key has a passphrase and you are running non-interactively (e.g., CI),
set `GPG_PASSPHRASE` as an environment variable or use `gpg-agent`.

## 6. Publish

Run the publish script from the monorepo root:

```bash
./scripts/publish-jvm.sh
```

This builds and deploys all four packages in dependency order:

1. `primust-rules-core`
2. `primust-cedar`
3. `primust-drools`
4. `primust-odm`

The `central-publishing-maven-plugin` uploads each deployment bundle directly
to the Central Portal. With `<autoPublish>true</autoPublish>`, validated
artifacts are published automatically without manual portal intervention.

### Monitor deployment status

After the script completes, check the status at:
<https://central.sonatype.com/publishing/deployments>

Artifacts typically appear on Maven Central within 10-30 minutes after
validation passes.

## Notes

- The `central-publishing-maven-plugin` v0.7.0 with `<extensions>true</extensions>`
  handles the entire upload flow. No `<repository>` element is needed in
  `distributionManagement` -- only `<snapshotRepository>` is required (for
  snapshot builds).
- The `snapshotRepository` URL `https://central.sonatype.com/repository/maven-snapshots/`
  is the Central Portal's snapshot endpoint. Snapshot publishing requires a
  separate opt-in on the portal.
- Version numbers in pom.xml must NOT end in `-SNAPSHOT` for release builds.
