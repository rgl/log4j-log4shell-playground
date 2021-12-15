# About

A playground for poking at the [critical log4j (aka Log4Shell) (CVE-2021-44228) vulnerability](https://en.wikipedia.org/wiki/Log4Shell) mitigations.

This particular problem lies within the [JndiLookup feature](https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup) and the log4j ability to interpret **ALL** the arguments of a logging call.

I would expect it to only interpret the format message (the first argument of a logging call), e.g., the `Hello {}` in `log.info("Hello {}", "${jndi:ldap://127.0.0.1:8081}")`, but it interprests all of them.

The mitigations will prevent log4j from triggering the `jndi` lookups, but they still allow other lookups like `${java:version}`.

**NB: Since log4j [2.16.0](https://logging.apache.org/log4j/2.x/changes-report.html#a2.16.0) ([LOG4J2-3211](https://issues.apache.org/jira/browse/LOG4J2-3211); [diff](https://github.com/apache/logging-log4j2/compare/rel/2.15.0...rel/2.16.0)) the format message is no longer interpreted.**

This vulnerability can be triggered remotely when the target application logs any user supplied data, for example, from these common HTTP headers:

* `Accept`
* `Cookie`
* `Location`
* `Origin`
* `Referer`
* `User-Agent`
* `X-Api-Version`
* `X-Forwarded-For`
* `X-Forwarded-Host`
* `X-Requested-With`

# Play (Ubuntu 20.04)

Build:

```bash
sudo apt-get install -y openjdk-11-jdk-headless
wget https://archive.apache.org/dist/logging/log4j/2.10.0/apache-log4j-2.10.0-bin.tar.gz
wget https://archive.apache.org/dist/logging/log4j/2.16.0/apache-log4j-2.16.0-bin.tar.gz
tar xf apache-log4j-2.10.0-bin.tar.gz
tar xf apache-log4j-2.16.0-bin.tar.gz
javac -Werror -cp apache-log4j-2.10.0-bin/log4j-api-2.10.0.jar Server.java
```

Try a vulnerable log4j version:

```bash
java \
    -cp apache-log4j-2.10.0-bin/log4j-api-2.10.0.jar:apache-log4j-2.10.0-bin/log4j-core-2.10.0.jar:. \
    Server
curl -H 'X-Api-Version:${jndi:ldap://127.0.0.1:8081}' http://localhost:8080
curl -H 'X-Api-Version:${java:version}' http://localhost:8080
```

Try removing the `JndiLookup` class from the classpath mitigation:

```bash
cp apache-log4j-2.10.0-bin/log4j-core-2.10.0.jar log4j-core-2.10.0-without-jndi-lookup.jar
zip -q -d log4j-core-2.10.0-without-jndi-lookup.jar org/apache/logging/log4j/core/lookup/JndiLookup.class
java \
    -cp apache-log4j-2.10.0-bin/log4j-api-2.10.0.jar:log4j-core-2.10.0-without-jndi-lookup.jar:. \
    Server
curl -H 'X-Api-Version:${jndi:ldap://127.0.0.1:8081}' http://localhost:8080
curl -H 'X-Api-Version:${java:version}' http://localhost:8080
```

Try the environment variable mitigation:

**NB** Since 2021-12-15 (circa log4j 2.16.0 / CVE-2021-45046 release date) this is no longer recommended.

```bash
LOG4J_FORMAT_MSG_NO_LOOKUPS=true \
    java \
    -cp apache-log4j-2.10.0-bin/log4j-api-2.10.0.jar:apache-log4j-2.10.0-bin/log4j-core-2.10.0.jar:. \
    Server
curl -H 'X-Api-Version:${jndi:ldap://127.0.0.1:8081}' http://localhost:8080
curl -H 'X-Api-Version:${java:version}' http://localhost:8080
```

Try a non-vulnerable log4j version:

```bash
java \
    -cp apache-log4j-2.16.0-bin/log4j-api-2.16.0.jar:apache-log4j-2.16.0-bin/log4j-core-2.16.0.jar:. \
    Server
curl -H 'X-Api-Version:${jndi:ldap://127.0.0.1:8081}' http://localhost:8080
curl -H 'X-Api-Version:${java:version}' http://localhost:8080
```

Try [grype](https://github.com/anchore/grype) to see whether it detects the vulnerability:

```bash
wget https://github.com/anchore/grype/releases/download/v0.27.2/grype_0.27.2_linux_amd64.tar.gz
tar xf grype_0.27.2_linux_amd64.tar.gz grype
./grype dir:.
```

Try [trivy](https://github.com/aquasecurity/trivy) to see whether it detects the vulnerability:

```bash
wget https://github.com/aquasecurity/trivy/releases/download/v0.21.2/trivy_0.21.2_Linux-64bit.tar.gz
tar xf trivy_0.21.2_Linux-64bit.tar.gz trivy
./trivy fs --security-checks vuln .
```

# References

* https://www.lunasec.io/docs/blog/log4j-zero-day-mitigation-guide/
* https://blog.cloudflare.com/inside-the-log4j2-vulnerability-cve-2021-44228/
* https://logging.apache.org/log4j/2.x/security.html
* https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup
