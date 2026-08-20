# gcid

Idiomatic Java implementation of the GCIDv2 wire format.

This package is dependency-free at runtime. It uses the JDK AES primitive and
implements the RFC 8452 AES-256-GCM-SIV construction needed by GCIDv2.

Failures are reported as `GcidException` with a stable `GcidException.Code`, so
callers can branch on error class without parsing message text.

```java
import com.github.jrepp.gcid.GcidCodec;

final class Example {
    public static void main(String[] args) throws Exception {
        var codec = GcidCodec.create("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX".getBytes());
        var id = codec.encode("prf", 123);
        var decoded = codec.decode("prf", id);

        System.out.println(id);
        System.out.println(Long.toUnsignedString(decoded.sequence()));
    }
}
```

Run a complete command-line example from this directory:

```sh
JAVA_HOME=/Users/jrepp/.sdkman/candidates/java/current \
  /Users/jrepp/.sdkman/candidates/maven/current/bin/mvn \
  -q \
  -Dexec.classpathScope=test \
  -Dexec.mainClass=com.github.jrepp.gcid.GcidCommandLineExample \
  -Dexec.args="asset 456 42" \
  test-compile exec:java
```

Expected output:

```text
id=asset_CbdrzdRr8YDyt2EjYC9AexJ4QVhfCHrbt95DGXpUjzb6TGw
prefix=asset
sequence=456
location=42
keyId=0
```

Run tests and benchmarks from this directory with SDKMAN Java and Maven:

```sh
JAVA_HOME=/Users/jrepp/.sdkman/candidates/java/current \
  /Users/jrepp/.sdkman/candidates/maven/current/bin/mvn test

JAVA_HOME=/Users/jrepp/.sdkman/candidates/java/current \
  /Users/jrepp/.sdkman/candidates/maven/current/bin/mvn -Pbench verify
```

Build Maven distribution artifacts:

```sh
JAVA_HOME=/Users/jrepp/.sdkman/candidates/java/current \
  /Users/jrepp/.sdkman/candidates/maven/current/bin/mvn clean verify
```

This produces the runtime jar, sources jar, and javadoc jar under `target/`.
The runtime jar also embeds the Maven POM metadata under `META-INF/maven`.

```text
target/gcid-0.2.0-SNAPSHOT.jar
target/gcid-0.2.0-SNAPSHOT-sources.jar
target/gcid-0.2.0-SNAPSHOT-javadoc.jar
```

Install the package into the local Maven repository for another project to use:

```sh
JAVA_HOME=/Users/jrepp/.sdkman/candidates/java/current \
  /Users/jrepp/.sdkman/candidates/maven/current/bin/mvn install
```

Then depend on it with:

```xml
<dependency>
  <groupId>com.github.jrepp</groupId>
  <artifactId>gcid</artifactId>
  <version>0.2.0-SNAPSHOT</version>
</dependency>
```

For repository distribution, run the `release` profile in an environment with
GPG configured:

```sh
JAVA_HOME=/Users/jrepp/.sdkman/candidates/java/current \
  /Users/jrepp/.sdkman/candidates/maven/current/bin/mvn -Prelease verify
```

The Maven benchmark profile is a smoke benchmark that runs inside the Maven
process. For cleaner local numbers, run `GcidBenchmark` directly after a Maven
test build.

Recent local result on Apple Silicon with OpenJDK 25.0.3:

```text
Java GCIDv2 benchmark (100000 operations)
----------------------------------------------------------------
java encode           10672 ns/op        93701 ops/s
java decode           10497 ns/op        95263 ops/s
```
