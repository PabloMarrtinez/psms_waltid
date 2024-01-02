# key-formats-java

## Information

This is an implementation of various key formats used by DIDs and Verifiable Credentials.

## Maven

Build:

	mvn clean install

Dependency:

	<repositories>
		<repository>
			<id>danubetech-maven-public</id>
			<url>https://repo.danubetech.com/repository/maven-public/</url>
		</repository>
	</repositories>

	<dependency>
		<groupId>com.danubetech</groupId>
		<artifactId>key-formats-java</artifactId>
		<version>1.12.0</version>
	</dependency>

## Libsodium or Tink

By default, **key-formats-java** uses [libsodium](https://doc.libsodium.org/) for Ed25519 cryptographic operations.
In situations when this library is not available on a system (e.g. Android), [Tink](https://developers.google.com/tink) can be used instead.
For details on how to change the "provider" for the Ed25519 functions, see this issue: https://github.com/danubetech/key-formats-java/issues/11

## About

Danube Tech - https://danubetech.com/

<br clear="left" />

<img align="left" height="70" src="https://raw.githubusercontent.com/danubetech/key-formats-java/main/docs/logo-ngi-essiflab.png">

This software library is part of a project that has received funding from the European Union's Horizon 2020 research and innovation programme under grant agreement No 871932
