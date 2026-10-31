// Canton release the driver API is compiled against. Match the fleet's participant
// (Splice 0.9.x ships Canton 3.6). The v1 driver API is stable within a minor line.
val cantonVersion = "3.6.4"

name := "openbao-kms-driver"
organization := "com.saxonxyz"
version := "0.1.0-SNAPSHOT"
scalaVersion := "2.13.18" // Canton 3.6.4's

// Everything Canton already ships is Provided, so the driver JAR carries only our own
// classes. A second copy of logback/pureconfig/circe/scala-library on Canton's flat
// classpath breaks Canton's logging and config reader (found the hard way in the Scaleway
// driver). Versions are PINNED to what Canton 3.6.4 ships. Re-pin on every Canton minor bump.
libraryDependencies ++= Seq(
  "com.softwaremill.sttp.client3" %% "core" % "3.11.0" % Provided,
  "io.circe" %% "circe-core" % "0.14.2" % Provided,
  "io.circe" %% "circe-parser" % "0.14.2" % Provided,
  "com.github.pureconfig" %% "pureconfig" % "0.14.0" % Provided,
  "ch.qos.logback" % "logback-classic" % "1.6.3" % Provided,
  "com.typesafe.scala-logging" %% "scala-logging" % "3.9.5" % Provided,

  // Testing
  "org.scalatest" %% "scalatest" % "3.2.17" % Test
)

// Canton provides the Scala library too.
assembly / assemblyOption ~= (_.withIncludeScala(false))

// Official Canton KMS Driver API, published on Maven Central. Provided: the Canton runtime
// supplies it, along with opentelemetry-api, at load time.
libraryDependencies += "com.daml" %% "kms-driver-api" % cantonVersion % Provided

// DA's reusable driver test suite (KmsDriverTest / KmsDriverFactoryTest).
libraryDependencies += "com.daml" %% "kms-driver-testing" % cantonVersion % Test

// Don't run the test suites as part of `assembly`; the OpenBao-backed ones need a server.
assembly / test := {}

assembly / assemblyMergeStrategy := {
  case PathList("META-INF", "MANIFEST.MF") => MergeStrategy.discard
  case PathList("META-INF", "services", xs @ _*) => MergeStrategy.concat
  case PathList("META-INF", xs @ _*) if xs.lastOption.exists(_.endsWith(".SF")) => MergeStrategy.discard
  case PathList("META-INF", xs @ _*) if xs.lastOption.exists(_.endsWith(".DSA")) => MergeStrategy.discard
  case PathList("META-INF", xs @ _*) if xs.lastOption.exists(_.endsWith(".RSA")) => MergeStrategy.discard
  case PathList("reference.conf") => MergeStrategy.concat
  case _ => MergeStrategy.first
}

assembly / assemblyJarName := s"${name.value}-${version.value}.jar"

scalacOptions ++= Seq(
  "-encoding", "UTF-8",
  "-deprecation",
  "-feature",
  "-unchecked"
)
