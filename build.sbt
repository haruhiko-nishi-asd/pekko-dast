ThisBuild / organization := "org.apache.pekko"

name := "pekko-dast"

scalaVersion := "3.3.4"
val pekkoVersion = "1.1.5"
val pekkoHttpVersion = "1.2.0"
val logbackVersion = "1.5.18"

scalacOptions :=
  Seq("-feature", "-unchecked", "-deprecation", "-encoding", "utf8")

run / fork := true
Compile / run / fork := true

// Several runnable mains (dast.scan.*); choose one with `runMain` (scripts/scan.sh
// drives them). `sbt stage` produces a runnable launcher under target/universal/stage.
enablePlugins(JavaAppPackaging)

libraryDependencies ++= Seq(
  "org.apache.pekko" %% "pekko-actor-typed" % pekkoVersion,
  "org.apache.pekko" %% "pekko-http" % pekkoHttpVersion,
  "org.apache.pekko" %% "pekko-stream-typed" % pekkoVersion,
  "ch.qos.logback" % "logback-classic" % logbackVersion,
  "com.lihaoyi" %% "ujson" % "4.1.0",
  "com.microsoft.playwright" % "playwright" % "1.60.0",
  "org.scalatest" %% "scalatest" % "3.2.19" % Test,
  "org.apache.pekko" %% "pekko-actor-testkit-typed" % pekkoVersion % Test,
  "org.apache.pekko" %% "pekko-testkit" % pekkoVersion % Test,
  "org.apache.pekko" %% "pekko-stream-testkit" % pekkoVersion % Test,
)
