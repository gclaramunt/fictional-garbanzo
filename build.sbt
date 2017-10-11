scalacOptions += "-Ypartial-unification"

libraryDependencies ++= Seq(
  "com.typesafe.akka"          %% "akka-actor"                  % "2.4.14",
  "org.typelevel"              %% "cats-core"                   % "1.0.0-MF",
  "com.typesafe.akka"          %% "akka-http-testkit"           % "10.0.1" % "test",
  "org.bouncycastle"           % "bcpg-jdk15on"                 % "1.56",
  "org.scalatest"              %% "scalatest"                   % "3.0.1" ,
  "org.scalacheck"             %% "scalacheck"                  % "1.13.5"
)
