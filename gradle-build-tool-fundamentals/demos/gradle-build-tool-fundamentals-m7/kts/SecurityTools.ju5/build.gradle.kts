import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent


val log4j_version: String by project
val jaxb_version: String by project
val junit_version: String by project

plugins {
  application
}

java {                                      
  sourceCompatibility = JavaVersion.VERSION_11
  targetCompatibility = JavaVersion.VERSION_11
}

repositories {
  jcenter()
}

dependencies {
  implementation("log4j:log4j:$log4j_version")
  implementation("javax.xml.bind:jaxb-api:$jaxb_version")
  testImplementation("org.junit.jupiter:junit-jupiter-api:$junit_version")
  testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:$junit_version")
}

tasks {
  test {
      useJUnitPlatform()
      testLogging.events = setOf(TestLogEvent.FAILED, TestLogEvent.PASSED, TestLogEvent.SKIPPED)      
  }
}

application {
  mainClassName = "com.pluralsight.security.Hash"
}

tasks.register<Test>("singleTest") {
  group = "Verification"
  description = "Runs a single test"
  dependsOn("testClasses")
  useJUnitPlatform()
  testLogging.events = setOf(TestLogEvent.FAILED, TestLogEvent.PASSED, TestLogEvent.SKIPPED)      
  filter {
    includeTestsMatching("com.pluralsight.security.TestCreateStreams.testWhenInputFileDoesExist")
  }
}

