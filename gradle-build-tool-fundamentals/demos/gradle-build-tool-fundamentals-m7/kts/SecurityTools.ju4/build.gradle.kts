import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent


val log4j_version: String by project
val jaxb_version: String by project
val junit_version: String by project

plugins {
  application
}

java {                                      
    sourceCompatibility = JavaVersion.VERSION_1_9
    targetCompatibility = JavaVersion.VERSION_1_9
}

repositories {
  jcenter()
}

dependencies {
  implementation("log4j:log4j:$log4j_version")
  implementation("javax.xml.bind:jaxb-api:$jaxb_version")
  testImplementation("junit:junit:$junit_version")
}

tasks {
  test {
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
  filter {
    includeTestsMatching("com.pluralsight.security.TestCreateStreams.testWhenInputFileDoesExist")
  }
}

