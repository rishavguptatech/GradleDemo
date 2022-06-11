import com.adarshr.gradle.testlogger.theme.ThemeType

val log4j_version: String by project
val jaxb_version: String by project
val junit_version: String by project

plugins {
  application
  id ("com.adarshr.test-logger") version "2.0.0"
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
  testlogger {
      // can't use theme="some string" but can call the setTheme function
      setTheme("mocha")
//      theme=ThemeType.STANDARD
      showExceptions=true
      showStackTraces=true
      showFullStackTraces=false
      showCauses=true
      slowThreshold=2000
      showSummary=true
      showSimpleNames=false
      showPassed=true
      showSkipped=true
      showFailed=true
      showStandardStreams=false
      showPassedStandardStreams=true
      showSkippedStandardStreams=true
      showFailedStandardStreams=true
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

