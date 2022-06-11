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
  //  implementation files ('lib/log4j-1.2.8.jar', 'lib/junit-3.8.1.jar')
  implementation("log4j:log4j:$log4j_version")
  implementation("javax.xml.bind:jaxb-api:$jaxb_version")
  testImplementation("junit:junit:$junit_version")
}

application {
  mainClassName = "com.pluralsight.security.Hash"
}



