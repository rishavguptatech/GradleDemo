plugins { 
  application
  kotlin("jvm") version "1.3.31"
}

kotlin {
    sourceSets["main"].apply {    
        kotlin.srcDir("src") 
    }

    sourceSets["test"].apply {    
        kotlin.srcDir("test/src") 
    }
}


application {
    mainClassName = "com.pluralsight.security.Hash"
}

repositories {
    mavenCentral()
}


dependencies {
  implementation(kotlin("stdlib-jdk8"))
  implementation(files ("lib/log4j-1.2.8.jar", "lib/junit-3.8.1.jar", "lib/jaxb-api-2.3.1.jar"))
}

tasks {
    compileKotlin {
        kotlinOptions.jvmTarget = "1.8"
    }
    compileTestKotlin {
        kotlinOptions.jvmTarget = "1.8"
    }
}
