plugins { 
  application
}

java {
  sourceCompatibility = JavaVersion.VERSION_1_8
  targetCompatibility = JavaVersion.VERSION_1_8
  withJavadocJar()
  withSourcesJar()
}

sourceSets {
  main {
    java {
      setSrcDirs(listOf("src"))
    }
  }
  test {
    java {
      setSrcDirs(listOf("test/src")) 
    }
  }
}

application {
    mainClassName = "com.pluralsight.security.Hash"
}

dependencies {
  implementation(files ("lib/log4j-1.2.8.jar", "lib/junit-3.8.1.jar", "lib/jaxb-api-2.3.1.jar"))
}

