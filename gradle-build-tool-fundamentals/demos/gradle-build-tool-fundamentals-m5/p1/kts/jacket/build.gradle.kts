val flyway_version: String by project
val junit_version: String by project
val h2_version: String by project
val hamcrest_version: String by project
val mockito_version: String by project
val commons_logging_version: String by project
val springBootVersion: String by project
val springDependencyVersion: String by project

buildscript {
    val h2_version: String by project
    repositories {
        jcenter()
    }
    dependencies {
        classpath("com.h2database:h2:$h2_version")
    }
}


plugins {
  id ("org.flywaydb.flyway") version "6.3.1"
  id("org.springframework.boot") version "2.2.5.RELEASE" apply false
  id("io.spring.dependency-management") version "1.0.9.RELEASE" apply false
  java
}

java {                                      
  sourceCompatibility = JavaVersion.VERSION_1_9  
  targetCompatibility = JavaVersion.VERSION_1_9
}


allprojects {

  apply(plugin = "java")

  version = "0.1-SNAPSHOT"
  
  repositories {
    jcenter()
  }

  dependencies {
    testImplementation("org.hamcrest:hamcrest-core:$hamcrest_version")
    testImplementation("junit:junit:$junit_version")
    testImplementation("org.hamcrest:hamcrest-library:$hamcrest_version")
    testImplementation("org.mockito:mockito-core:$mockito_version")

    implementation("commons-logging:commons-logging:$commons_logging_version")

  }
}

project(":Repository") {
    dependencies {
    }
}

project(":HibernateRepository") {
    dependencies {
      "implementation"(project(":Repository"))
    }
}

project(":JacketRepository") {
    dependencies {
      "implementation"(project(":HibernateRepository")) 
      "implementation"(project(":Repository"))
    }
}

project(":JacketService") {
    dependencies {
      "implementation"(project(":JacketRepository"))
      "implementation"(project(":Repository"))
    }
}

project(":JacketWeb") {

    apply(plugin = "org.springframework.boot")
    apply(plugin = "io.spring.dependency-management")
    apply(plugin = "war")
    
    dependencies {
      "implementation"(project(":JacketService"))
    }

}

listOf("JacketRepository", "JacketService", "JacketWeb").forEach { name ->
  project(":$name") { 

    apply(plugin="org.flywaydb.flyway")

    tasks.register("migrateTest") {	
       group = "test"
       description = "Run migration scripts for test"
       doFirst {
         flyway {
           url = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1;DATABASE_TO_UPPER=false"
           user = "sa"
           password = ""
           schemas = arrayOf("jacket")
           locations = arrayOf("filesystem:${rootProject.projectDir}/migrations/common", "filesystem:${rootProject.projectDir}/migrations/h2")
           sqlMigrationPrefix = ""
           baselineOnMigrate = true
           outOfOrder = true
         }
       }
    }
	
    tasks["migrateTest"].finalizedBy(tasks["flywayMigrate"])
 
   }
}

