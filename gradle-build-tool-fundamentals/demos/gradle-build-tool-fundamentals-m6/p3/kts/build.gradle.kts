plugins {
    java
}

subprojects {

  repositories {
    jcenter()
  }

   version = "0.1-SNAPSHOT"
}




project(":jCurlLib"){
    dependencies {
  }
}

project(":TerminalClient"){
  apply(plugin= "java")
  dependencies {
    implementation (project(":jCurlLib"))
  }
}
