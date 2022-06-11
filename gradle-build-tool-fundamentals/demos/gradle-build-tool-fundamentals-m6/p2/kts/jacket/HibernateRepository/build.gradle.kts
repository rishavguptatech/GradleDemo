val javax_version: String by project
val hibernate_version: String by project

dependencies {
	
  implementation("org.hibernate:hibernate-core:$hibernate_version")
  implementation("org.hibernate:hibernate-entitymanager:$hibernate_version")
    
  implementation("javax.inject:javax.inject:$javax_version")
}
