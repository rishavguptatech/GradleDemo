val jstl_version: String by project
val cdi_version: String by project
val javax_version: String by project
val log4j_version: String by project
val c3p_version: String by project
val servlet_version: String by project
val spring_orm_version: String by project
val persistence_api_version: String by project

dependencies {

    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("jstl:jstl:$jstl_version")
    implementation("javax.inject:javax.inject:$javax_version")
    implementation("javax.enterprise:cdi-api:$jstl_version")
    implementation("c3p0:c3p0:$c3p_version")
    implementation("log4j:log4j:$log4j_version")
    
    providedCompile("javax.servlet:javax.servlet-api:$servlet_version")
    implementation("org.springframework:spring-orm:$spring_orm_version")
  	implementation("javax.persistence:persistence-api:$persistence_api_version")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}


// Because Spring
// https://stackoverflow.com/questions/54501697/gradle-war-plugin-how-to-change-name-of-an-archive
tasks.bootWar {
    archiveBaseName.set("JacketWeb")
    archiveVersion.set("0.0.2-SNAPSHOT")
}

