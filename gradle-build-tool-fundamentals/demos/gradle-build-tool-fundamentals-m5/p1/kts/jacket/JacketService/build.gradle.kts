val commons_logging_version: String by project
val javax_version: String by project
val mockito_version: String by project
val junit_version: String by project
val hamcrest_version: String by project

dependencies {
    testImplementation("org.hamcrest:hamcrest-core:$hamcrest_version")
    testImplementation("junit:junit:$junit_version")
    testImplementation("org.hamcrest:hamcrest-library:$hamcrest_version")
    testImplementation("org.mockito:mockito-core:$mockito_version")

    implementation("javax.inject:javax.inject:$javax_version")
    implementation("commons-logging:commons-logging:$commons_logging_version")
}



