val mockito_version: String by project
val mysql_version: String by project
val javax_version: String by project
val persistence_api_version: String by project

dependencies {

    implementation("mysql:mysql-connector-java:$mysql_version")
    implementation("javax.inject:javax.inject:$javax_version")
	implementation("javax.persistence:persistence-api:$persistence_api_version")

    testImplementation("org.mockito:mockito-all:$mockito_version")

}


tasks.register("migrateProduction") {
	group = "deploy"
	description = "Run migration scripts for production"
	doFirst {
		 flyway {
		    url = "jdbc:mysql://localhost:3306"
		    user = "root'"
		    password = "password"
		    schemas = arrayOf("jacket")
		    locations = arrayOf("filesystem:${projectDir}/migrations/common", "filesystem:${projectDir}/migrations/mysql")
		    sqlMigrationPrefix = ""
		    baselineOnMigrate = true
		    outOfOrder = true
		}
	}
}

tasks["migrateProduction"].finalizedBy(tasks["flywayMigrate"])

