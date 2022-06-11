package com.pluralsight.security

import java.security.Security

/**
 * @author kevinj
 *
 * Window - Preferences - Java - Code Style - Code Templates
 */
object Providers {
    @JvmStatic
    fun main(args: Array<String>) {
        val providers = Security.getProviders()
        for (i in providers.indices) {
            val provider = providers[i]
            println(provider.name + " " + provider.version)
            println("------------------------------------------------------------------------------------------")
            val it: Iterator<*> = provider.entries.iterator()
            while (it.hasNext()) {
                val e = it.next() as Map.Entry<*, *>
                println("\t" + e.key + ": " + e.value)
            }
            println("------------------------------------------------------------------------------------------")
        }
    }
}