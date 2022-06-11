package com.pluralsight.security

import org.apache.log4j.Logger
import org.apache.log4j.PropertyConfigurator
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.NoSuchProviderException

/**
 * @author kevinj
 */
class Hash : SecurityBase() {
    /**
     * @return Returns the bytesToHash.
     */
    /**
     * @param bytesToHash
     * The bytesToHash to set.
     */
    var bytesToHash: ByteArray

    @Throws(NoSuchProviderException::class, NoSuchProviderException::class, NoSuchAlgorithmException::class, IOException::class)
    fun run() {
        val md = createDigestInstance()
        val `is` = createInputStream(fileName)
        val os = createOutputStream(destFileName)
        val hashedBytes = digestData(md, `is`)
        writeBytes(os, hashedBytes)
    }

    /**
     * @param md
     * @param is
     * @param os
     * @throws IOException
     */
    @Throws(IOException::class)
    fun digestData(md: MessageDigest, `is`: InputStream?): ByteArray {
        bytesToHash = readBytes(`is`!!)
        md.update(bytesToHash)
        return md.digest()
    }

    /**
     * @return @throws
     * NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class)
    private fun createDigestInstance(): MessageDigest {
        val md: MessageDigest
        md = if (provider == null) MessageDigest.getInstance(algorithm) else MessageDigest.getInstance(algorithm, provider)
        return md
    }

    companion object {
        var logger = Logger.getLogger(Hash::class.java)
        const val ARRAY_INITIAL_SIZE = 100

        @JvmStatic
        fun main(args: Array<String>) {
            val url = Hash::class.java.getResource("/log4j.properties")
            if (url != null) {
                PropertyConfigurator.configure(url)
            }
            if (args.size == 0 || args.size == 1 && args[0] == "--help") {
                System.err.println("usage: java Hash [-f filename]  [-d destfilename] [-p provider] [-a algorithm] [-o] [-encode]")
                System.err.println("\tf filename\t: read input data from filename")
                System.err.println("\td destfilename\t: write output hash to destfilename")
                System.err.println("\tp provider\t: use specific provider")
                System.err.println("\ta algorithm\t: algorithm to use for digest")
                System.err.println("\to\t\t: overwrite destfilename file")
                System.err.println("\to\t\t: overwrite destfilename file")
                System.err.println("\tencode\t\t: BASE64 encode output")
                return
            }
            val h = Hash()
            try {
                h.parseArgs(args)
                h.run()
            } catch (e: NoSuchProviderException) {
                logger.info("Security Error", e)
            } catch (e: NoSuchAlgorithmException) {
                logger.info("Security Error", e)
            } catch (e: IOException) {
                logger.info("Security Error", e)
            }
        }
    }

    init {
        bytesToHash = ByteArray(ARRAY_INITIAL_SIZE)
        algorithm = "MD5"
    }
}