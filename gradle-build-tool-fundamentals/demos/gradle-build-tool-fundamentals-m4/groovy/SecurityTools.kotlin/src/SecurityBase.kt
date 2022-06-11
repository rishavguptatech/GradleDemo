package com.pluralsight.security

import java.io.*
import javax.xml.bind.DatatypeConverter

/**
 * @author kevinj
 *
 * Preferences - Java - Code Style - Code Templates
 */
open class SecurityBase {
    /**
     * @return Returns the fileName.
     */
    /**
     * @param fileName
     * The fileName to set.
     */
    var fileName: String? = null
    /**
     * @return Returns the destFileName.
     */
    /**
     * @param destFileName
     * The destFileName to set.
     */
    var destFileName: String? = null
    /**
     * @return Returns the algorithm.
     */
    /**
     * @param algorithm
     * The algorithm to set.
     */
    var algorithm = "MD5"
    /**
     * @return Returns the provider.
     */
    /**
     * @param provider
     * The provider to set.
     */
    var provider: String? = null
    /**
     * @return Returns the overwrite.
     */
    /**
     * @param overwrite
     * The overwrite to set.
     */
    var isOverwrite = false
    /**
     * @return Returns the encode.
     */
    /**
     * @param encode
     * The encode to set.
     */
    var isEncode = false

    protected open fun parseArgs(args: Array<String>) {
        var i = 0
        while (i < args.size) {
            if (args[i] == "-f") fileName = args[++i] else if (args[i] == "-d") destFileName = args[++i] else if (args[i] == "-p") provider = args[++i] else if (args[i] == "-a") algorithm = args[++i] else if (args[i] == "-o") isOverwrite = true else if (args[i] == "-encode") isEncode = true
            i++
        }
    }

    @Throws(FileNotFoundException::class)
    protected fun createInputStream(fileName: String?): InputStream {
        return if (fileName == null) System.`in` else {
            val f = File(fileName)
            if (f.exists()) {
                FileInputStream(f)
            } else {
                throw FileNotFoundException()
            }
        }
    }

    @Throws(IOException::class)
    protected fun createOutputStream(fileName: String?): OutputStream {
        return if (fileName == null) System.out else {
            val f = File(fileName)
            if (f.exists()) {
                if (isOverwrite) FileOutputStream(f) else throw IOException("Destination file already exists")
            } else {
                FileOutputStream(f)
            }
        }
    }

    protected fun resizeArray(`in`: ByteArray): ByteArray {
        val size = `in`.size
        val tmp = ByteArray(`in`.size * 2)
        System.arraycopy(`in`, 0, tmp, 0, `in`.size)
        return tmp
    }

    /**
     * @param os
     * @throws IOException
     */
    @Throws(IOException::class)
    protected fun writeBytes(os: OutputStream, bytes: ByteArray?) {
        if (isEncode) {
            val temp: String
            temp = DatatypeConverter.printBase64Binary(bytes)
            os.write(temp.toByteArray())
        } else {
            os.write(bytes)
        }
        os.flush()
        os.close()
    }

    /**
     * @throws IOException
     */
    @Throws(IOException::class)
    protected fun readBytes(`is`: InputStream): ByteArray {
        var offset = 0
        var bytesRead = 0
        var size = 0
        var temp = ByteArray(ARRAY_INITIAL_SIZE)
        while (`is`.read(temp, offset, ARRAY_INITIAL_SIZE).also { bytesRead = it } != -1) {
            offset += ARRAY_INITIAL_SIZE
            while (offset >= temp.size) temp = resizeArray(temp)
            size += bytesRead
        }
        val bytes = ByteArray(size)
        for (i in 0 until size) {
            bytes[i] = temp[i]
        }
        `is`.close()
        return bytes
    }

    companion object {
        const val ARRAY_INITIAL_SIZE = 100
    }
}