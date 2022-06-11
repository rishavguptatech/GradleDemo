package com.pluralsight.security

import org.apache.log4j.Logger
import org.apache.log4j.PropertyConfigurator
import java.io.FileInputStream
import java.io.FileNotFoundException
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.xml.bind.DatatypeConverter

/**
 * @author kevinj
 */
class Sign : SecurityBase() {
    /**
     * @return Returns the bytesToHash.
     */
    /**
     * @param bytesToSign
     * The bytesToHash to set.
     */
    var bytesToSign = byteArrayOf()
    /**
     * @return Returns the verify.
     */
    /**
     * @param verify
     * The verify to set.
     */
    var isVerify = false
    /**
     * @return
     */
    /**
     * @param keystore
     * The keystore to set.
     */
    var keystore: KeyStore? = null
    /**
     * @return Returns the keyStorePass.
     */
    /**
     * @param keyStorePass
     * The keyStorePass to set.
     */
    var keyStorePass = charArrayOf()
    private var keyPassword = charArrayOf()
    /**
     * @return
     */
    /**
     * @param keystoreType
     * The keystoreType to set.
     */
    var keystoreType: String? = null

    /**
     * @return
     */
    var keyAlias: String? = null
    /**
     * @return Returns the keyStoreFilename.
     */
    /**
     * @param keyStoreFilename The keyStoreFilename to set.
     */
    var keyStoreFilename: String? = null
    /**
     * @return Returns the signatureFileName.
     */
    /**
     * @param signatureFileName The signatureFileName to set.
     */
    var signatureFileName: String? = null
    /**
     * @return Returns the decode.
     */
    /**
     * @param decode
     */
    var isDecode = false

    /**
     *
     */
    private fun checkArgs() {
        if (keyStoreFilename == null || getKeyPassword() == null || keyAlias == null) {
            usage()
            System.exit(-1)
        }
        if (isVerify && signatureFileName == null) {
            usage()
            System.exit(-1)
        }
    }

    @Throws(SignatureException::class, InvalidKeyException::class, NoSuchProviderException::class, UnrecoverableKeyException::class, KeyStoreException::class, NoSuchAlgorithmException::class, CertificateException::class, FileNotFoundException::class, IOException::class)
    fun run() {
        val signature = createSignatureInstance()
        val isDataToSignOrVerify = createInputStream(fileName)
        val os = createOutputStream(destFileName)
        val ks = loadKeyStore()
        keystore = ks
        if (isVerify) {
            val isSig = createInputStream(signatureFileName)
            if (verifyData(signature, readBytes(isDataToSignOrVerify), readBytes(isSig))) {
                println("Data verified")
            } else {
                println("Data not verified")
            }
        } else {
            val bytesToSign = readBytes(isDataToSignOrVerify)
            val signedBytes = signData(signature, bytesToSign)
            writeBytes(os, signedBytes)
            print("Data signed")
            if (destFileName != null) {
                println(" to file: $destFileName")
            } else println()
        }
        os.close()
    }

    /**
     * @return
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    @Throws(KeyStoreException::class, NoSuchAlgorithmException::class, UnrecoverableKeyException::class)
    protected fun loadPrivateKey(): PrivateKey {
        val alias = keyAlias
        val password = getKeyPassword()
        require(!(alias == null || password == null)) { "Either alias or password is null" }
        return keystore!!.getKey(alias, password) as PrivateKey
    }

    @Throws(KeyStoreException::class, NoSuchAlgorithmException::class, CertificateException::class, FileNotFoundException::class, IOException::class)
    protected fun loadKeyStore(): KeyStore {
        require(!(keystoreType == null
                || keyStoreFilename == null)) { "Either keystore type or keystore name is null" }
        val keystore = KeyStore.getInstance(keystoreType)
        keystore.load(FileInputStream(keyStoreFilename), keyStorePass)
        return keystore
    }

    /**
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    @Throws(NoSuchAlgorithmException::class, NoSuchProviderException::class)
    protected fun createSignatureInstance(): Signature {
        val sign: Signature
        sign = if (provider == null) Signature.getInstance(algorithm) else Signature.getInstance(algorithm, provider)
        return sign
    }

    /**
     * @param signature
     * @param bytesToSign
     * @throws IOException
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws UnrecoverableKeyException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    @Throws(IOException::class, SignatureException::class, InvalidKeyException::class, KeyStoreException::class, NoSuchAlgorithmException::class, UnrecoverableKeyException::class)
    fun signData(signature: Signature, bytesToSign: ByteArray?): ByteArray {
        val pk = loadPrivateKey()
        signature.initSign(pk)
        signature.update(bytesToSign)
        return signature.sign()
    }

    /**
     * @return
     * @throws KeyStoreException
     */
    @Throws(KeyStoreException::class)
    protected fun loadPublicKey(): PublicKey {
        val alias = keyAlias ?: throw IllegalArgumentException("Alias is null")
        return keystore!!.getCertificate(alias).publicKey
    }

    /**
     * @param signature
     * @param bytesToVerify
     * @param bytesSignature
     * @throws InvalidKeyException
     * @throws IOException
     * @throws SignatureException
     * @throws KeyStoreException
     */
    //  public boolean verifyData(Signature signature, InputStream isBytesToVerify, InputStream isSignature) throws InvalidKeyException, IOException, SignatureException, KeyStoreException
    @Throws(InvalidKeyException::class, IOException::class, SignatureException::class, KeyStoreException::class)
    fun verifyData(signature: Signature, bytesToVerify: ByteArray?, bytesSignature: ByteArray?): Boolean {
        var bytesSignature = bytesSignature
        val key = loadPublicKey()
        signature.initVerify(key)
        //        byte[] bytesToVerify = readBytes(isBytesToVerify);
//        byte[] bytesSignature = readBytes(isSignature);
        if (isDecode) bytesSignature = decodeData(bytesSignature)
        signature.update(bytesToVerify)
        return signature.verify(bytesSignature)
    }

    /**
     * @param bytesSignature
     * @return
     * @throws IOException
     */
    @Throws(IOException::class)
    private fun decodeData(bytesSignature: ByteArray?): ByteArray {
        return DatatypeConverter.parseBase64Binary(String(bytesSignature!!))
    }

    /**
     * @return
     */
    fun getKeyPassword(): CharArray? {
        return keyPassword
    }

    /**
     * @param keyPassword
     * The keyPass to set.
     */
    fun setKeyPassword(keyPassword: CharArray) {
        this.keyPassword = keyPassword
    }

    override fun parseArgs(args: Array<String>) {
        super.parseArgs(args)
        var i = 0
        while (i < args.size) {
            if (args[i] == "-s") isVerify = false else if (args[i] == "-v") isVerify = true else if (args[i] == "-keystore") setKeystoreFileName(args[++i]) else if (args[i] == "-keystoretype") keystoreType = args[++i] else if (args[i] == "-keypass") setKeyPassword(args[++i].toCharArray()) else if (args[i] == "-storepass") keyStorePass = args[++i].toCharArray() else if (args[i] == "-alias") keyAlias = args[++i] else if (args[i] == "-sigfilename") signatureFileName = args[++i] else if (args[i] == "-decode") isDecode = true
            i++
        }
    }

    /**
     * @param keyStoreFilename
     */
    fun setKeystoreFileName(keyStoreFilename: String?) {
        this.keyStoreFilename = keyStoreFilename
    }

    companion object {
        var logger = Logger.getLogger(Hash::class.java)

        @JvmStatic
        fun main(args: Array<String>) {
            val url = Hash::class.java.getResource("/log4j.properties")
            if (url != null) {
                PropertyConfigurator.configure(url)
            }
            if (args.size == 1 && args[0] == "--help" || args.size < 6) {
                usage()
                System.exit(-1)
            }
            val h = Sign()
            try {
                h.parseArgs(args)
                h.checkArgs()
                h.run()
            } catch (e: Exception) {
                logger.info(e, e)
            }
        }

        /**
         *
         */
        private fun usage() {
            System.err.println("signing: java Sign "
                    + "-s [-f filename] [-d signaturefile] [-p provider] [-a algorithm]")
            System.err.println("\t\t[-o] [-encode] [-keystoretype keystoretype] [-storepass storepassword]")
            System.err.println("\t\t-keystore storename -keypass keypassword -alias alias")
            System.err.println()
            System.err.println("verifying: java Sign "
                    + "-v [-f filename] [-p provider] [-a algorithm] [-decode]")
            System.err.println("\t\t[-keystoretype keystoretype] [-sigfilename signaturefilename]")
            System.err.println("\t\t[-storepass storepassword]")
            System.err.println()
            System.err.println("\t\t-keystore storename -keypass keypassword -alias alias")
            System.err.println("\tf filename\t: read input data from filename")
            System.err.println("\td signaturefile\t: write output signature to signaturefile")
            System.err.println("\tp provider\t: use specific provider")
            System.err.println("\ta algorithm\t: algorithm to use for digest")
            System.err.println("\to\t\t: overwrite destfilename file")
            System.err.println("\tencode\t\t: BASE64 encode output")
            System.err.println("\tdecode\t\t: BASE64 decode intput")
            System.err.println("\ts\t\t: sign data")
            System.err.println("\tv\t\t: verify signature")
            System.err.println("\tsigfilename\t: name of file containing signature (if verifying)")
            System.err.println("\tkeystoretype\t: type of keystore in use")
            System.err.println("\tstorepasst\t: password to keystore")
            System.err.println("\tkeystore\t\t: keystore")
            System.err.println("\tkeypass\t\t: password for key")
            System.err.println("\talias\t\t: alias for key")
        }
    }

    init {
        algorithm = "DSA"
        keystoreType = "JKS"
    }
}