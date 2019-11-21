package com.company;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Scanner;

import static com.sun.org.apache.xml.internal.security.keys.keyresolver.KeyResolver.getPublicKey;

public class Main {

    public static void main(String[] args) throws Exception {

        // Ejercicio 1.1
        System.out.println("\nEjercicio 1.1\n**********************\n");

        KeyPair parellClaus = Claves.randomGenerate(1024);

        String data = new Scanner(System.in).nextLine();

        byte[] dataBytes = data.getBytes();

        byte[] dataEnc = Claves.encryptData(dataBytes,parellClaus.getPublic());

        System.out.println(new String(dataEnc));

        byte[] dataDec = Claves.decryptData(dataEnc,parellClaus.getPrivate());

        System.out.println(new String(dataDec));

        // Ejercicio 1.2.1

        System.out.println("\nEjercicio 1.2.1\n**********************\n");

        KeyStore keyStore = Claves.loadKeyStore("/home/dam2a/keystore_jona2.jks", "password");

        System.out.println("Tipo del keystore: " + keyStore.getType());
        System.out.println("Tamaño del keystore: " + keyStore.size());

        Enumeration<String> enumeration = keyStore.aliases();
        while (enumeration.hasMoreElements()){
            System.out.println("Alias del keystore: " + enumeration.nextElement());
        }
        System.out.println("Certificado de una clave del keystore: " + keyStore.getCertificate("lamevaclaum9"));
        System.out.println("Algoritmo de una clave del keystore: " + keyStore.getKey("lamevaclaum9", "password".toCharArray()).getAlgorithm());


        // 1.2.2
        System.out.println("\nEjercicio 1.2.2\n**********************\n");

        String psw = "password";

        SecretKey secretKey = Claves.keygenKeyGeneration(256);

        KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);

        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(psw.toCharArray());

        keyStore.setEntry("secretKeyAlias", skEntry, protParam);

        try (FileOutputStream fos = new FileOutputStream("/home/dam2a/keystore_jona2.jks")) {
            keyStore.store(fos, "password".toCharArray());
        }

        System.out.println(keyStore.getEntry("secretKeyAlias", protParam));


        // 1.2.3
        System.out.println("\nEjercicio 1.2.3\n**********************\n");

        FileInputStream fis = new FileInputStream("/home/dam2a/jordi.cer");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        Collection c = cf.generateCertificates(fis);
        Iterator i = c.iterator();
        while (i.hasNext()) {
            Certificate cert = (Certificate)i.next();
            System.out.println(cert);
        }

        // 1.2.4
        System.out.println("\nEjercicio 1.2.4\n**********************\n");


        FileInputStream is = new FileInputStream("/home/dam2a/keystore_jona2.jks");
        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, "password".toCharArray());

        String alias = "mykey";

        Key key = keystore.getKey(alias, "password".toCharArray());
        if (key instanceof PrivateKey) {
            // Get certificate of public key
            Certificate cert = keystore.getCertificate(alias);

            // Get public key
            PublicKey publicKey = cert.getPublicKey();
            System.out.println(publicKey.toString());
        }



        // 1.2.5

        System.out.println("\nEjercicio 1.2.5\n**********************\n");

        byte[] dataBy = "data".getBytes();

        PrivateKey privKey = parellClaus.getPrivate();

        byte[] firma = Claves.signData(dataBy,privKey);

        System.out.println(new String(firma));


        // 1.2.6

        System.out.println("\nEjercicio 1.2.6\n**********************\n");

        PublicKey publicKey = parellClaus.getPublic();

        boolean verificado = Claves.validateSignature(dataBy,firma,publicKey);

        System.out.println(verificado);


        // Ejercicio 2.2

        System.out.println("\nEjercicio 2.2\n**********************\n");

        KeyPair claves = Claves.randomGenerate(1024);

        PublicKey pubKey = claves.getPublic();
        PrivateKey privateKey = claves.getPrivate();

        byte[][] clauEmbEnc = Claves.encryptWrappedData(dataBy,pubKey);


        byte[]  clauEmbDec = Claves.decryptWrappedData(clauEmbEnc,privateKey);

        System.out.println(new String(clauEmbDec));

    }
}
