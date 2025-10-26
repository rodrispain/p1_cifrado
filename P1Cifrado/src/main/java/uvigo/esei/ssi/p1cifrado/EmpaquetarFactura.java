package uvigo.esei.ssi.p1cifrado;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class EmpaquetarFactura {

    public static void main(String[] args) {
        if (args.length != 4) {
            System.out.println("Uso: java EmpaquetarFactura <fichero JSON factura> <nombre paquete> <clave publica Hacienda> <clave privada Empresa>");
            System.exit(1);
        }

        Security.addProvider(new BouncyCastleProvider());
        String archivoFactura = args[0];
        String nombrePaquete = args[1];
        String clavePublicaHacienda = args[2];
        String clavePrivadaEmpresa = args[3];

        try {
            // Leer el contenido de la factura
            byte[] contenidoFactura = Files.readAllBytes(Paths.get(archivoFactura));

            // Generar clave AES para cifrar el contenido
            SecretKey claveAES = generarClaveAES();

            // Cifrar el contenido de la factura con AES
            byte[] contenidoCifradoAES = cifrarContenido(contenidoFactura, "AES", "BC", claveAES);

            // Cargar clave pública de Hacienda
            PublicKey publicKeyHacienda = cargarClavePublica(clavePublicaHacienda);

            // Cifrar la clave AES con RSA usando la clave pública de Hacienda
            byte[] claveAESCifrada = cifrarContenido(claveAES.getEncoded(),
                                      "RSA/ECB/PKCS1Padding", "BC", publicKeyHacienda);

            // Firmar el contenido cifrado AES con la clave privada de la empresa
            PrivateKey privateKeyEmpresa = cargarClavePrivada(clavePrivadaEmpresa);
            Signature firma = Signature.getInstance("SHA256withRSA", "BC");
            firma.initSign(privateKeyEmpresa);
            firma.update(contenidoCifradoAES);
            byte[] firmaEmpresa = firma.sign();

            // Crear y guardar el paquete
            Paquete paquete = new Paquete();
            paquete.anadirBloque("facturaCifrada", contenidoCifradoAES);
            paquete.anadirBloque("claveSimetricaCifrada", claveAESCifrada);
            paquete.anadirBloque("firmaEmpresa", firmaEmpresa);
            paquete.escribirPaquete(nombrePaquete);

            System.out.println("Factura empaquetada exitosamente en " + nombrePaquete);

        } catch (Exception e) {
            System.err.println("Error al empaquetar el paquete");
            e.printStackTrace();
        }
    }
    
    private static byte[] cifrarContenido(byte[] datos, String transformacion,
                            String provider, Key clave) throws Exception {
        Cipher cipher = Cipher.getInstance(transformacion, provider);
        cipher.init(Cipher.ENCRYPT_MODE, clave);
        return cipher.doFinal(datos);
    }

    private static SecretKey generarClaveAES() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "BC");
        kg.init(128);
        return kg.generateKey();
    }

    private static PublicKey cargarClavePublica(String path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(path));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return keyFactory.generatePublic(new X509EncodedKeySpec(keyBytes));
    }

    private static PrivateKey cargarClavePrivada(String path) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(path));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
    }
}