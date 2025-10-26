package uvigo.esei.ssi.p1cifrado;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DesempaquetarFactura {

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("Uso: DesempaquetarFactura <nombre paquete> <fichero JSON factura> <clave privada Hacienda> <clave pública autoridad>");
            return;
        }

        Security.addProvider(new BouncyCastleProvider());
        
        String paquetePath = args[0];
        String facturaJsonPath = args[1];
        String clavePrivadaHaciendaPath = args[2];
        String clavePublicaAutoridadPath = args[3];

        // Leer el paquete
        Paquete paquete = new Paquete();
        paquete.leerPaquete(paquetePath);

        // Verificar que los bloques necesarios existen
        byte[] facturaCifrada = paquete.getContenidoBloque("facturaCifrada");
        byte[] firmaAutoridad = paquete.getContenidoBloque("firmaAutoridad");
        byte[] claveSimetricaCifrada = paquete.getContenidoBloque("claveSimetricaCifrada");
        byte[] selloTiempo = paquete.getContenidoBloque("selloTiempo");

        if (facturaCifrada == null || firmaAutoridad == null || claveSimetricaCifrada == null || selloTiempo == null) {
            System.out.println("Error: Faltan bloques necesarios en el paquete");
            return;
        }

        // Leer la clave privada de Hacienda
        PrivateKey clavePrivadaHacienda = leerClavePrivada(clavePrivadaHaciendaPath);

        // Leer la clave pública de la Autoridad de Sellado
        PublicKey clavePublicaAutoridad = leerClavePublica(clavePublicaAutoridadPath);

        // Verificar la firma de la Autoridad sobre el sello de tiempo
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initVerify(clavePublicaAutoridad);
        signature.update(selloTiempo);
        boolean firmaValida = signature.verify(firmaAutoridad);
        
        if (!firmaValida) {
            System.out.println("Firma de la Autoridad no válida.");
            return;
        }

        System.out.println("Sello de tiempo: " + new String(selloTiempo));

        // Desencriptar la clave simétrica con la clave privada de Hacienda (RSA)
        Cipher cipherRSA = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipherRSA.init(Cipher.DECRYPT_MODE, clavePrivadaHacienda);
        byte[] claveSimetricaDescifrada = cipherRSA.doFinal(claveSimetricaCifrada);

        // Desencriptar la factura con AES (clave simétrica)
        SecretKeySpec claveSimetrica = new SecretKeySpec(claveSimetricaDescifrada, "AES");
        Cipher cipherAES = Cipher.getInstance("AES", "BC");
        cipherAES.init(Cipher.DECRYPT_MODE, claveSimetrica);
        byte[] facturaDescifrada = cipherAES.doFinal(facturaCifrada);

        // Guardar la factura descifrada en un fichero JSON
        Files.write(Paths.get(facturaJsonPath), facturaDescifrada);

        System.out.println("Factura desempaquetada y verificada correctamente.");
    }

    private static PrivateKey leerClavePrivada(String clavePrivadaPath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(clavePrivadaPath));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return keyFactory.generatePrivate(spec);
    }

    private static PublicKey leerClavePublica(String clavePublicaPath) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(clavePublicaPath));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        return keyFactory.generatePublic(spec);
    }
}