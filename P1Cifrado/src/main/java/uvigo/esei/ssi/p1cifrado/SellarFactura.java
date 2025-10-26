package uvigo.esei.ssi.p1cifrado;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Date;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class SellarFactura {
    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Uso: java SellarFactura <nombre paquete> <clave publica Empresa> <clave privada Autoridad>");
            System.exit(1);
        }

        Security.addProvider(new BouncyCastleProvider());
        String nombrePaquete = args[0];
        String clavePublicaEmpresa = args[1];
        String clavePrivadaAutoridad = args[2];

        try {
            PublicKey publicKeyEmpresa = cargarClavePublica(clavePublicaEmpresa);
            PrivateKey privateKeyAutoridad = cargarClavePrivada(clavePrivadaAutoridad);

            Paquete paquete = new Paquete(nombrePaquete);
            byte[] contenidoCifrado = paquete.getContenidoBloque("facturaCifrada");
            byte[] firmaEmpresa = paquete.getContenidoBloque("firmaEmpresa");

            if (contenidoCifrado == null || firmaEmpresa == null) {
                System.out.println("Error: Bloques necesarios no encontrados en el paquete");
                System.exit(1);
            }

            if (!verificarFirma(publicKeyEmpresa, contenidoCifrado, firmaEmpresa)) {
                System.out.println("Firma de la empresa no coincide. Fin del programa.");
                System.exit(1);
            }

            byte[] selloTiempo = new Date().toString().getBytes();
            byte[] firmaAutoridad = firmarDatos(privateKeyAutoridad, selloTiempo);

            paquete.anadirBloque("selloTiempo", selloTiempo);
            paquete.anadirBloque("firmaAutoridad", firmaAutoridad);
            paquete.escribirPaquete(nombrePaquete);

            System.out.println("Factura sellada exitosamente.");

        } catch (Exception e) {
           System.err.println("Error al sellar la factura");
           e.printStackTrace();
        }
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

    public static Boolean verificarFirma(PublicKey clave, byte[] contenido, byte[] firma) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA", "BC");
        sig.initVerify(clave);
        sig.update(contenido);
        return sig.verify(firma);
    }

    private static byte[] firmarDatos(PrivateKey key, byte[] data) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(key);
        signature.update(data);
        return signature.sign();
    }
}