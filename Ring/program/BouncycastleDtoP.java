import java.io.*;
import java.security.cert.*;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class BouncycastleDtoP {

    public static void main(String[] args) {

        if (args.length != 2) {
            System.err.println("Usage: java DtoP <input_folder> <output_folder>");
            System.exit(1);
        }

        String inputFolder = args[0];
        String outputFolder = args[1];

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            File[] files = new File(inputFolder).listFiles();
            if (files == null) {
                System.err.println("Error:Input folder is empty or does not exist.");
                System.exit(1);
            }

            new File(outputFolder).mkdirs();

            for (File inputFile : files) {
                if (inputFile.isFile() && inputFile.getName().endsWith(".der")) {
                    String inputPath = inputFile.getAbsolutePath();
                    String outputPath = outputFolder + File.separator + inputFile.getName().replace(".der", ".pem");

                    try (InputStream inputStream = new FileInputStream(inputPath);
                         OutputStream outputStream = new FileOutputStream(outputPath);
                         JcaPEMWriter pemWriter = new JcaPEMWriter(new OutputStreamWriter(outputStream))) {

                        Certificate cert = cf.generateCertificate(inputStream);
                        pemWriter.writeObject(cert);

                        System.out.println(inputFile.getName() + " Converted");

                    } catch (Exception e) {
                        System.err.println("Error: processing file: " + inputFile.getName());
                        e.printStackTrace();
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

