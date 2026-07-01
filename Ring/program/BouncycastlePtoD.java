import java.io.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class BouncycastlePtoD {

    public static void main(String[] args) {

        if (args.length != 2) {
            System.err.println("Usage: java PtoD <input_folder> <output_folder>");
            System.exit(1);
        }
        String inputFolder = args[0];
        String outputFolder = args[1];

        try {
            File[] files = new File(inputFolder).listFiles();

            if (files == null) {
                System.err.println("Error: Input folder is empty or does not exist.");
                System.exit(1);
            }

            new File(outputFolder).mkdirs();

            for (File inputFile : files) {

                if (inputFile.isFile() && inputFile.getName().endsWith(".pem")) {

                    String inputPath = inputFile.getAbsolutePath();
                    String outputPath = outputFolder + File.separator + inputFile.getName().replace(".pem", ".der");

                    try (InputStream inputStream = new FileInputStream(inputPath);
                         OutputStream outputStream = new FileOutputStream(outputPath)) {
                         
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");

                        X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);

                        outputStream.write(cert.getEncoded());
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

