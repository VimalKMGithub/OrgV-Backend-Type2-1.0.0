package org.v.auth.service.utils;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class QrUtility {
    private static final int DEFAULT_SIZE = 300;
    private static final String DEFAULT_IMAGE_FORMAT = "PNG";
    private static final QRCodeWriter QR_CODE_WRITER = new QRCodeWriter();

    public static byte[] encodeStringInQr(String content) throws IOException, WriterException {
        return encodeStringInQr(content, DEFAULT_SIZE, DEFAULT_IMAGE_FORMAT);
    }

    public static byte[] encodeStringInQr(String content,
                                          int size,
                                          String format) throws WriterException, IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(
                QR_CODE_WRITER.encode(content, BarcodeFormat.QR_CODE, size, size),
                format,
                outputStream
        );
        return outputStream.toByteArray();
    }
}
