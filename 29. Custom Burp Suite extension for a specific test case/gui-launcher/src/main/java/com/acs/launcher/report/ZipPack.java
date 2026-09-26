package com.acs.launcher.report;

import com.acs.burptester.core.Hashes;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public final class ZipPack {

    private ZipPack() {
    }

    public record Entry(String name, byte[] data) {
    }

    public static byte[] archive(Entry entry0, Entry... more) throws IOException {
        return archive(java.util.stream.Stream.concat(java.util.stream.Stream.of(entry0),
                java.util.stream.Stream.of(more)).toList());
    }

    public static byte[] archive(List<Entry> entries) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bos)) {
            for (Entry entry : entries) {
                zip.putNextEntry(new ZipEntry(entry.name()));
                zip.write(entry.data());
                zip.closeEntry();
            }
            StringBuilder manifest = new StringBuilder();
            for (Entry entry : entries) {
                manifest.append(Hashes.sha256(entry.data())).append("  ").append(entry.name()).append('\n');
            }
            zip.putNextEntry(new ZipEntry("SHA256SUMS.txt"));
            zip.write(manifest.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
            zip.closeEntry();
        }
        return bos.toByteArray();
    }
}