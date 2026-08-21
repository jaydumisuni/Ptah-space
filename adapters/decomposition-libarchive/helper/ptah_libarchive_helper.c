#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef PTAH_LIBARCHIVE_SOURCE_SHA
#define PTAH_LIBARCHIVE_SOURCE_SHA "unknown"
#endif

static int write_all(const void *buffer, size_t length) {
    return fwrite(buffer, 1, length, stdout) == length ? 0 : -1;
}
static int write_u8(uint8_t value) { return write_all(&value, sizeof(value)); }
static int write_u32(uint32_t value) {
    uint8_t bytes[4] = {(uint8_t)value, (uint8_t)(value >> 8), (uint8_t)(value >> 16), (uint8_t)(value >> 24)};
    return write_all(bytes, sizeof(bytes));
}
static int write_u64(uint64_t value) {
    uint8_t bytes[8];
    for (unsigned i = 0; i < 8; ++i) bytes[i] = (uint8_t)(value >> (8U * i));
    return write_all(bytes, sizeof(bytes));
}
static int write_text(const char *text, uint32_t max_len) {
    size_t length = text == NULL ? 0 : strlen(text);
    if (length > max_len) length = max_len;
    if (write_u32((uint32_t)length) != 0) return -1;
    return length == 0 ? 0 : write_all(text, length);
}
static int configure_reader(struct archive *a) {
    int rc = ARCHIVE_OK;
    rc = archive_read_support_filter_none(a); if (rc != ARCHIVE_OK) return rc;
    rc = archive_read_support_filter_gzip(a); if (rc != ARCHIVE_OK) return rc;
    rc = archive_read_support_filter_bzip2(a); if (rc != ARCHIVE_OK) return rc;
    rc = archive_read_support_filter_xz(a); if (rc != ARCHIVE_OK) return rc;
    rc = archive_read_support_filter_lz4(a); if (rc != ARCHIVE_OK) return rc;
    rc = archive_read_support_filter_zstd(a); if (rc != ARCHIVE_OK) return rc;
    return archive_read_support_format_all(a);
}
static int emit_terminal(uint8_t terminal, struct archive *a, const char *diagnostic) {
    const char *format = a == NULL ? NULL : archive_format_name(a);
    if (write_u8(2) != 0 || write_u8(terminal) != 0 || write_text(format, 256) != 0 || write_text(diagnostic, 512) != 0) return -1;
    return fflush(stdout) == 0 ? 0 : -1;
}
static uint8_t entry_kind(struct archive_entry *entry) {
    if (archive_entry_symlink(entry) != NULL) return 3;
    if (archive_entry_hardlink(entry) != NULL) return 4;
    mode_t type = archive_entry_filetype(entry);
    if (type == AE_IFREG) return 1;
    if (type == AE_IFDIR) return 2;
    return 5;
}
static int emit_entry(struct archive *a, struct archive_entry *entry) {
    const char *path = archive_entry_pathname_utf8(entry);
    if (path == NULL) path = archive_entry_pathname(entry);
    if (path == NULL) return -1;
    size_t path_len = strlen(path);
    if (path_len > UINT32_MAX) return -1;
    uint8_t kind = entry_kind(entry);
    if (kind != 1) {
        if (write_u8(1) != 0 || write_u8(kind) != 0 || write_u32((uint32_t)path_len) != 0 || write_u64(0) != 0 || write_all(path, path_len) != 0) return -1;
        return 0;
    }
    FILE *member = tmpfile();
    if (member == NULL) return -1;
    uint64_t total = 0;
    char buffer[16384];
    for (;;) {
        la_ssize_t count = archive_read_data(a, buffer, sizeof(buffer));
        if (count == 0) break;
        if (count < 0) { fclose(member); return -2; }
        if (fwrite(buffer, 1, (size_t)count, member) != (size_t)count) { fclose(member); return -1; }
        if (UINT64_MAX - total < (uint64_t)count) { fclose(member); return -1; }
        total += (uint64_t)count;
    }
    if (fflush(member) != 0 || fseek(member, 0, SEEK_SET) != 0) { fclose(member); return -1; }
    if (write_u8(1) != 0 || write_u8(kind) != 0 || write_u32((uint32_t)path_len) != 0 || write_u64(total) != 0 || write_all(path, path_len) != 0) { fclose(member); return -1; }
    for (;;) {
        size_t count = fread(buffer, 1, sizeof(buffer), member);
        if (count > 0 && write_all(buffer, count) != 0) { fclose(member); return -1; }
        if (count < sizeof(buffer)) { if (ferror(member)) { fclose(member); return -1; } break; }
    }
    fclose(member);
    return 0;
}
static int probe(void) {
    struct archive *a = archive_read_new();
    if (a == NULL) return 2;
    int rc = configure_reader(a);
    archive_read_free(a);
    if (rc != ARCHIVE_OK) return 3;
    printf("protocol=1\nlibarchive=%s\nsource_sha256=%s\nfilters=in_process\n", archive_version_number() >= 0 ? ARCHIVE_VERSION_ONLY_STRING : "unknown", PTAH_LIBARCHIVE_SOURCE_SHA);
    return 0;
}
static int parse_stdin(void) {
    FILE *source = tmpfile();
    if (source == NULL) return 2;
    char buffer[16384];
    for (;;) {
        size_t count = fread(buffer, 1, sizeof(buffer), stdin);
        if (count > 0 && fwrite(buffer, 1, count, source) != count) { fclose(source); return 2; }
        if (count < sizeof(buffer)) { if (ferror(stdin)) { fclose(source); return 2; } break; }
    }
    if (fflush(source) != 0 || fseek(source, 0, SEEK_SET) != 0) { fclose(source); return 2; }
    struct archive *a = archive_read_new();
    if (a == NULL) { fclose(source); return 2; }
    int rc = configure_reader(a);
    if (rc != ARCHIVE_OK) { archive_read_free(a); fclose(source); return 3; }
    if (write_all("PTAHA12\0", 8) != 0 || write_u32(1) != 0) { archive_read_free(a); fclose(source); return 2; }
    rc = archive_read_open_FILE(a, source);
    if (rc != ARCHIVE_OK) {
        const char *diag = archive_error_string(a);
        emit_terminal(11, a, diag == NULL ? "unsupported archive" : diag);
        archive_read_free(a); fclose(source); return 0;
    }
    struct archive_entry *entry = NULL;
    for (;;) {
        rc = archive_read_next_header(a, &entry);
        if (rc == ARCHIVE_EOF) { emit_terminal(0, a, ""); break; }
        if (rc < ARCHIVE_WARN) { emit_terminal(5, a, archive_error_string(a)); break; }
        if (rc == ARCHIVE_WARN) { emit_terminal(7, a, archive_error_string(a)); break; }
        if (archive_entry_is_encrypted(entry) == 1) { emit_terminal(1, a, "encrypted entry requires credential"); break; }
        int erc = emit_entry(a, entry);
        if (erc == -2) { emit_terminal(6, a, archive_error_string(a)); break; }
        if (erc != 0) { emit_terminal(7, a, "helper output failure"); break; }
    }
    archive_read_close(a);
    archive_read_free(a);
    fclose(source);
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--probe") == 0) return probe();
    if (argc == 2 && strcmp(argv[1], "--parse-stdin") == 0) return parse_stdin();
    return 64;
}
