#include <gcrypt.h>
#include <uuid/uuid.h>
#define NEED_LIBGCRYPT_VERSION "1.6.0"
#define BUFF_SIZE 32
#define IV_SIZE 32
#define TXT_SIZE 512
#define UUID_LEN 37
void 
app_log(int is_err, const char *fmt, ...)
{
    va_list args;
    FILE *fp;
    if (is_err) fp = stderr;
    else fp = stdout;
    va_start(args, fmt);
    vfprintf(fp, fmt, args );
    fprintf(fp, "\n" );
    va_end(args);
    abort();
}

#if 0
static unsigned char sect_t[UUID_LEN] __attribute__((section (".section_t"))) = { 0 };
void gen_uid() {
    uuid_t binuuid;
    char uuid[UUID_LEN];
    uuid_generate_random(uuid);
    uuid_unparse(binuuid, uuid);
    memcpy(sect_t, uuid, UUID_LEN);
}
#endif

void main() {
    int i;
    char *master_pwd = "atomic";
    char iv[IV_SIZE] = { 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0 };
    char keyBuffer[BUFF_SIZE];
    unsigned char plaintext[TXT_SIZE] = "the world is mine";
    unsigned char ciphertext[TXT_SIZE];
    unsigned char deciphertext[TXT_SIZE];
    memset(ciphertext, 0, 512);
    memset(deciphertext, 0, 512);
    char *salt = "5002a066-fd7f-0000-1e00-000000000000"; /// salt parameter that contains UUID
    size_t saltLen = strlen(salt);
    if (!gcry_check_version (NEED_LIBGCRYPT_VERSION)){
        fprintf (stderr, "libgcrypt is too old (need %s, have %s)\n",
                NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL));
        exit(2);
    }
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
      fputs ("libgcrypt has not been initialized\n", stderr);
      abort ();
    }
    gcry_cipher_hd_t cipherHd;
    gcry_error_t err;
    err = gcry_cipher_open(&cipherHd, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
    if(err) app_log(1, "Failed in grcy_cipher_open %s -> %s",
            gcry_strsource(err),
            gcry_strerror(err));
    gcry_kdf_derive(master_pwd, strlen(master_pwd), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, saltLen, 10000, BUFF_SIZE, keyBuffer);
    err = gcry_cipher_setkey(cipherHd, keyBuffer, BUFF_SIZE);
    if(err) app_log(1, "Failed in grcy_cipher_setkey %s -> %s",
            gcry_strsource(err),
            gcry_strerror(err));
    err = gcry_cipher_setiv(cipherHd, iv, 16);
    if(err) app_log(1, "Failed in grcy_cipher_setiv %s -> %s",
            gcry_strsource(err),
            gcry_strerror(err));
    err = gcry_cipher_encrypt(cipherHd, ciphertext, TXT_SIZE, plaintext, TXT_SIZE);
    if(err) app_log(1, "Failed in grcy_cipher_encrypt %s -> %s",
            gcry_strsource(err),
            gcry_strerror(err));
    err = gcry_cipher_setiv(cipherHd, iv, 16);
    if(err) app_log(1, "Failed in grcy_cipher_setiv %s -> %s",
            gcry_strsource(err),
            gcry_strerror(err));
    err = gcry_cipher_decrypt(cipherHd, deciphertext, TXT_SIZE, ciphertext, TXT_SIZE);
    if(err) app_log(1, "Failed in grcy_cipher_decrypt %s -> %s",
            gcry_strsource(err),
            gcry_strerror(err));
    printf("Encrypted: ");
    for (i = 0;  i < 512; i++) {
        printf("%d", ciphertext[i]);
    }
    printf("\n");
    printf("ASCII: %s\n", deciphertext);
    gcry_cipher_close(cipherHd);
}
