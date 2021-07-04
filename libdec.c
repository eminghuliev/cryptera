#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <dlfcn.h>
#include <gcrypt.h>
#include <uuid/uuid.h>
#include <elf.h>
#define NEED_LIBGCRYPT_VERSION "1.6.0"
#define HIDDEN_SECTION ".section_t"
#define BUFF_SIZE 32
#define IV_SIZE 32
#define TXT_SIZE 512
#define UUID_LEN 37
void 
app_log(int is_err, const char *fmt, ...) {
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

FILE* open_file(PyObject *path, const char *mode) {
    FILE *f;
    int async_err = 0;
    PyObject *bytes;
    char *path_bytes;
    assert(PyGILState_Check());
    if (!PyUnicode_FSConverter(path, &bytes))
        return NULL;
    path_bytes = PyBytes_AS_STRING(bytes);
    do {
        Py_BEGIN_ALLOW_THREADS
        f = fopen(path_bytes, mode);
        Py_END_ALLOW_THREADS
    } while (f == NULL
             && errno == EINTR && !(async_err = PyErr_CheckSignals()));
    Py_DECREF(bytes);
    if (async_err)
        return NULL;
    if (f == NULL) {
        PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError, path);
        return NULL;
    }
    if (_Py_set_inheritable(fileno(f), 0, NULL) < 0) {
        fclose(f);
        return NULL;
    }
    return f;

}

static unsigned int read_elf(const char* fpath) {
    FILE * fp = NULL;
    Elf64_Ehdr elfHdr;
    Elf64_Shdr* shTbl;
    char* shbuff = NULL;
    unsigned int hdroffset = 0;
    PyObject *fobj = Py_BuildValue("s", fpath);
    fp = open_file(fobj, "rb");
    if(fp == NULL) {
        Py_DECREF(fobj);
        return 0;
    }
    fseek(fp, 0, SEEK_SET);
    fread(&elfHdr, 1, sizeof(elfHdr), fp);
    
    if(elfHdr.e_ident[1] != 'E' ||
       elfHdr.e_ident[2] != 'L' ||
       elfHdr.e_ident[3] != 'A') {
        PyErr_SetString(PyExc_RuntimeError, "corrupted ELF file - it has the wrong magic bytes at the start");
        goto dealloc;
    }
    shTbl = PyMem_Malloc(elfHdr.e_shentsize * elfHdr.e_shnum);
    if(!shTbl) {
        PyErr_NoMemory();
        goto dealloc;
    }
    if(!(elfHdr.e_shnum > 0)) {
        PyErr_SetString(PyExc_RuntimeError, "There should be at least one section header in ELF file");
        goto dealloc;
    }
    fseek(fp, elfHdr.e_shoff, SEEK_SET);
    fread(shTbl, 1, elfHdr.e_shentsize * elfHdr.e_shnum, fp);

    shbuff = PyMem_Malloc(shTbl[elfHdr.e_shstrndx].sh_size);
    if(!shbuff) {
        PyErr_NoMemory();
        PyMem_Free(shTbl);
        goto dealloc;
    }
    fseek(fp, shTbl[elfHdr.e_shstrndx].sh_offset, SEEK_SET);
    fread(shbuff, 1, shTbl[elfHdr.e_shstrndx].sh_size, fp);
    for(int i=0; i<elfHdr.e_shnum; i++) {
        if(!strcmp(HIDDEN_SECTION, shbuff + shTbl[i].sh_name)) {
            hdroffset = (unsigned int)shTbl[i].sh_offset;
        }
    }
    PyMem_Free(shTbl);
    PyMem_Free(shbuff);
dealloc:
    Py_DECREF(fobj);
    fclose(fp);
    return hdroffset;
}


#pragma GCC push_options
#pragma GCC optimize ("-O0")
static char sect_t[UUID_LEN] __attribute__((section (HIDDEN_SECTION))) = { 0 };
#pragma GCC pop_options
#if 0
void gen_uid() {
    uuid_t binuuid;
    char uuid[UUID_LEN];
    uuid_generate_random(uuid);
    uuid_unparse(binuuid, uuid);
    memcpy(sect_t, uuid, UUID_LEN);
}
#endif

static int initalized = 0;

static PyObject * crypt_init(PyObject *self, PyObject *args) {
    Dl_info info;
    if (dladdr(crypt_init, &info)) {
        const char *dli_fname = info.dli_fname;
        read_elf(dli_fname);
    }
    if(initalized) { 
        PyErr_SetString(PyExc_RuntimeError, "Cryptera has been initialized already"); 
        return NULL; 
    }
    if (!gcry_check_version (NEED_LIBGCRYPT_VERSION)) {
        PyErr_Format(PyExc_RuntimeError, "libgcrypt is too old (need %s, have %s)\n",
                NEED_LIBGCRYPT_VERSION, gcry_check_version (NULL));
        return NULL;
    }
    gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

    gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

    gcry_control (GCRYCTL_RESUME_SECMEM_WARN);
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
    if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
        PyErr_SetString(PyExc_RuntimeError, "libgcrypt has not been initialized");
        return NULL;
    }
    initalized = 1;
    Py_RETURN_NONE;
}

static PyObject * decode_fn(PyObject *self, PyObject *args) {
    const char *payload;
    if(!initalized) { 
        PyErr_SetString(PyExc_RuntimeError, "Cryptera should be initialized"); 
        return NULL; 
    }
    if (!PyArg_ParseTuple(args, "s", &payload))
        return NULL;
    return NULL;
}

static PyObject * encode_fn(PyObject *self, PyObject *args)
{
    const char *payload;
    const char *mpwd_str;
    if(!initalized) { 
        PyErr_SetString(PyExc_RuntimeError, "Cryptera should be initialized"); 
        return NULL; 
    }
    if(PyTuple_GET_SIZE(args) < 2) {
        PyErr_SetString(PyExc_TypeError, 
                        "Encode function should have at least 2 arguments");
        return NULL;
    }
    PyObject *mpwd_tuple;
    PyObject *cipher_tuple;
    Py_ssize_t cipher_size;
    mpwd_tuple = PyTuple_GET_ITEM(args, 0);
    cipher_tuple = PyTuple_GET_ITEM(args, 1);
    if (!PyUnicode_Check(mpwd_tuple) || !PyUnicode_Check(cipher_tuple)) {
        PyErr_SetString(PyExc_TypeError,
                        "master pwd and cipher tuple must be a string");
        return NULL;
    }
    mpwd_str = PyUnicode_AsUTF8(mpwd_tuple);
    payload = PyUnicode_AsUTF8AndSize(cipher_tuple, &cipher_size);
    if (cipher_size > TXT_SIZE) {
        PyErr_SetString(PyExc_TypeError,
                        "cipher payload should be less than 512 bytes");
        return NULL;
    }
    const char *master_pwd = mpwd_str;
    char iv[IV_SIZE];
    memset(iv, 0x0, IV_SIZE);
    char keyBuffer[BUFF_SIZE];
    unsigned char plaintext[TXT_SIZE];
    memset(plaintext, 0x0, TXT_SIZE);
    memcpy(plaintext, payload, TXT_SIZE);
    Py_DECREF(payload);
    unsigned char ciphertext[TXT_SIZE];
    memset(ciphertext, 0x0, TXT_SIZE);
    char *salt = sect_t;
    size_t saltLen = strlen(salt);
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
    gcry_cipher_close(cipherHd);
    Py_DECREF(mpwd_str);
    int i;
    PyObject *pylist, *item;
    pylist = PyList_New(TXT_SIZE);
    for (i = 0; i < TXT_SIZE; i ++) {
        item = PyLong_FromLong(ciphertext[i]);
        if (!item) {
            PyErr_SetString(PyExc_TypeError,
                            "failed to allocate encoded payload");
            Py_DECREF(pylist);
            return NULL;
        }
        PyList_SetItem(pylist, i, item);
    }
    return pylist;
}

static PyMethodDef CryptoMethods[] = {
    {"decode",  decode_fn, METH_VARARGS,
     "Cryptera payload decoder"},
     {"encode",  encode_fn, METH_VARARGS,
     "Cryptera payload encoder"},
     {"init",  crypt_init, METH_VARARGS,
     "Cryptera payload initializer"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef cryptomodule = {
    PyModuleDef_HEAD_INIT,
    "cryptera",
    0, /// doc string
    -1,
    CryptoMethods
};

PyMODINIT_FUNC
PyInit_cryptera(void)
{
    return PyModule_Create(&cryptomodule);
}
