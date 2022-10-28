/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    OpenSSL implementation for generating the self-signed certificate.

--*/

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _WIN32
#include <glob.h>
#endif

#define QUIC_TEST_APIS 1
#include "platform_internal.h"

#include <wolfssl/options.h>

// force openssl compatibility off
#undef HAVE_OPENSSL_CMD
#undef OPENSSL_ALL
#undef WOLFSSL_ERROR_CODE_OPENSSL
#undef OPENSSL_EXTRA

// #include <wolfssl/openssl/evp.h>
// #include <wolfssl/openssl/pem.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/rsa.h>
// #include <wolfssl/wolfcrypt/pkcs12.h>

// #include <wolfssl/wolfcrypt/chacha20_poly1305.h>
// #include <wolfssl/wolfcrypt/error-crypt.h>
// #include <wolfssl/wolfcrypt/hmac.h>
// #include <wolfssl/wolfcrypt/wc_port.h>

#if 0
#define _CRT_SECURE_NO_WARNINGS // NOLINT
                                // bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp

#include <fcntl.h>
#ifndef _WIN32
#include <glob.h>
#endif
#include "platform_internal.h"
#ifdef _WIN32
#pragma warning(push)
#pragma warning(                                                               \
    disable : 4100) // Unreferenced parameter errcode in inline function
#endif

#include <wolfssl/options.h>

#include "wolfssl/openssl/err.h"
#include "wolfssl/openssl/kdf.h"
#include "wolfssl/openssl/pem.h"
#include "wolfssl/openssl/pkcs12.h"
#include "wolfssl/openssl/rsa.h"
#include "wolfssl/openssl/ssl.h"
#include "wolfssl/openssl/x509.h"

#ifdef _WIN32
#pragma warning(pop)
#endif
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#ifdef QUIC_CLOG
#include "selfsign_openssl.c.clog.h"
#endif
#endif


static uint8_t * ReadPkcs12(const char * Name, uint32_t * Length)
{
    size_t FileSize = 0;
    FILE * Handle = fopen(Name, "rb");
    if (Handle == NULL) {
        return NULL;
    }
#ifdef _WIN32
    struct _stat Stat;
    if (_fstat(_fileno(Handle), &Stat) == 0) {
        FileSize = (int)Stat.st_size;
    }
#else
    struct stat Stat;
    if (fstat(fileno(Handle), &Stat) == 0) {
        FileSize = (int)Stat.st_size;
    }
#endif
    if (FileSize == 0) {
        fclose(Handle);
        return NULL;
    }

    uint8_t * Buffer = (uint8_t *)malloc(FileSize);
    if (Buffer == NULL) {
        fclose(Handle);
        return NULL;
    }

    size_t ReadLength = 0;
    *Length = 0;
    do {
        ReadLength = fread(Buffer + *Length, 1, FileSize - *Length, Handle);
        *Length += (uint32_t)ReadLength;
    } while (ReadLength > 0 && *Length < (uint32_t)FileSize);
    fclose(Handle);
    if (*Length != FileSize) {
        free(Buffer);
        return NULL;
    }
    return Buffer;
}


//
// Generates a self signed cert using low level OpenSSL APIs.
//
QUIC_STATUS CxPlatTlsGenerateSelfSignedCert(char * CertFileName,
                                            char * PrivateKeyFileName,
                                            char * SNI,
                                            char * Password,
                                            BOOLEAN OutputPkcs12)
{
    UNREFERENCED_PARAMETER(CertFileName);
    UNREFERENCED_PARAMETER(PrivateKeyFileName);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(OutputPkcs12);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

#if 0
    int Ret = 0;
    WOLFSSL_EVP_PKEY * PKey = NULL;
    WOLFSSL_EVP_PKEY_CTX * EcKeyCtx = NULL;
    WOLFSSL_X509 * X509 = NULL;
    WOLFSSL_X509_NAME * Name = NULL;
    WC_PKCS12 * Pkcs12 = NULL;
#endif
    FILE * Fd = NULL;
#if 0
    PKey = wolfSSL_EVP_PKEY_new();
    if (PKey == NULL) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "EVP_PKEY_new failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    EcKeyCtx = wolfSSL_EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (EcKeyCtx == NULL) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "EVP_PKEY_CTX_new_id failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = EVP_PKEY_keygen_init(EcKeyCtx);
    if (Ret != 1) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "EVP_PKEY_keygen_init failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }
#endif


    RsaKey key;
    RNG rng;
    int ret;

    wc_InitRng(&rng);
    wc_InitRsaKey(&key, 0);

    ret = wc_MakeRsaKey(&key, 1024, 65537, &rng);
    if (ret != 0)
        /* ret contains error */;

#if 0
    Ret = EVP_PKEY_keygen(EcKeyCtx, &PKey);
    if (Ret != 1) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "EVP_PKEY_keygen failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509 = wolfSSL_X509_new();
    if (X509 == NULL) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "X509_new failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = ASN1_INTEGER_set(wolfSSL_X509_get_serialNumber(X509), 1);
    if (Ret != 1) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "ASN1_INTEGER_set failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509_gmtime_adj(X509_get_notBefore(X509), 0);
    X509_gmtime_adj(X509_get_notAfter(X509), 31536000L);

    X509_set_pubkey(X509, PKey);

    Name = X509_get_subject_name(X509);

    Ret = X509_NAME_add_entry_by_txt(Name, "C", MBSTRING_ASC,
                                     (unsigned char *)"CA", -1, -1, 0);
#endif

    Cert myCert;
    wc_InitCert(&myCert);

    strncpy(myCert.subject.country, "CA", CTC_NAME_SIZE);

#if 0
    if (Ret != 1) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "X509_NAME_add_entry_by_txt failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_NAME_add_entry_by_txt(Name, "O", MBSTRING_ASC,
                                     (unsigned char *)"Microsoft", -1, -1, 0);
#endif
    strncpy(myCert.subject.org, "Microsoft", CTC_NAME_SIZE);

#if 0
    if (Ret != 1) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "X509_NAME_add_entry_by_txt failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_NAME_add_entry_by_txt(Name, "CN", MBSTRING_ASC,
                                     (unsigned char *)SNI, -1, -1, 0);
#endif
    strncpy(myCert.subject.commonName, SNI, CTC_NAME_SIZE);

#if 0
    if (Ret != 1) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "X509_NAME_add_entry_by_txt failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_set_issuer_name(X509, Name);
    if (Ret != 1) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "X509_set_issuer_name failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_sign(X509, PKey, EVP_sha256());
    if (Ret <= 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "X509_sign failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }
#endif

    byte derCert[4096];

    int certSz = wc_MakeSelfCert(&myCert, derCert, sizeof(derCert), &key, &rng);
    if (certSz < 0) {
    }

#if 0
    if (!OutputPkcs12) {

        Fd = fopen(PrivateKeyFileName, "wb");
        if (Fd == NULL) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "fopen failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret = PEM_write_PrivateKey(Fd, PKey,
                                   Password == NULL ? NULL : EVP_aes_128_ecb(),
                                   NULL, 0, NULL, Password);
        if (Ret != 1) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "PEM_write_PrivateKey failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        fclose(Fd);
        Fd = NULL;

        Fd = fopen(CertFileName, "wb");
        if (Fd == NULL) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "fopen failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret = PEM_write_X509(Fd, X509);
        if (Ret != 1) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "PEM_write_X509 failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        fclose(Fd);
        Fd = NULL;

    } else {

        Pkcs12 = wolfSSL_PKCS12_create(Password, "MsQuicTest", PKey, X509, NULL,
                                       Password == NULL ? -1 : 0,
                                       Password == NULL ? -1 : 0, 0, 0, 0);

        if (Pkcs12 == NULL) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "PKCS12_create failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Fd = fopen(CertFileName, "wb");
        if (Fd == NULL) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "fopen failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret = i2d_PKCS12_fp(Fd, Pkcs12);
        if (Ret != 1) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "i2d_PKCS12_fp failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
        fclose(Fd);
        Fd = NULL;
    }
#endif

#if 0
Exit:
    if (PKey != NULL) {
        EVP_PKEY_free(PKey);
        PKey = NULL;
    }

    if (EcKeyCtx != NULL) {
        EVP_PKEY_CTX_free(EcKeyCtx);
        EcKeyCtx = NULL;
    }

    if (X509 != NULL) {
        X509_free(X509);
        X509 = NULL;
    }

    if (Pkcs12 != NULL) {
        wc_PKCS12_free(Pkcs12);
    }
#endif
    if (Fd != NULL) {
        fclose(Fd);
        Fd = NULL;
    }

    return Status;
}

static char * QuicTestServerCertFilename = (char *)"localhost_cert.pem";
static char * QuicTestServerPrivateKeyFilename = (char *)"localhost_key.pem";
static char * QuicTestServerPrivateKeyProtectedFilename =
    (char *)"localhost_key_prot.pem";
static char * QuicTestServerPkcs12Filename = (char *)"localhost_certkey.p12";
static char * QuicTestClientCertFilename = (char *)"client_cert.pem";
static char * QuicTestClientPrivateKeyFilename = (char *)"client_key.pem";
static char * QuicTestClientPrivateKeyProtectedFilename =
    (char *)"client_key_prot.pem";
static char * QuicTestClientPkcs12Filename = (char *)"client_certkey.p12";

#define TEST_PASS "placeholder"

#if 0
#ifndef MAX_PATH
#define MAX_PATH 50
#endif
#endif


typedef struct CXPLAT_CREDENTIAL_CONFIG_INTERNAL {
    QUIC_CREDENTIAL_CONFIG;
    QUIC_CERTIFICATE_FILE CertFile;
    char CertFilepath[MAX_PATH];
    char PrivateKeyFilepath[MAX_PATH];

} CXPLAT_CREDENTIAL_CONFIG_INTERNAL;

#define TEMP_DIR_TEMPLATE "/tmp/quictest.XXXXXX"

#define TEMP_DIR_SEARCH "/tmp/quictest.*"

BOOLEAN FindOrCreateTempFiles(const char * const CertFileName,
                              const char * const KeyFileName,
                              char * CertFilePath,
                              char * KeyFilePath)
{
#ifdef _WIN32
    char TempPath[MAX_PATH] = {0};
    char TempCertPath[MAX_PATH] = {0};
    char TempKeyPath[MAX_PATH] = {0};
    DWORD PathLength = GetTempPathA(sizeof(TempPath), TempPath);
    if (PathLength > MAX_PATH || PathLength <= 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "GetTempPathA failed");
        return FALSE;
    }
    CxPlatCopyMemory(TempCertPath, TempPath, PathLength);
    CxPlatCopyMemory(TempCertPath + PathLength, CertFileName,
                     strlen(CertFileName));
    CxPlatCopyMemory(TempCertPath + PathLength + strlen(CertFileName), "*\0",
                     2);

    WIN32_FIND_DATAA FindData = {0};
    HANDLE FindHandle = FindFirstFileA(TempCertPath, &FindData);
    if (FindHandle == INVALID_HANDLE_VALUE) {
        FindClose(FindHandle);
        //
        // File doesn't exist, create it
        //
        UINT TempFileStatus =
            GetTempFileNameA(TempPath, CertFileName, 0, CertFilePath);
        if (TempFileStatus == 0) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                           "GetTempFileNameA Cert Path failed");
            return FALSE;
        }
    } else {
        CxPlatCopyMemory(CertFilePath, TempPath, PathLength);
        CxPlatCopyMemory(
            CertFilePath + PathLength, FindData.cFileName,
            strnlen(FindData.cFileName, sizeof(FindData.cFileName)));
        FindClose(FindHandle);
        FindHandle = INVALID_HANDLE_VALUE;
    }

    if (KeyFileName != NULL && KeyFilePath != NULL) {
        CxPlatCopyMemory(TempKeyPath, TempPath, PathLength);
        CxPlatCopyMemory(TempKeyPath + PathLength, KeyFileName,
                         strlen(KeyFileName));
        CxPlatCopyMemory(TempKeyPath + PathLength + strlen(KeyFileName), "*\0",
                         2);

        FindHandle = FindFirstFileA(TempKeyPath, &FindData);
        if (FindHandle == INVALID_HANDLE_VALUE) {
            FindClose(FindHandle);
            //
            // File doesn't exist, create it
            //
            UINT TempFileStatus =
                GetTempFileNameA(TempPath, KeyFileName, 0, KeyFilePath);
            if (TempFileStatus == 0) {
                QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                               "GetTempFileNameA Key Path failed");
                return FALSE;
            }
        } else {
            CxPlatCopyMemory(KeyFilePath, TempPath, PathLength);
            CxPlatCopyMemory(
                KeyFilePath + PathLength, FindData.cFileName,
                strnlen(FindData.cFileName, sizeof(FindData.cFileName)));
            FindClose(FindHandle);
            FindHandle = INVALID_HANDLE_VALUE;
        }
    }

#else

    char TempPath[MAX_PATH] = {0};
    char * TempDir = NULL;

    glob_t GlobData = {0};
    if (glob(TEMP_DIR_SEARCH, 0, NULL, &GlobData) != 0 ||
        GlobData.gl_pathc == 0) {
        globfree(&GlobData);
        //
        // Temp dir not found, create it
        //
        CxPlatCopyMemory(TempPath, TEMP_DIR_TEMPLATE,
                         sizeof(TEMP_DIR_TEMPLATE));

        TempDir = mkdtemp(TempPath);
        if (TempDir == NULL) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "mkdtemp failed");
            return FALSE;
        }
    } else {
        //
        // Assume the first result is the desired folder
        //
        strncpy(TempPath, GlobData.gl_pathv[0],
                strnlen(GlobData.gl_pathv[0], sizeof(TempPath)));
        globfree(&GlobData);
        TempDir = TempPath;
    }

    CxPlatCopyMemory(CertFilePath, TempDir, strlen(TempDir));
    CxPlatCopyMemory(CertFilePath + strlen(TempDir), "/", 1);
    CxPlatCopyMemory(CertFilePath + strlen(TempDir) + 1, CertFileName,
                     strlen(CertFileName) + 1);

    if (KeyFilePath != NULL && KeyFileName != NULL) {
        CxPlatCopyMemory(KeyFilePath, TempDir, strlen(TempDir));
        CxPlatCopyMemory(KeyFilePath + strlen(TempDir), "/", 1);
        CxPlatCopyMemory(KeyFilePath + strlen(TempDir) + 1, KeyFileName,
                         strlen(KeyFileName) + 1);
    }
#endif

    return TRUE;
}


QUIC_CREDENTIAL_CONFIG *
CxPlatGetSelfSignedCert(CXPLAT_SELF_SIGN_CERT_TYPE Type,
                        BOOLEAN ClientCertificate)
{
    UNREFERENCED_PARAMETER(Type);
    UNREFERENCED_PARAMETER(ClientCertificate);
#if 0
    const char * CertFileName = NULL;
    const char * KeyFileName = NULL;

    if (ClientCertificate) {
#ifdef _WIN32
        CertFileName = "msquicopensslclientcert";
        KeyFileName = "msquicopensslclientkey";
#else
        CertFileName = QuicTestClientCertFilename;
        KeyFileName = QuicTestClientPrivateKeyFilename;
#endif
    } else {
#ifdef _WIN32
        CertFileName = "msquicopensslservercert";
        KeyFileName = "msquicopensslserverkey";
#else
        CertFileName = QuicTestServerCertFilename;
        KeyFileName = QuicTestServerPrivateKeyFilename;
#endif
    }

    CXPLAT_CREDENTIAL_CONFIG_INTERNAL * Params = malloc(
        sizeof(CXPLAT_CREDENTIAL_CONFIG_INTERNAL) + sizeof(TEMP_DIR_TEMPLATE));
    if (Params == NULL) {
        return NULL;
    }

    CxPlatZeroMemory(Params, sizeof(*Params));
    Params->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Params->CertificateFile = &Params->CertFile;
    Params->CertFile.CertificateFile = Params->CertFilepath;
    Params->CertFile.PrivateKeyFile = Params->PrivateKeyFilepath;

    if (!FindOrCreateTempFiles(CertFileName, KeyFileName, Params->CertFilepath,
                               Params->PrivateKeyFilepath)) {
        goto Error;
    }

    if (QUIC_FAILED(CxPlatTlsGenerateSelfSignedCert(
            Params->CertFilepath, Params->PrivateKeyFilepath,
            ClientCertificate ? (char *)"MsQuicClient" : (char *)"localhost",
            NULL, FALSE))) {
        goto Error;
    }

    return (QUIC_CREDENTIAL_CONFIG *)Params;

Error:

#if _WIN32
    DeleteFileA(Params->CertFilepath);
    DeleteFileA(Params->PrivateKeyFilepath);
#endif
    free(Params);
#endif
    return NULL;
}

BOOLEAN
CxPlatGetTestCertificate(CXPLAT_TEST_CERT_TYPE Type,
                         CXPLAT_SELF_SIGN_CERT_TYPE StoreType,
                         uint32_t CredType,
                         QUIC_CREDENTIAL_CONFIG * Params,
                         QUIC_CERTIFICATE_HASH * CertHash,
                         QUIC_CERTIFICATE_HASH_STORE * CertHashStore,
                         QUIC_CERTIFICATE_FILE * CertFile,
                         QUIC_CERTIFICATE_FILE_PROTECTED * CertFileProtected,
                         QUIC_CERTIFICATE_PKCS12 * Pkcs12,
                         char Principal[100])
{
    UNREFERENCED_PARAMETER(StoreType);
    UNREFERENCED_PARAMETER(CertHash);
    UNREFERENCED_PARAMETER(CertHashStore);
    UNREFERENCED_PARAMETER(Principal);

    BOOLEAN Result = FALSE;
    if ((Type == CXPLAT_TEST_CERT_SELF_SIGNED_SERVER ||
         Type == CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT) &&
        (CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE ||
         CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED ||
         CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12)) {

        const char * CertFileName = NULL;
        const char * KeyFileName = NULL;
        char * CertFilePath = NULL;
        char * KeyFilePath = NULL;
        BOOLEAN IsClient = Type == CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT;

        if (CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
            if (IsClient) {
                CertFileName = QuicTestClientCertFilename;
                KeyFileName = QuicTestClientPrivateKeyFilename;
            } else {
                CertFileName = QuicTestServerCertFilename;
                KeyFileName = QuicTestServerPrivateKeyFilename;
            }

            CertFilePath = malloc(MAX_PATH * 2);
            if (CertFilePath == NULL) {
                return FALSE;
            }
            KeyFilePath = CertFilePath + MAX_PATH;

            _Analysis_assume_(CertFile != NULL);
            CertFile->CertificateFile = CertFilePath;
            CertFile->PrivateKeyFile = KeyFilePath;
        } else if (CredType ==
                   QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
            if (IsClient) {
                CertFileName = QuicTestClientCertFilename;
                KeyFileName = QuicTestClientPrivateKeyProtectedFilename;
            } else {
                CertFileName = QuicTestServerCertFilename;
                KeyFileName = QuicTestServerPrivateKeyProtectedFilename;
            }

            CertFilePath = malloc((MAX_PATH * 2) + sizeof(TEST_PASS));
            if (CertFilePath == NULL) {
                return FALSE;
            }
            KeyFilePath = CertFilePath + MAX_PATH;

            _Analysis_assume_(CertFileProtected != NULL);
            CertFileProtected->CertificateFile = CertFilePath;
            CertFileProtected->PrivateKeyFile = KeyFilePath;
            CertFileProtected->PrivateKeyPassword = KeyFilePath + MAX_PATH;
            CxPlatCopyMemory(KeyFilePath + MAX_PATH, TEST_PASS,
                             sizeof(TEST_PASS));
        } else {
            if (IsClient) {
                CertFileName = QuicTestClientPkcs12Filename;
            } else {
                CertFileName = QuicTestServerPkcs12Filename;
            }
            CertFilePath = malloc(MAX_PATH);
            if (CertFilePath == NULL) {
                return FALSE;
            }
        }

        if (!FindOrCreateTempFiles(CertFileName, KeyFileName, CertFilePath,
                                   KeyFilePath)) {
            goto Error;
        }

        if (QUIC_FAILED(CxPlatTlsGenerateSelfSignedCert(
                CertFilePath, KeyFilePath,
                Type == CXPLAT_TEST_CERT_SELF_SIGNED_SERVER ? "localhost"
                                                            : "MsQuicClient",
                CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE ? NULL
                                                                  : TEST_PASS,
                CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12))) {
            goto Error;
        }

        if (CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
            Params->CertificateFile = CertFile;
            CertFilePath = NULL;
        } else if (CredType ==
                   QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
            Params->CertificateFileProtected = CertFileProtected;
            CertFilePath = NULL;
        } else {
            _Analysis_assume_(Pkcs12 != NULL);
            Params->CertificatePkcs12 = Pkcs12;
            Pkcs12->Asn1Blob =
                ReadPkcs12(CertFilePath, &Pkcs12->Asn1BlobLength);
            if (Pkcs12->Asn1Blob == NULL) {
                goto Error;
            }
            //
            // Repurpose CertFilePath to store the password.
            //
            Pkcs12->PrivateKeyPassword = CertFilePath;
            CxPlatCopyMemory(CertFilePath, TEST_PASS, sizeof(TEST_PASS));
            CertFilePath = NULL;
        }
        Params->Type = CredType;
        Result = TRUE;
    Error:
        if (CertFilePath != NULL) {
            free(CertFilePath);
        }
    }
    return Result;
}


void CxPlatFreeTestCert(QUIC_CREDENTIAL_CONFIG * Params)
{
    if (Params->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
        free((char *)Params->CertificateFile->CertificateFile);
    } else if (Params->Type ==
               QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
        free((char *)Params->CertificateFileProtected->CertificateFile);
    } else if (Params->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12) {
        free((uint8_t *)Params->CertificatePkcs12->Asn1Blob);
        free((char *)Params->CertificatePkcs12->PrivateKeyPassword);
    }
}

void CxPlatFreeSelfSignedCert(const QUIC_CREDENTIAL_CONFIG * CredConfig)
{
    CXPLAT_CREDENTIAL_CONFIG_INTERNAL * Params =
        (CXPLAT_CREDENTIAL_CONFIG_INTERNAL *)CredConfig;

    free(Params);
}
