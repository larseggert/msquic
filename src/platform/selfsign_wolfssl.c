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
    if (Handle == 0) {
        return 0;
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
        return 0;
    }

    uint8_t * Buffer = (uint8_t *)malloc(FileSize);
    if (Buffer == 0) {
        fclose(Handle);
        return 0;
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
        return 0;
    }
    return Buffer;
}


// Generates a self signed cert using WolfSSL
QUIC_STATUS CxPlatTlsGenerateSelfSignedCert(char * CertFileName,
                                            char * PrivateKeyFileName,
                                            char * SNI,
                                            char * Password,
                                            BOOLEAN OutputPkcs12)
{
    printf("CxPlatTlsGenerateSelfSignedCert %s %s %s %s\n", CertFileName,
           PrivateKeyFileName, SNI, Password);

    // UNREFERENCED_PARAMETER(CertFileName);
    // UNREFERENCED_PARAMETER(PrivateKeyFileName);
    // UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(OutputPkcs12);

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    FILE * Fd = 0;

    RNG rng;
    wc_InitRng(&rng);

    RsaKey key;
    wc_InitRsaKey(&key, 0);

    int ret = wc_MakeRsaKey(&key, 1024, 65537, &rng);
    if (ret != 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wc_MakeRsaKey failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    byte der[4096];
    ret = wc_RsaKeyToDer(&key, der, sizeof(der));
    if (ret < 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wc_RsaKeyToDer failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    byte key_pem[4096];
    const int len_key_pem =
        wc_DerToPem(der, ret, key_pem, sizeof(key_pem),
                    OutputPkcs12 ? PKCS8_PRIVATEKEY_TYPE : PRIVATEKEY_TYPE);
    if (len_key_pem < 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "wc_DerToPem failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Cert cert;
    wc_InitCert(&cert);
    strncpy(cert.subject.commonName, SNI, CTC_NAME_SIZE);

    ret = wc_MakeSelfCert(&cert, der, sizeof(der), &key, &rng);
    if (ret < 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
                       "wc_MakeSelfCert failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    byte cert_pem[4096];
    const int len_cert_pem =
        wc_DerToPem(der, ret, cert_pem, sizeof(cert_pem), CERT_TYPE);
    if (len_cert_pem < 0) {
        QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "wc_DerToPem failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    if (!OutputPkcs12) {

        Fd = fopen(PrivateKeyFileName, "wb");
        if (Fd == 0) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "fopen failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        // this writes w/o password
        ret = fwrite(key_pem, len_key_pem, 1, Fd);
        if (ret != 1) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "fwrite failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        fclose(Fd);
        Fd = 0;

        Fd = fopen(CertFileName, "wb");
        if (Fd == 0) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "fopen failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        ret = fwrite(cert_pem, len_cert_pem, 1, Fd);
        if (ret != 1) {
            QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "fwrite failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        fclose(Fd);
        Fd = 0;

    } else {
        puts("TODO OutputPkcs12");
        //     Pkcs12 = wolfSSL_PKCS12_create(Password, "MsQuicTest", PKey,
        //     X509, 0,
        //                                    Password == 0 ? -1 : 0,
        //                                    Password == 0 ? -1 : 0, 0, 0, 0);

        //     if (Pkcs12 == 0) {
        //         QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
        //                        "PKCS12_create failed");
        //         Status = QUIC_STATUS_TLS_ERROR;
        //         goto Exit;
        //     }

        //     Fd = fopen(CertFileName, "wb");
        //     if (Fd == 0) {
        //         QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.", "fopen
        //         failed"); Status = QUIC_STATUS_TLS_ERROR; goto Exit;
        //     }

        //     Ret = i2d_PKCS12_fp(Fd, Pkcs12);
        //     if (Ret != 1) {
        //         QuicTraceEvent(LibraryError, "[ lib] ERROR, %s.",
        //                        "i2d_PKCS12_fp failed");
        //         Status = QUIC_STATUS_TLS_ERROR;
        //         goto Exit;
        //     }
        //     fclose(Fd);
        //     Fd = 0;
    }

Exit:
    if (Fd != 0) {
        fclose(Fd);
        Fd = 0;
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
    printf("FindOrCreateTempFiles 1%s 2%s 3%s 4%s\n", CertFileName, KeyFileName,
           CertFilePath, KeyFilePath);

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

    if (KeyFileName != 0 && KeyFilePath != 0) {
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
    char * TempDir = 0;

    glob_t GlobData = {0};
    if (glob(TEMP_DIR_SEARCH, 0, 0, &GlobData) != 0 || GlobData.gl_pathc == 0) {
        globfree(&GlobData);
        //
        // Temp dir not found, create it
        //
        CxPlatCopyMemory(TempPath, TEMP_DIR_TEMPLATE,
                         sizeof(TEMP_DIR_TEMPLATE));

        TempDir = mkdtemp(TempPath);
        if (TempDir == 0) {
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

    if (KeyFilePath != 0 && KeyFileName != 0) {
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
    puts("CxPlatGetSelfSignedCert");

    UNREFERENCED_PARAMETER(Type);

    const char * CertFileName = 0;
    const char * KeyFileName = 0;

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
    if (Params == 0) {
        return 0;
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
            ClientCertificate ? (char *)"MsQuicClient" : (char *)"localhost", 0,
            FALSE))) {
        goto Error;
    }

    return (QUIC_CREDENTIAL_CONFIG *)Params;

Error:

#if _WIN32
    DeleteFileA(Params->CertFilepath);
    DeleteFileA(Params->PrivateKeyFilepath);
#endif
    free(Params);
    return 0;
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
    puts("CxPlatGetTestCertificate");

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

        const char * CertFileName = 0;
        const char * KeyFileName = 0;
        char * CertFilePath = 0;
        char * KeyFilePath = 0;
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
            if (CertFilePath == 0) {
                return FALSE;
            }
            KeyFilePath = CertFilePath + MAX_PATH;

            _Analysis_assume_(CertFile != 0);
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
            if (CertFilePath == 0) {
                return FALSE;
            }
            KeyFilePath = CertFilePath + MAX_PATH;

            _Analysis_assume_(CertFileProtected != 0);
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
            if (CertFilePath == 0) {
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
                CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE ? 0
                                                                  : TEST_PASS,
                CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12))) {
            goto Error;
        }

        if (CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
            Params->CertificateFile = CertFile;
            CertFilePath = 0;
        } else if (CredType ==
                   QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
            Params->CertificateFileProtected = CertFileProtected;
            CertFilePath = 0;
        } else {
            _Analysis_assume_(Pkcs12 != 0);
            Params->CertificatePkcs12 = Pkcs12;
            Pkcs12->Asn1Blob =
                ReadPkcs12(CertFilePath, &Pkcs12->Asn1BlobLength);
            if (Pkcs12->Asn1Blob == 0) {
                goto Error;
            }

            // Repurpose CertFilePath to store the password.
            Pkcs12->PrivateKeyPassword = CertFilePath;
            CxPlatCopyMemory(CertFilePath, TEST_PASS, sizeof(TEST_PASS));
            CertFilePath = 0;
        }
        Params->Type = CredType;
        Result = TRUE;
    Error:
        if (CertFilePath != 0) {
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
