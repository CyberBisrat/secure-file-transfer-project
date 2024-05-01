#ifndef types_h
#define types_h

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;

typedef char mtype;
typedef uint seqnum;
typedef ushort flen;

#define SEQNUM_MAX ((1UL << 32) - 1)
#define LOGOUT_THRESHOLD 5
#define SEQ_MAX_THRESHOLD (SEQNUM_MAX - LOGOUT_THRESHOLD)

#define FLEN_MAX ((1 << 16) - 1)
#define FSIZE_MAX ((1UL << 32) - 1)

#define TAG_LEN 16
#define FNAME_MAX_LEN 128

// Size of a download/upload chunk
#define CHUNK_SIZE 32768

enum mtypes {
    // Authentication
    AuthStart,
    AuthServerAns,
    AuthClientAns,

    // Upload
    UploadReq,
    UploadAns,
    UploadChunk,
    UploadEnd,
    UploadRes,

    // Download
    DownloadReq,
    DownloadChunk,
    DownloadEnd,

    // Delete
    DeleteReq,
    DeleteConfirm,
    DeleteAns,
    DeleteRes,

    // List
    ListReq,
    ListAns,

    // Rename
    RenameReq,
    RenameAns,

    // Logout
    LogoutReq,
    LogoutAns,

    // Generic error
    Error
};

#endif
