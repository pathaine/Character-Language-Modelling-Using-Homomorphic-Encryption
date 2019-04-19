#ifndef KEYMANAGEMENT_H

#define KEYMANAGEMENT_H

#include <iostream>
#include <fstream>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include <stdio.h>
#include <unistd.h>
#include <iterator>
#include <list>

#include "palisade.h"
#include "../lib/cryptocontext.h"
#include "../lib/utils/serializable.h"
#include "../lib/utils/serializablehelper.h"


#include "cryptocontexthelper.h"
#include "encoding/encodings.h"
#include "utils/debug.h"
#include "cryptocontextgen.h"





using namespace std;
using namespace lbcrypto;
using namespace rapidjson;

struct EncryptionInfo {
    CryptoContext<DCRTPoly> cryptocontext;
    LPKeyPair<DCRTPoly> keypair;
};

bool FileExists( const string& name );
EncryptionInfo generate_encryption_info(const char *storagePath, size_t batchSize);
//LPPublicKey<DCRTPoly> read_public_key(const char *filePath);
EncryptionInfo read_encryption_info( const char *filePath);

#endif /* KEYMANAGEMENT_H */