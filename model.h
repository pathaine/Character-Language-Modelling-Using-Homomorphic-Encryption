#ifndef MODEL_H
#define MODEL_H

#include <fstream>
#include <fstream>
#include <string>
#include <vector>
#include <algorithm>
#include <random>
#include <unistd.h>
#include <string>
#include <stdio.h>
#include <chrono>

#include "../lib/cryptocontext.h"
#include "../lib/utils/serializable.h"
#include "../lib/utils/serializablehelper.h"

#include "cryptocontexthelper.h"
#include "encoding/encodings.h"
#include "utils/debug.h"
#include "keymanagement.h"

using namespace lbcrypto;
using namespace rapidjson;

int character_value_to_index(int value, int numberOfTypes);
Matrix<Plaintext> calculate_bigram_statistics(string filepath, int numberOfTypes, EncryptionInfo info);
Matrix<Plaintext> calculate_trigram_statistics(string filepath, int numberOfTypes, EncryptionInfo info);

#endif /* MODEL_H */