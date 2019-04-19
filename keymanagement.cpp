#include "keymanagement.h"

//TODO CHECK USER PERMISSIONS

bool FileExists( const string& name ) {
	ifstream file(name);
    if(!file) {
        return false;
    } else {
        return true;
	}
}

EncryptionInfo generate_encryption_info( const char *storagePath, size_t batchSize) {

	EncryptionInfo info;

	// benchmarking variables
	string storagePathStr = storagePath;//2032795649-1996647829
	//3281944577;//3277455361; 2458255361; are no good
	usint plaintextModulus = 65537;//12289;//2032795649;//1966473217;//1744896001;//1735032833;//1709670401;//1700134913;//1695907841;//1684996097;//1676279809;//1672544257;//1640366081;//1630044161;//1615495169;//1607827457;//1599963137;//1599275009;//1593081857;//1070727169;//1063452673;//526123009;//525434881;//520716289;//515571713;//510001153;//497221633;//493060097;//488243201;//14942209; //65537;//14942209; 1769473;
	double sigma = 3.2;
	double rootHermiteFactor = 1.0081;
	batchSize = 64;

	////////////////////////////////////////////////////////////
	// Parameter generation
	////////////////////////////////////////////////////////////
	//printf("STEP");
    SecurityLevel securityLevel = HEStd_256_classic;
   	EncodingParams encodingParams(new EncodingParamsImpl(plaintextModulus, batchSize));

	//Set Crypto Parameters
	// # of evalMults = 3 (first 3) is used to support the multiplication of 7 ciphertexts, i.e., ceiling{log2{7}}
	// Max depth is set to 3 (second 3) to generate homomorphic evaluation multiplication keys for s^2 and s^3
	CryptoContext<DCRTPoly> cc = CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
			encodingParams, securityLevel, sigma, 0, 3, 0, OPTIMIZED, 3);

	// enable features that you wish to use
	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);
    
	LPKeyPair<DCRTPoly> kp = cc->KeyGen();
    
	if( !kp.good() ) {
		std::cout << "Key generation failed!" << std::endl;
		exit(1);
	}

	usint m = cc->GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();
	cout << *cc->GetCryptoParameters()->GetEncodingParams() << endl;
	cout << *cc->GetCryptoParameters()->GetElementParams() << endl;

	PackedEncoding::SetParams(m, encodingParams);
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalMultKeyGen(kp.secretKey);

	Serialized emKeys, esKeys;

	if (cc->SerializeEvalMultKey(&emKeys)) {
		if (!SerializableHelper::WriteSerializationToFile(emKeys, storagePathStr + "/key-eval-mult.txt")) {
			cerr << "Error writing serialization of the eval mult keys to " + storagePathStr + "/key-eval-mult.txt" << endl;
			return info;
		}
	}
	else {
		cerr << "Error serializing eval mult keys" << endl;
		return info;
	}

	if (cc->SerializeEvalSumKey(&esKeys)) {
		if (!SerializableHelper::WriteSerializationToFile(esKeys, storagePathStr + "/key-eval-sum.txt")) {
			cerr << "Error writing serialization of the eval sum keys to " + storagePathStr + "/key-eval-sum.txt" << endl;
			return info;
		}
	}
	else {
		cerr << "Error serializing eval sum keys" << endl;
		return info;
	}

	Serialized pubK, privK;
	if (kp.publicKey->Serialize(&pubK)) {
		if (!SerializableHelper::WriteSerializationToFile(pubK, storagePathStr + "encryption_info_pubK.txt")) {
			cerr << "Error writing serialization of public key to " + storagePathStr + " /encryption_info_pubK.txt" << endl;
			return info;
		}
	}
	else {
		cerr << "Error serializing public key" << endl;
		return info;
	}
	if (kp.secretKey->Serialize(&privK)) {
		if (!SerializableHelper::WriteSerializationToFile(privK, storagePathStr + "/encryption_info_priK.txt")) {
			cerr << "Error writing serialization of public key to " + storagePathStr + "/encryption_info_priK.txt" << endl;
			return info;
		}
	}
	else {
		cerr << "Error serializing private key" << endl;
		return info;
	}

	info.cryptocontext = cc;
	info.keypair = kp;
		
	return info;
}

/*LPPublicKey<DCRTPoly> read_public_key( const char *filePath ){
	Serialized kser;
	LPPublicKey<DCRTPoly> pk;
	if ( SerializableHelper::ReadSerializationFromFile(filePath, &kser) == false ) {
		cerr << "Could not read public key" << endl;
		return pk;
	}

	pk = info.cryptocontext->deserializePublicKey( kser );
	if ( !pk ) {
		cerr << "Could not deserialize public key" << endl;
		return pk;
	}
	return pk;
}*/

EncryptionInfo read_encryption_info( const char *storagePath){
	EncryptionInfo info;
	Serialized kserPri, kserPub;
	string storagePathStr = storagePath;
	string storagePathStrSK = storagePath;
	storagePathStrSK += "/encryption_info_priK.txt";
	const char *skFile = storagePathStrSK.c_str();
	FILE* fp_sk = fopen(skFile, "r");
	if (fp_sk == 0)
		printf("failed to open %s\n", storagePathStrSK.c_str());

	char readBufferSK[65536];
	FileReadStream sSK(fp_sk, readBufferSK, sizeof(readBufferSK));

	kserPri.ParseStream(sSK);
	fclose(fp_sk);


	string storagePathStrPK = storagePath;
	storagePathStrPK += "/encryption_info_pubK.txt";
	const char *pkFile = storagePathStrPK.c_str();
	FILE* fp_pk = fopen(pkFile, "r");
	char readBufferPK[65536];
	FileReadStream sPK(fp_pk, readBufferPK, sizeof(readBufferPK));
	if (fp_pk == 0)
		printf("failed to open %s\n", storagePathStrPK.c_str());
	kserPub.ParseStream(sPK);
	fclose(fp_pk);

	info.cryptocontext = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(kserPri);

	const auto encodingParams = info.cryptocontext->GetCryptoParameters()->GetEncodingParams();
	const auto elementParams = info.cryptocontext->GetCryptoParameters()->GetElementParams();
	//cout << *info.cryptocontext->GetCryptoParameters()->GetEncodingParams() << endl;
	//cout << *info.cryptocontext->GetCryptoParameters()->GetElementParams() << endl;
	usint m = elementParams->GetCyclotomicOrder();

	PackedEncoding::SetParams(m, encodingParams);
	LPPrivateKey<DCRTPoly> sk = info.cryptocontext->deserializeSecretKey(kserPri);
	info.keypair.secretKey = sk;
	LPPublicKey<DCRTPoly> pk = info.cryptocontext->deserializePublicKey(kserPub);
	info.keypair.publicKey = pk;

	if (!sk) {
		cerr << "Could not deserialize public key" << endl;
		return info;
	}

	Serialized ccEmk;
	if (!SerializableHelper::ReadSerializationFromFile(storagePathStr + "/key-eval-mult.txt", &ccEmk)) {
		cerr << "I cannot read serialization from " << storagePathStr << "/key-eval-mult.txt" << endl;
		return info;
	}

	Serialized ccEsk;
	if (!SerializableHelper::ReadSerializationFromFile(storagePathStr + "/key-eval-sum.txt", &ccEsk)) {
		cerr << "I cannot read serialization from " << storagePathStr << "/key-eval-sum.txt" << endl;
		return info;
	}

	info.cryptocontext->DeserializeEvalMultKey(ccEmk);
	info.cryptocontext->DeserializeEvalSumKey(ccEsk);
	return info;
}