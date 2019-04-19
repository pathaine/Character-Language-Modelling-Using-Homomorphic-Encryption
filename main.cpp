#include "keymanagement.h"
#include "model.h"
#include <tuple>
#include <string>
#include <stdio.h>
#include <chrono>


std::tuple<Ciphertext<DCRTPoly>, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> generate_encrypted_inputs_for_bigram_statistic(int value, int numberOfTypes, EncryptionInfo info) {
	Plaintext currentCharacterPlaintext;
	Ciphertext<DCRTPoly> currentCharacterCiphertext;
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> currentCharacterCiphertextMatrix;
	int index = character_value_to_index(value, numberOfTypes);
	auto zeroAlloc = [=]() { return Plaintext(); };
	Matrix<Plaintext> currentCharacterPlaintextMatrix = Matrix<Plaintext>(zeroAlloc, numberOfTypes, 1);

	vector<int64_t> current(numberOfTypes, 0);
	current[index] = 1;
	currentCharacterPlaintext = info.cryptocontext->MakePackedPlaintext(current);
	currentCharacterCiphertext = info.cryptocontext->Encrypt(info.keypair.publicKey, currentCharacterPlaintext);
	
	for (int i = 0; i < numberOfTypes; i++) {
		vector<int64_t> currentRow(numberOfTypes, current[i]);
		currentCharacterPlaintextMatrix(i,0) = info.cryptocontext->MakePackedPlaintext(currentRow);
	}
	currentCharacterCiphertextMatrix = info.cryptocontext->EncryptMatrix(info.keypair.publicKey, currentCharacterPlaintextMatrix);

	return {currentCharacterCiphertext, currentCharacterCiphertextMatrix};
}

std::tuple<Ciphertext<DCRTPoly>, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>, shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>>> generate_encrypted_inputs_for_trigram_statistic(int value, int numberOfTypes, EncryptionInfo info) {
	int index = character_value_to_index(value, numberOfTypes);
	vector<int64_t> current27(numberOfTypes, 0);
	vector<int64_t> current729a(numberOfTypes * numberOfTypes, 0);
	vector<int64_t> current729b(numberOfTypes * numberOfTypes, 0);
	auto zeroAlloc = [=]() { return Plaintext(); };
	Matrix<Plaintext> currentCharacterPlaintextMatrix27 = Matrix<Plaintext>(zeroAlloc, numberOfTypes, 1);
	Matrix<Plaintext> currentCharacterPlaintextMatrix729a = Matrix<Plaintext>(zeroAlloc, numberOfTypes * numberOfTypes, 1);
	Matrix<Plaintext> currentCharacterPlaintextMatrix729b = Matrix<Plaintext>(zeroAlloc, numberOfTypes * numberOfTypes, 1);
	Plaintext currentCharacterPlaintext27;
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> currentCharacterCiphertextMatrix27;
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> currentCharacterCiphertextMatrix729a;
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> currentCharacterCiphertextMatrix729b;
	Ciphertext<DCRTPoly> currentCharacterCiphertext27;
	
	current27[index] = 1;

	for (int i = index; i < numberOfTypes * numberOfTypes; i += numberOfTypes) {
		current729a[i] = 1;
	}
	
	for (int i = index * numberOfTypes; i < index * numberOfTypes + numberOfTypes; i++) {
		current729b[i] = 1;
	}
	
	currentCharacterPlaintext27 = info.cryptocontext->MakePackedPlaintext(current27);
	currentCharacterCiphertext27 = info.cryptocontext->Encrypt(info.keypair.publicKey, currentCharacterPlaintext27);

	for (int i = 0; i < numberOfTypes; i++) {
		vector<int64_t> currentRow(numberOfTypes, current27[i]);
		currentCharacterPlaintextMatrix27(i,0) = info.cryptocontext->MakePackedPlaintext(currentRow);
	}
	currentCharacterCiphertextMatrix27 = info.cryptocontext->EncryptMatrix(info.keypair.publicKey, currentCharacterPlaintextMatrix27);

	for (int i = 0; i < numberOfTypes * numberOfTypes; i++) {
		vector<int64_t> currentRow(numberOfTypes * numberOfTypes, current729a[i]);
		currentCharacterPlaintextMatrix729a(i,0) = info.cryptocontext->MakePackedPlaintext(currentRow);
	}
	currentCharacterCiphertextMatrix729a = info.cryptocontext->EncryptMatrix(info.keypair.publicKey, currentCharacterPlaintextMatrix729a);

	for (int i = 0; i < numberOfTypes * numberOfTypes; i++) {
		vector<int64_t> currentRow(numberOfTypes * numberOfTypes,current729b[i]);
		currentCharacterPlaintextMatrix729b(i,0) = info.cryptocontext->MakePackedPlaintext(currentRow);
	}
	currentCharacterCiphertextMatrix729b = info.cryptocontext->EncryptMatrix(info.keypair.publicKey, currentCharacterPlaintextMatrix729b);

	return {currentCharacterCiphertext27, currentCharacterCiphertextMatrix27, currentCharacterCiphertextMatrix729a, currentCharacterCiphertextMatrix729b};
}

int main(int argc, char *argv[]) {

	double diff, start, finish;
	shared_ptr<Matrix<Plaintext>> numerator;
	auto zeroAlloc = [=]() { return Plaintext(); };

	generate_encryption_info("/mnt/c/Users/patri/Documents/141PALISADE/PALISADE/src/pke/CharacterLanguageModel/Keys/", 2048);
	EncryptionInfo info = read_encryption_info("/mnt/c/Users/patri/Documents/141PALISADE/PALISADE/src/pke/CharacterLanguageModel/Keys/");
	

	int num = 27; //INCREASE ACCORDING TO DATASET -- 27 here for a-z & space
	std::cout << "number of characters = " << num << std::endl;


	string filepath = "/mnt/c/Users/patri/Documents/141PALISADE/PALISADE/src/pke/CharacterLanguageModel/train_emails.txt";
	

	/* CALCULATE BIGRAM STATISTIC */

	Matrix<Plaintext> plaintextBigrams = calculate_bigram_statistics(filepath, num, info);

	/* CALCULATE TRIGRAM STATISTIC */

	Matrix<Plaintext> plaintextTrigrams = calculate_trigram_statistics(filepath, num, info);
	
    /* START: ENCRYPTED DATA, PLAINTEXT BIGRAM MODEL */
    
	std::ifstream inFile;

	inFile.open("/mnt/c/Users/patri/Documents/141PALISADE/PALISADE/src/pke/CharacterLanguageModel/dev_emails.txt", ios::in);
	
	start = currentDateTime();
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> currentCharacterCiphertextMatrix, previousCharacterCiphertextMatrix;
	Ciphertext<DCRTPoly> currentCharacterCiphertext, previousCharacterCiphertext;

	
	vector<int64_t> prob(num,0);
	Plaintext probabilityPT = info.cryptocontext->MakePackedPlaintext(prob);

	bool first = true;
	
	int likelihoodOfCurrentCharacter;
	char currentCharacter;
	while (!inFile.eof()) {
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> result = info.cryptocontext->EncryptMatrix(info.keypair.publicKey, plaintextBigrams);
	
		inFile.get(currentCharacter);

		tie(currentCharacterCiphertext, currentCharacterCiphertextMatrix) = generate_encrypted_inputs_for_bigram_statistic(currentCharacter, num, info);

		Ciphertext<DCRTPoly> probabilityCT = info.cryptocontext->Encrypt(info.keypair.publicKey, probabilityPT);


		if (first) {
			previousCharacterCiphertextMatrix = currentCharacterCiphertextMatrix;
			previousCharacterCiphertext = currentCharacterCiphertext;
			first = false;
			continue;
		}

		/* HERE IS WHERE THE MAGIC HAPPENS -- THIS WOULD HAPPEN ON THE SERVER SIDE */
		for (int i = 0; i < num; i++) {
			(*result)(i,0).SetNumerator(info.cryptocontext->EvalMult(plaintextBigrams(i,0), (*previousCharacterCiphertextMatrix)(i,0).GetNumerator()));
			(*result)(i,0).SetNumerator(info.cryptocontext->EvalMult((*result)(i,0).GetNumerator(), currentCharacterCiphertext));
			probabilityCT = info.cryptocontext->EvalAdd(probabilityCT,(*result)(i,0).GetNumerator());
		}
		probabilityCT = info.cryptocontext->EvalSum(probabilityCT,32);

		finish = currentDateTime();
		diff = finish - start;
		std::cout << "bigram statistic runtime (ms): " << diff << std::endl;

		/* DECRYPT STAT */
		shared_ptr<Matrix<Plaintext>> numerator;
	
		info.cryptocontext->DecryptMatrixNumerator(info.keypair.secretKey, result, &numerator);
		

		Plaintext cur;

		info.cryptocontext->Decrypt(info.keypair.secretKey, probabilityCT, &cur);

		std::cout << (float)(cur->GetPackedValue()[0]) / 1000.0f << std::endl;

		previousCharacterCiphertextMatrix = currentCharacterCiphertextMatrix;
		previousCharacterCiphertext = currentCharacterCiphertext;

		break; //REMOVE THIS IF YOU WANT TO CONTINUE CALCULATING STATISTICS

	}

	inFile.close();
    /* END: ENCRYPTED DATA, PLAINTEXT BIGRAM MODEL */




    /* START: ENCRYPTED DATA, PLAINTEXT TRIGRAM MODEL */

	std::ifstream inFile2;

	inFile2.open("/mnt/c/Users/patri/Documents/141PALISADE/PALISADE/src/pke/CharacterLanguageModel/dev_emails.txt", ios::in);
	start = currentDateTime();
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> currentCharacterCiphertextMatrix27;
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> currentCharacterCiphertextMatrix729a;
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> currentCharacterCiphertextMatrix729b;
	Ciphertext<DCRTPoly> currentCharacterCiphertext27;

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> previousCharacterCiphertextMatrix729a;
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> previousCharacterCiphertextMatrix729b;
	Ciphertext<DCRTPoly> previousCharacterCiphertext729a;
	Ciphertext<DCRTPoly> previousCharacterCiphertext729b;

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> previousPreviousCharacterCiphertextMatrix729b;
	Ciphertext<DCRTPoly> previousPreviousCharacterCiphertext729b;

	first = true;
	bool second = true;
	while (!inFile2.eof()) {
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> resultTri = info.cryptocontext->EncryptMatrix(info.keypair.publicKey, plaintextTrigrams);
		
		Ciphertext<DCRTPoly> probabilityCT = info.cryptocontext->Encrypt(info.keypair.publicKey,probabilityPT);

		inFile2.get(currentCharacter);

		tie(currentCharacterCiphertext27, currentCharacterCiphertextMatrix27, currentCharacterCiphertextMatrix729a, currentCharacterCiphertextMatrix729b) = generate_encrypted_inputs_for_trigram_statistic(currentCharacter, num, info);

		if (first) {
			previousCharacterCiphertextMatrix729a = currentCharacterCiphertextMatrix729a;
			previousCharacterCiphertextMatrix729b = currentCharacterCiphertextMatrix729b;
			first = false;
			continue;
		} else if (second){
			previousPreviousCharacterCiphertextMatrix729b = previousCharacterCiphertextMatrix729b;
			previousPreviousCharacterCiphertext729b = previousCharacterCiphertext729b;
			previousCharacterCiphertextMatrix729a = currentCharacterCiphertextMatrix729a;
			previousCharacterCiphertextMatrix729b = currentCharacterCiphertextMatrix729b;
			second = false;
			continue;			
		}

		/* HERE IS WHERE THE MAGIC HAPPENS -- THIS WOULD HAPPEN ON THE SERVER SIDE */
		for (int i = 0; i < num*num; i++) {
			(*resultTri)(i,0).SetNumerator(info.cryptocontext->EvalMult((*previousPreviousCharacterCiphertextMatrix729b)(i,0).GetNumerator(),(*previousCharacterCiphertextMatrix729a)(i,0).GetNumerator()));
			(*resultTri)(i,0).SetNumerator(info.cryptocontext->EvalMult(plaintextTrigrams(i,0),(*resultTri)(i,0).GetNumerator()));
			(*resultTri)(i,0).SetNumerator(info.cryptocontext->EvalMult((*resultTri)(i,0).GetNumerator(), currentCharacterCiphertext27));
			probabilityCT = info.cryptocontext->EvalAdd(probabilityCT,(*resultTri)(i,0).GetNumerator());
		}
		probabilityCT = info.cryptocontext->EvalSum(probabilityCT,32);

		finish = currentDateTime();
		diff = finish - start;
		std::cout << "trigram statistic runtime (ms):" << diff << std::endl;

		/* DECRYPT STAT */

		Plaintext cur;

		info.cryptocontext->Decrypt(info.keypair.secretKey, probabilityCT, &cur);
		std::cout << (float)(cur->GetPackedValue()[0])/ 1000.0f << std::endl;

		previousCharacterCiphertextMatrix = currentCharacterCiphertextMatrix;
		previousCharacterCiphertext = currentCharacterCiphertext;

		break; //REMOVE THIS IF YOU WANT TO CONTINUE CALCULATING  TATISTICS

	}
	inFile2.close();

    /* END: ENCRYPTED DATA, PLAINTEXT TRIGRAM MODEL */




 	/* START: ENCRYPTED DATA, ENCRYPTED BIGRAM MODEL */

	std::ifstream inFile3;

	inFile3.open("/mnt/c/Users/patri/Documents/141PALISADE/PALISADE/src/pke/CharacterLanguageModel/dev_emails.txt", ios::in);

	start = currentDateTime();
	first = true;
	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> bigramsCT = info.cryptocontext->EncryptMatrix(info.keypair.publicKey, plaintextBigrams);

	while (!inFile3.eof()) {

		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> result = info.cryptocontext->EncryptMatrix(info.keypair.publicKey, plaintextBigrams);

		Ciphertext<DCRTPoly> probabilityCT = info.cryptocontext->Encrypt(info.keypair.publicKey,probabilityPT);

		inFile3.get(currentCharacter);
		
		tie(currentCharacterCiphertext, currentCharacterCiphertextMatrix) = generate_encrypted_inputs_for_bigram_statistic(currentCharacter, num, info);

		if (first) {
			previousCharacterCiphertextMatrix = currentCharacterCiphertextMatrix;
			previousCharacterCiphertext = currentCharacterCiphertext;
			first = false;
			continue;
		}

		/* HERE IS WHERE THE MAGIC HAPPENS -- THIS WOULD HAPPEN ON THE SERVER SIDE */
		for (int i = 0; i < num; i++) {
			(*result)(i,0).SetNumerator(info.cryptocontext->EvalMult((*bigramsCT)(i,0).GetNumerator(),(*previousCharacterCiphertextMatrix)(i,0).GetNumerator()));
			(*result)(i,0).SetNumerator(info.cryptocontext->EvalMult((*result)(i,0).GetNumerator(), currentCharacterCiphertext));
			probabilityCT = info.cryptocontext->EvalAdd(probabilityCT,(*result)(i,0).GetNumerator());
		}
		probabilityCT = info.cryptocontext->EvalSum(probabilityCT,32);

		finish = currentDateTime();
		diff = finish - start;
		std::cout << "trigram statistic runtime (ms):" << diff << std::endl;
		
		/* DECRYPT STAT */

		shared_ptr<Matrix<Plaintext>> numerator;
	
		info.cryptocontext->DecryptMatrixNumerator(info.keypair.secretKey, bigramsCT, &numerator);

		Plaintext cur;

		info.cryptocontext->Decrypt(info.keypair.secretKey, probabilityCT, &cur);

		cout << (float)(cur->GetPackedValue()[0]) / 1000.0f << endl;

		previousCharacterCiphertextMatrix = currentCharacterCiphertextMatrix;
		previousCharacterCiphertext = currentCharacterCiphertext;

		break; //REMOVE THIS IF YOU WANT TO CONTINUE CALCULATING STATISTICS

	}
	inFile3.close();

    /* END: ENCRYPTED DATA, ENCRYPTED BIGRAM MODEL */



    
    /* START: ENCRYPTED DATA, ENCRYPTED TRIGRAM MODEL */

	std::ifstream inFile4;

	inFile4.open("/mnt/c/Users/patri/Documents/141PALISADE/PALISADE/src/pke/CharacterLanguageModel/dev_emails.txt", ios::in);

	shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> trigramsCT = info.cryptocontext->EncryptMatrix(info.keypair.publicKey,plaintextTrigrams);
	start = currentDateTime();
	//Plaintext previousCharacterPlaintext;
	first = true;
	second = true;
	while (!inFile4.eof()) {
		shared_ptr<Matrix<RationalCiphertext<DCRTPoly>>> resultTri = info.cryptocontext->EncryptMatrix(info.keypair.publicKey, plaintextTrigrams);
		
		Ciphertext<DCRTPoly> probabilityCT = info.cryptocontext->Encrypt(info.keypair.publicKey,probabilityPT);

		inFile4.get(currentCharacter);
		//std::cout << currentCharacter << std::endl;
		tie(currentCharacterCiphertext27, currentCharacterCiphertextMatrix27, currentCharacterCiphertextMatrix729a, currentCharacterCiphertextMatrix729b) = generate_encrypted_inputs_for_trigram_statistic(currentCharacter, num, info);

		if (first) {
			previousCharacterCiphertextMatrix729a = currentCharacterCiphertextMatrix729a;
			previousCharacterCiphertextMatrix729b = currentCharacterCiphertextMatrix729b;
			first = false;
			continue;
		} else if (second){
			previousPreviousCharacterCiphertextMatrix729b = previousCharacterCiphertextMatrix729b;
			previousPreviousCharacterCiphertext729b = previousCharacterCiphertext729b;
			previousCharacterCiphertextMatrix729a = currentCharacterCiphertextMatrix729a;
			previousCharacterCiphertextMatrix729b = currentCharacterCiphertextMatrix729b;
			second = false;
			continue;			
		}

		/* HERE IS WHERE THE MAGIC HAPPENS -- THIS WOULD HAPPEN ON THE SERVER SIDE */
		for (int i = 0; i < num*num; i++) {
			//cout << i << endl;
			(*resultTri)(i,0).SetNumerator(info.cryptocontext->EvalMult((*previousPreviousCharacterCiphertextMatrix729b)(i,0).GetNumerator(),(*previousCharacterCiphertextMatrix729a)(i,0).GetNumerator()));
			(*resultTri)(i,0).SetNumerator(info.cryptocontext->EvalMult((*trigramsCT)(i,0).GetNumerator(),(*resultTri)(i,0).GetNumerator()));
			(*resultTri)(i,0).SetNumerator(info.cryptocontext->EvalMult((*resultTri)(i,0).GetNumerator(), currentCharacterCiphertext27));
			probabilityCT = info.cryptocontext->EvalAdd(probabilityCT,(*resultTri)(i,0).GetNumerator());
		}
		probabilityCT = info.cryptocontext->EvalSum(probabilityCT,32);

		finish = currentDateTime();
		diff = finish - start;
		std::cout << "trigram statistic runtime (ms):" << diff << std::endl;
		
		/* DECRYPT STAT */

		Plaintext cur;

		info.cryptocontext->Decrypt(info.keypair.secretKey, probabilityCT, &cur);
		std::cout << (float)(cur->GetPackedValue()[0]) / 1000.0f << std::endl;

		previousCharacterCiphertextMatrix = currentCharacterCiphertextMatrix;
		previousCharacterCiphertext = currentCharacterCiphertext;

		break; //REMOVE THIS IF YOU WANT TO CONTINUE CALCULATING STATISTICS

	}
	inFile4.close();
    
    /* END: ENCRYPTED DATA, ENCRYPTED TRIGRAM MODEL */

	return 0;
}
