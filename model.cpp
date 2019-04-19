#include "model.h"

int character_value_to_index(int value, int numberOfTypes) {
	int index;
	if (value == 32 || value == 13 || value == 10) {
		index = numberOfTypes-1;
	} else {
		index = value - 97;
	}
	return index;
}

Matrix<Plaintext> calculate_bigram_statistics(string filepath, int numberOfTypes, EncryptionInfo info) {
	auto zeroAlloc = [=]() { return Plaintext(); };

	std::ifstream inFile;
	inFile.open(filepath, ios::in);

	vector<vector<int64_t>> bigrams(numberOfTypes, vector<int64_t>(numberOfTypes, 0));
	vector<int64_t> totals(numberOfTypes, 0);

	char currentCharacter;
	int previousCharacterIndex = 9999;

	Matrix<Plaintext> plaintextBigrams = Matrix<Plaintext>(zeroAlloc, numberOfTypes, 1);

	while (!inFile.eof()) {
		inFile.get(currentCharacter);

		int currentCharacterIndex = character_value_to_index((int) currentCharacter, numberOfTypes);
		
		if (currentCharacterIndex > numberOfTypes - 1 || currentCharacterIndex < 0) {
			continue;
		}
		if (previousCharacterIndex == 9999) {
			previousCharacterIndex = currentCharacterIndex;
			continue;
		}
		bigrams[previousCharacterIndex][currentCharacterIndex] += 1;
		totals[previousCharacterIndex] += 1;
		
		previousCharacterIndex = currentCharacterIndex;
	}
	std::cout << "bigrams:" << bigrams << std::endl;
	std::cout << "totals:" << totals << std::endl;	

	for (int i = 0; i < numberOfTypes; i++) {
		for (int j = 0; j < numberOfTypes; j++) {
			if (totals[i] == 0) {
				bigrams[i][j] = 0;
			} else {
				bigrams[i][j] = int(bigrams[i][j] * 1000 / totals[i]);
			}
		}
		plaintextBigrams(i, 0) = info.cryptocontext->MakePackedPlaintext(bigrams[i]);
	}
	std::cout << "bigrams:" << bigrams << std::endl;

	inFile.close();

	return plaintextBigrams;
}

Matrix<Plaintext> calculate_trigram_statistics(string filepath, int numberOfTypes, EncryptionInfo info) {

	int previousCharacterIndex = 9999;
	int previousPreviousCharacterIndex = 9999;
	int index = 0;
	char currentCharacter;
	vector<vector<int64_t>> trigrams(numberOfTypes * numberOfTypes, vector<int64_t>(numberOfTypes, 0));
	vector<int64_t> totals(numberOfTypes * numberOfTypes, 0);

	auto zeroAlloc = [=]() { return Plaintext(); };
	Matrix<Plaintext> plaintextTrigrams = Matrix<Plaintext>(zeroAlloc, numberOfTypes * numberOfTypes, 1);
	std::ifstream inFile;

	inFile.open(filepath, ios::in);

	while (!inFile.eof()) {
		inFile.get(currentCharacter);
		int currentCharacterIndex = character_value_to_index((int) currentCharacter, numberOfTypes);

		if (currentCharacterIndex > 26 || currentCharacterIndex < 0) {
			continue;
		}
		if (previousCharacterIndex == 9999) {
			previousCharacterIndex = currentCharacterIndex;
			continue;
		}
		if (previousPreviousCharacterIndex == 9999) {
			previousPreviousCharacterIndex = previousCharacterIndex;
			previousCharacterIndex = currentCharacterIndex;
			continue;
		}

		index = previousPreviousCharacterIndex * numberOfTypes + previousCharacterIndex;
		trigrams[index][currentCharacterIndex] += 1;
		totals[index] += 1;
		previousPreviousCharacterIndex = previousCharacterIndex;
		previousCharacterIndex = currentCharacterIndex;
	}

	for (int i = 0; i < numberOfTypes * numberOfTypes; i++) {
		for (int j = 0; j < numberOfTypes; j++) {
			if (totals[i] == 0) {
				trigrams[i][j] = 0;
			} else {
				trigrams[i][j] = int(trigrams[i][j] * 1000 / totals[i]);
			}
		}
		plaintextTrigrams(i, 0) = info.cryptocontext->MakePackedPlaintext(trigrams[i]);
	}

	inFile.close();

	std::cout << "trigrams:" << trigrams << std::endl;

	return plaintextTrigrams;
}