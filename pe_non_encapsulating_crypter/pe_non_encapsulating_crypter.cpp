//#include "pestructs.h" //Just to define the structs myself
#include <Windows.h>
#include <vector>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fstream>
//REDESIGN THIS
long unchangedPeSize;

char* openFile(const char* filename) { //fix memory leak
	FILE* file;
	errno_t err = fopen_s(&file, filename, "rb");

	if (err != 0) {
		printf("Failed to open file\n");
		return NULL;
	}

	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	unchangedPeSize = size;
	printf("%d", size);
	fseek(file, 0, SEEK_SET);

	char* buffer = (char*)malloc(size);
	if (buffer == NULL) {
		printf("Failed to allocate file buffer.\n");
		return NULL;
	}

	size_t result = fread(buffer, 1, size, file);
	if (result != size) {
		printf("Can't read PE\n");
		free(buffer);
		return NULL;
	}
	fclose(file);
	return buffer;
}

void writeFile(const char* filename, const char* data) {
	FILE* file;
	errno_t err = fopen_s(&file, filename, "wb");

	if (err != 0) {
		printf("Failed to open file\n");
		return;
	}

	//size_t len = strlen(data);
	size_t len = (size_t)unchangedPeSize;
	size_t result = fwrite(data, 1, len, file);

	if (result != len) {
		printf("Cannot write to file");
	}

	fclose(file);
}

int main() {

	char* pe_buffer = openFile("C:\\Users\\vboxuser\\Documents\\input.exe"); //try with vector
	if (pe_buffer == NULL) {
		return 1;
	}
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)pe_buffer;
	PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)(pe_buffer + dos_header->e_lfanew);
	//PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((PBYTE)nt_header + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_header);

	int numberOfCrypts;
	int mainProc;

	printf("How many functions do you want to crypt?\n> ");
	scanf_s("%d", &numberOfCrypts);


	int* arrayOfTargets = (int*)malloc(sizeof(int) * numberOfCrypts);

	if (arrayOfTargets == NULL) {
		printf("Lol I couldn't allocate the function number array");
	}

	printf("\nAssuming you know the orders of functions in the PE Image, enter the functions you want to crypt?");
	for (int desiredTarget = 0; desiredTarget < numberOfCrypts; desiredTarget++) {
		printf("Enter each function you want to crypt\n> ");//Find pointers bnased on ret instructions
		scanf_s("%d", (arrayOfTargets + desiredTarget));
	}//Find machine instructions for ret and split it depending on if the stuff between the count is in the array, man I wish this were python
	//Later, change the start point of the PE to the decrypt function and add a new section with the crypted code
	printf("Which function is main?\n> ");
	scanf_s("%d", &mainProc);


	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; section_header++) {
		if (strcmp((char*)section_header->Name, ".text") == 0) {
			BYTE* code = (BYTE*)pe_buffer + section_header->PointerToRawData;
			printf("[+] Uncrypted: %d\n", (int)*code);
			DWORD sizeOfCode = section_header->SizeOfRawData;

			/*		for (int target = 0; target < numberOfCrypts; target++) {
						*(arrayOfTargets + target);
					}*/

					//Take functions from the array and copy them to the new section, then replace the old functions with a call/jmp and crypt the new instructions and add decoder and re-encoder on call

			char* proc = strtok(code, "");

			for (DWORD j = 0; j < sizeOfCode; j++) {
				code[j] ^= 0xff;
			}
			printf("[+] Crypted: %d\n", (int)*code);
			break;
		}
	}



	//printf("%s",(char*)pe_buffer + section_header->PointerToRawData);
	writeFile("C:\\Users\\vboxuser\\Documents\\input.exe", pe_buffer);//It only writes MZ.

	free(arrayOfTargets);

	return 0;
}