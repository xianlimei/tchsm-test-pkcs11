#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>

#include "pkcs11.h"
#include "tools.h"
#include "main.h"

//PUNTERO A ESTRUCTURAS QUE TIENEN LAS FUNCIONES
CK_FUNCTION_LIST_PTR lib;
//PUNTERO A ESTRUCTURAS QUE TIENEN LAS FUNCIONES



CK_UTF8CHAR userPIN[] = {"123456"};
char ret[500];
CK_ULONG slotInvalid = 9999;
CK_ULONG numberOfSlots = 0;
CK_ULONG numberOfSlotsWithInitToken = 0;
CK_ULONG numberOfSlotsWithNotInitToken = 0;
CK_ULONG numberOfSlotsWithNoToken = 0;

CK_SLOT_ID_PTR slots;
CK_SLOT_ID_PTR slotsWithInitToken;
CK_SLOT_ID_PTR slotsWithNotInitToken;
CK_SLOT_ID_PTR slotsWithNoToken;
CK_UTF8CHAR_PTR * soPINs; 

int behavior;
int showMessage;
int repetitions;

void usage()
{
	printf("Bad Format\n");
	printf("FirstArgument: (one or more)option/s\n\t-f(FAIL) if an error happens the test stops\n\t-a(ASK) if an error happens the test asks for continuing\n\t-p(PASS) if an error happens the test continues\n\t-r(REPEAT) run stress tests\n\t-h(HIDE) hide the progress report\n");
	printf("Second Argument: [path to the dynamic cryptoki library]\n");
	printf("Third Argument: [n], positive number which indicates the HSM's number of slots\n");
	printf("Following 2n arguments: slotID-information tuples. Options:\n\t slotID NOTOKEN when the slot does not have a token inside\n\t slotID NOINIT when the slot has a token, but it is not initialized\n\t slotID [soPIN] when the slot has a token and its soPIN(Security Officer PIN) is given\n");
	printf("Eg: Using the SoftHSM cryptoki library in PASS mode, hiding the progress report, with 3 slots(0 does not have a token, 1 has a token and soPIN 12345678 and 2 has a token but it is not initialized)\n");
	printf("./testPKCS11 -ph /usr/lib/softhsm/libsofthsm.so 3 0 NOTOKEN 1 12345678 2 NOINIT\n");
}


//main, initialices ther variables, calls the tests and opens/closes the library
int main(int argc, char **argv)
{
	// For SoftHSM testing
	#ifdef WIN32
  	_putenv("SOFTHSM_CONF=./softhsm.conf");
	#else
	setenv("SOFTHSM_CONF", "./softhsm.conf", 1);
	#endif
	//For SoftHSM testing

	repetitions = 0;
	showMessage = 1;

	if (argc < 4)
	{
		usage();
		exit(1);
	}
	
	int x;
	for(x = 1; x < strlen(argv[1]); ++x)
	{
		
		switch(argv[1][x])
		{
			case 'f':
				behavior = FAIL;
			break;
			case 'a':
				behavior = ASK;
			break;
			case 'p':
				behavior = PASS;
			break;
			case 'r':
				repetitions = 3;
			break;
			case 'h':
				showMessage = 0;
			break;
			default :
				usage();				
				exit(1);
			break;
		}
	}
	
	numberOfSlots = atoi(argv[3]);
	if(numberOfSlots && ((4+2*numberOfSlots) == argc))
	{
		slots = (CK_SLOT_ID_PTR)malloc(numberOfSlots*sizeof(CK_SLOT_ID));
		slotsWithInitToken = (CK_SLOT_ID_PTR)malloc(numberOfSlots*sizeof(CK_SLOT_ID));
		slotsWithNotInitToken = (CK_SLOT_ID_PTR)malloc(numberOfSlots*sizeof(CK_SLOT_ID));
		slotsWithNoToken = (CK_SLOT_ID_PTR)malloc(numberOfSlots*sizeof(CK_SLOT_ID));
		soPINs = (CK_UTF8CHAR_PTR *)malloc(numberOfSlots*sizeof(CK_UTF8CHAR_PTR));

		for(x = 0; x < numberOfSlots; ++x)
		{
			CK_SLOT_ID slotID = atoi(argv[4+2*x]);
			if (slotID != 0 || strcmp(argv[4+2*x],"0") == 0)
			{
				slots[x] = slotID;
				if(strcmp(argv[5+2*x], "NOTOKEN") == 0)
				{
					slotsWithNoToken[numberOfSlotsWithNoToken] = slotID;
					++numberOfSlotsWithNoToken;
				}
				else if (strcmp(argv[5+2*x], "NOINIT") == 0)
				{
					slotsWithNotInitToken[numberOfSlotsWithNotInitToken] = slotID;
					++numberOfSlotsWithNotInitToken;
				}
				else
				{
					slotsWithInitToken[numberOfSlotsWithInitToken] = slotID;
					soPINs[numberOfSlotsWithInitToken] = argv[5+2*x];
					++numberOfSlotsWithInitToken;
				}
				
			}
			else
			{
				usage();
				exit(1);
			}
		}
	}
	else
	{
		usage();
		exit(1);
	}

	if (!initDynamicLibrary(argv[2]))
	{
		exit(1);
	}
	
	
	apiTest();
	
	if(!closeDynamicLibrary())
	{
		exit(1);
	}

	free(slots);	
	free(slotsWithInitToken);
	free(slotsWithNotInitToken);
	free(slotsWithNoToken);
	free(soPINs);
	return 1;
}

//Main test
void apiTest()
{
	int level = 0;
	printlnLevel(showMessage, "Start: Test Compliance PKCS#11(cryptoki)v2.20", level);
	testNoToken(level + 1, showMessage);
	testNoSessionHandle(level + 1, showMessage);
	testSessionHandleNeeded(level + 1, showMessage);
	printlnLevel(showMessage, "End: Test Compliance PKCS#11(cryptoki)v2.20", level);
}


//tests, they tests functions which do not need a token to work
//C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList, C_GetSlotList, C_GetSlotInfo
void testNoToken(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test of functions wich does not need a token", level);

	testInitializeFinalize(level + 1, showMessage);
	stressInitializeFinalize(level + 1, repetitions, showMessage);
	testGetFunctionList(level + 1, showMessage);
	stressGetFunctionList(level + 1, repetitions, showMessage);
	testGetInfo(level + 1, showMessage);
	stressGetInfo(level + 1, repetitions, showMessage);
	testGetSlotList(level + 1, showMessage);
	stressGetSlotList(level + 1, repetitions, showMessage);
	testGetSlotInfo(level + 1, showMessage);
	stressGetSlotInfo(level + 1, repetitions, showMessage);

	printlnLevel(showMessage, "End: test of functions wich does not need a token", level);	
}


void testInitializeFinalize(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_Initialize, C_Finalize", level);

	CK_RV rv;
	

	CK_C_INITIALIZE_ARGS args;
	
	args.CreateMutex = NULL_PTR;
    	args.DestroyMutex = NULL_PTR;
    	args.LockMutex = NULL_PTR;
    	args.UnlockMutex = NULL_PTR;
    	args.flags = 0;
    	args.pReserved = NULL_PTR;
	

	args.pReserved = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with pReserved != NULL_PTR"));
	
	args.pReserved = NULL_PTR;
	
	//Some but not all arguments != null(14 casos)
	args.CreateMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD,"Call to C_Initialize with CreateMutex != NULL_PTR"));
	
	args.CreateMutex = NULL_PTR;
	
	args.DestroyMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with DestroyMutex != NULL_PTR"));

	args.DestroyMutex = NULL_PTR;

	args.LockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with LockMutex != NULL_PTR"));
	
	args.LockMutex = NULL_PTR;

	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with UnlockMutex != NULL_PTR"));
		
	args.UnlockMutex = NULL_PTR;
	
	args.CreateMutex = (void *)1;
	args.DestroyMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with CreateMutex, DestroyMutex != NULL_PTR"));

	args.CreateMutex = NULL_PTR;
	args.DestroyMutex = NULL_PTR;

	args.CreateMutex = (void *)1;
	args.LockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with CreateMutex, LockMutex != NULL_PTR"));

	args.CreateMutex = NULL_PTR;
	args.LockMutex = NULL_PTR;

	
	args.CreateMutex = (void *)1;
	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with CreateMutex, UnlockMutex != NULL_PTR"));

	args.CreateMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;

	args.DestroyMutex = (void *)1;
	args.LockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with DestroyMutex, LockMutex != NULL_PTR"));

	args.DestroyMutex = NULL_PTR;
	args.LockMutex = NULL_PTR;

	args.DestroyMutex = (void *)1;
	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with, DestroyMutex, UnlockMutex != NULL_PTR"));

	args.DestroyMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;

	args.LockMutex = (void *)1;
	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with LockMutex, UnlockMutex != NULL_PTR"));

	args.LockMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;

	args.CreateMutex = (void *)1;
	args.DestroyMutex = (void *)1;
	args.LockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with CreateMutex, DestroyMutex, LockMutex != NULL_PTR"));
	
	args.CreateMutex = NULL_PTR;
	args.DestroyMutex = NULL_PTR;
	args.LockMutex = NULL_PTR;

	args.CreateMutex = (void *)1;
	args.DestroyMutex = (void *)1;
	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with CreateMutex, DestroyMutex, UnlockMutex != NULL_PTR"));
	
	args.CreateMutex = NULL_PTR;
	args.DestroyMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;
	
	args.CreateMutex = (void *)1;
	args.LockMutex = (void *)1;
	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with CreateMutex, LockMutex, UnlockMutex != NULL_PTR"));
	
	args.CreateMutex = NULL_PTR;
	args.LockMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;

	args.DestroyMutex = (void *)1;
	args.LockMutex = (void *)1;
	args.UnlockMutex = (void *)1;	
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Initialize with DestroyMutex, LockMutex, UnlockMutex != NULL_PTR"));
	
	args.DestroyMutex = NULL_PTR;
	args.LockMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;

	//End: Some but not all arguments != null(14 casos)

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_Finalize before calling C_Initialize successfully"));

	
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED, "Call to C_Initialize after calling C_Initialize"));	
	
	rv = C_Finalize((void *)1);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Finalize with argument != NULL_PTR"));

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_Finalize after calling C_Finalize"));

	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with Null arguments( equivalent to call with NULL_PTR)"));

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));

	printlnLevel(showMessage, "End: test C_Initialize, C_Finalize", level);
}

void stressInitializeFinalize(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_Initialize C_Finalize", level);
		CK_RV rv;	
		int i;	
		for (i = 0; i < repetitions; ++i)
		{
			testInitializeFinalize(level + 1, 0);
		}
	
		printlnLevel(showMessage, "End: stress C_Initialize C_Finalize", level);
	}
}


void testGetFunctionList(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_GetFunctionList", level);
	CK_RV rv;
	
	rv = C_GetFunctionList(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GetFunctionList with NULL_PTR"));
	
	CK_FUNCTION_LIST_PTR pfunctionList;
	
	rv = C_GetFunctionList(&pfunctionList);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetFunctionList before calling C_Initialize"));

	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));
	
	rv = C_GetFunctionList(&pfunctionList);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetFunctionList between a C_Initialize and a C_Finalize call"));

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));

	rv = C_GetFunctionList(&pfunctionList);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetFunctionList after calling C_Finalize"));
	char * functionName;
	if ((functionName = checkCkFunctionList(pfunctionList)) != NULL_PTR)
	{
		sprintf(ret, "Result of calling C_GetFunctionList, has a NULL_PTR for %s, but should be a function which always returns CKR_FUNCTION_NOT_SUPPORTED", functionName);
		free(functionName);
		assert2(behavior, message(0, ret));	
	}	
	printlnLevel(showMessage, "End: test C_GetFunctionList", level);
}


void stressGetFunctionList(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_GetFunctionList", level);
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testGetFunctionList(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_GetFunctionList", level);
	}
}

//Tests funcion C_GetInfo
void testGetInfo(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_GetInfo", level);
	CK_RV rv;
	CK_INFO info;
	
	rv = C_GetInfo(&info);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_GetInfo before calling C_Initialize"));
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));
	
	rv = C_GetInfo(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GetInfo with NULL_PTR"));
	
	rv = C_GetInfo(&info);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetInfo"));
		
	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	rv = C_GetInfo(&info);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_GetInfo after calling C_Finalize"));

	sprintf(ret, "Cryptoki version in C_GetInfo should be 2.20, but it is %d.%d", (int)info.cryptokiVersion.major, (int)info.cryptokiVersion.minor);
	assert2(behavior, message(info.cryptokiVersion.major == 2 && info.cryptokiVersion.minor == 20, ret));
	
	sprintf(ret, "flags in C_GetInfo should be 0, but it is %d", (int)info.flags);
	assert2(behavior, message(info.flags == 0, ret));
	
	
	assert2(behavior, message(isBlankPadded(info.manufacturerID, 32), "manufacturerID in C_GetInfo should be blank padded"));
	assert2(behavior, message(isBlankPadded(info.libraryDescription, 32), "libraryDescription in C_GetInfo should be blank padded"));
	
	printlnLevel(showMessage, "End: test C_GetInfo", level);
}

//Test de stress de GetInfo
void stressGetInfo(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_GetInfo", level);
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testGetInfo(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_GetInfo", level);
	}
}

//Tests de funcion C_GetSlotList
void testGetSlotList(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_GetSlotList", level);
	CK_RV rv;
	CK_SLOT_ID_PTR buffer;	
	CK_ULONG size;
	int i;
	
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_GetSlotList before calling C_Initialize"));
	

	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));
	
	rv = C_GetSlotList(CK_TRUE, buffer, NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GetSlotList with third argument NULL_PTR"));

	rv = C_GetSlotList(CK_TRUE, NULL_PTR, NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GetSlotList with second, third argument NULL_PTR"));

	//CK_FALSE
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList to get number of slots"));
	
	sprintf(ret, "Number of slots of C_GetSlotList(%d) is different from specified(%d)", (int)size, (int)numberOfSlots);	
	assert2(behavior, message(size == numberOfSlots, ret));
	
	for(i = -1; i < size; ++i)
	{
		size = i;
		rv = C_GetSlotList(CK_FALSE, buffer, &size);
		sprintf(ret, "Call to C_GetSlotList with ulCount = %d less than number of slots(%d)", i, (int)numberOfSlots);
		assert2(behavior, verifyCode(rv, CKR_BUFFER_TOO_SMALL, ret));	
		
		sprintf(ret, "Number of slots of C_GetSlotList(%d) is different from specified(%d)", (int)size, (int)numberOfSlots);	
		assert2(behavior, message(size == numberOfSlots, ret));

	}
	buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_FALSE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	

	sprintf(ret, "Number of slots of C_GetSlotList(%d) is different from specified(%d)", (int)size, (int)numberOfSlots);
	assert2(behavior, message(size == numberOfSlots, ret));
	
	int slotsR [size];
	for (i = 0; i < size; ++i)
	{
		slotsR[i] = buffer[i];
	}
	

	for(i = 0; i < numberOfSlots; ++i)
	{
		CK_SLOT_ID slotID = slotsR[i];
		sprintf(ret, "C_GetSlotList(CK_FALSE) does not have the slot(%d)", (int)slotID);
		assert2(behavior, message(contains(slotsR, (int)size, (int)slotID), ret));
	}
	free(buffer);
	


	//CK_TRUE
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList to get the number of slots with token"));
	
	sprintf(ret, "Number of slots with token of C_GetSlotList(%d) is different from specified(%d)", (int)size, (int)numberOfSlotsWithInitToken + (int)numberOfSlotsWithNotInitToken);
	assert2(behavior, message(size == (int)numberOfSlotsWithInitToken + (int)numberOfSlotsWithNotInitToken, ret));
	
	for(i = -1; i < size; ++i)
	{
		size = i;
		rv = C_GetSlotList(CK_TRUE, buffer, &size);
		sprintf(ret, "Call to C_GetSlotList with ulCount = %d less than number of slots with token(%d)", i, (int)numberOfSlotsWithInitToken+(int)numberOfSlotsWithNotInitToken);
		assert2(behavior, verifyCode(rv, CKR_BUFFER_TOO_SMALL, ret));	
		
		sprintf(ret, "Number of slots with token of C_GetSlotList(%d) is different from specified(%d)", (int)size, (int)numberOfSlotsWithInitToken+(int)numberOfSlotsWithNotInitToken);
		assert2(behavior, message(size == (int)numberOfSlotsWithInitToken+(int)numberOfSlotsWithNotInitToken, ret));

	}
	buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
		
	
	sprintf(ret, "Number of slots with token entregado por C_GetSlotList(%d) is different from specified(%d)", (int)size, (int)numberOfSlotsWithInitToken+(int)numberOfSlotsWithNotInitToken);
	assert2(behavior, message(size == (int)numberOfSlotsWithInitToken+(int)numberOfSlotsWithNotInitToken, ret));

	int slotsToken [size];
	for (i = 0; i < size; ++i)
	{
		slotsToken[i] = buffer[i];
	}

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		CK_SLOT_ID slotID = slotsWithInitToken[i];
		sprintf(ret, "C_GetSlotList(CK_TRUE) does not have a slot(%d) from specified", (int)slotID);
		assert2(behavior, message(contains(slotsToken, (int)size, (int)slotID), ret));
	}
	
	for (i = 0; i < numberOfSlotsWithNotInitToken; ++i)
	{
		CK_SLOT_ID slotID = slotsWithNotInitToken[i];
		sprintf(ret, "C_GetSlotList(CK_TRUE) does not have a slot(%d) from specified", (int)slotID);
		assert2(behavior, message(contains(slotsToken, (int)size, (int)slotID), ret));
	}
	free(buffer);
	
	
	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_GetSlotList after calling C_Finalize"));

	printlnLevel(showMessage, "End: test C_GetSlotList", level);
}

//Test de stress de C_GetSlotList
void stressGetSlotList(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_GetSlotList", level);
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testGetSlotList(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_GetSlotList", level);
	}
}

//tests para la funcion C_GetSlotInfo
void testGetSlotInfo(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_GetSlotInfo", level);
	CK_RV rv;
	CK_SLOT_INFO info;
	int i;

	CK_SLOT_ID_PTR buffer;	
	CK_ULONG size;

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetSlotInfo(slotsWithInitToken[i], &info);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_GetSlotInfo before calling C_Initialize"));
	}

	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetSlotInfo(slotsWithInitToken[i], NULL_PTR);
		assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GetSlotInfo with second argument NULL_PTR"));
	}

	rv = C_GetSlotInfo(slotInvalid, &info);
	sprintf(ret, "Call to C_GetSlotInfo with invalid slotID(%d)", (int)slotInvalid);
	assert2(behavior, verifyCode(rv, CKR_SLOT_ID_INVALID, ret));
	
	
	//CK_FALSE, comprobaciones generales
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_FALSE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));

	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];	
		rv = C_GetSlotInfo(slot, &info);
		sprintf(ret, "Call to C_GetSlotInfo with slotID(%d) gotten from C_GetSlotList(CK_FALSE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		
		sprintf(ret, "slotDescription in C_GetSlotInfo(slot %d) should be blank padded", (int)slot);
		assert2(behavior, message(isBlankPadded(info.slotDescription, 64), ret));
		sprintf(ret, "manufacturerID in C_GetSlotInfo(slot %d) should be blank padded", (int)slot);
		assert2(behavior, message(isBlankPadded(info.manufacturerID, 32), ret));
		
		//COMPROBACION FALLO CKF_REMOVABLE_DEVICE isntSet => CKF_TOKEN_PRESENT isSet
		sprintf(ret, "flags of C_GetSlotInfo in slotID(%d) does not follow the rule:  CKF_REMOVABLE_DEVICE is not, then CKF_TOKEN_PRESENT must be,", (int)slot);
		assert2(behavior, message((info.flags & CKF_TOKEN_PRESENT)|| (info.flags & CKF_REMOVABLE_DEVICE), ret));
		//COMPROBACION FALLO CKF_REMOVABLE_DEVICE isntSet => CKF_TOKEN_PRESENT isSet
	}
	free(buffer);

	//CK_TRUE, comprobacion de flag
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));

	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		rv = C_GetSlotInfo(slot, &info);
		sprintf(ret, "Call to C_GetSlotInfo with slotID(%d) of C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		assert2(behavior, message(info.flags & CKF_TOKEN_PRESENT, "flags of C_GetSlotInfo(slot with token) should have CKF_TOKEN_PRESENT"));	
	}
	free(buffer);
	

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetSlotInfo(slotsWithInitToken[i], &info);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_GetSlotInfo after calling C_Finalize"));	
	}

	printlnLevel(showMessage, "End: test C_GetSlotInfo", level);

}

//test de stress para la funcion C_GetSlotInfo
void stressGetSlotInfo(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_GetSlotInfo", level);
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testGetSlotInfo(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_GetSlotInfo", level);
	}
}



//TESTS de funciones que no necesitan un handle de session(excepto por C_CloseSession)
//, pero si un slot with token
//C_GetTokenInfo, C_InitToken, C_OpenSession, C_CloseAllSessions, C_CloseSession
void testNoSessionHandle(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test of functions which does not need a session handle to work", level);
	
	testGetTokenInfo(level + 1, showMessage);
	stressGetTokenInfo(level + 1, repetitions, showMessage);
	testInitToken(level + 1, showMessage);
        stressInitToken(level + 1, repetitions, showMessage);
	testOpenSession(level + 1, showMessage);
	stressOpenSession(level + 1, repetitions, showMessage);
	testCloseSession(level + 1, showMessage);
	stressCloseSession(level + 1, repetitions, showMessage);
	testCloseAllSessions(level + 1, showMessage);
	stressCloseAllSessions(level + 1, repetitions, showMessage);

	printlnLevel(showMessage, "End: test of functions which does not need a session handle to work", level);
}

///////
void testGetTokenInfo(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_GetTokenInfo", level);
	CK_RV rv;
	CK_TOKEN_INFO info;
	CK_ULONG size;
	CK_SLOT_ID_PTR buffer;
	int i;
	

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithInitToken[i], &info);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_GetTokenInfo before calling C_Initialize"));
	}
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithInitToken[i], NULL_PTR);
		assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GetTokenInfo with second argument NULL_PTR"));
	}

	rv = C_GetTokenInfo(slotInvalid, &info);
	sprintf(ret, "Call to C_GetTokenInfo with invalid slotID(%d)", (int)slotInvalid);
	assert2(behavior, verifyCode(rv, CKR_SLOT_ID_INVALID, ret));

	for (i = 0; i < numberOfSlotsWithNoToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithNoToken[i], &info);
		sprintf(ret, "Call to C_GetTokenInfo with valid ID(%d), but which does not have a token", (int)slotsWithNoToken[i]);
		assert2(behavior, verifyCode(rv, CKR_TOKEN_NOT_PRESENT, ret));
	}
	
	
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));

	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		rv = C_GetTokenInfo(slot, &info);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d) of C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		
		sprintf(ret, "label of C_GetTokenInfo in slot %d should be blank padded", (int)slot);
		assert2(behavior, message(isBlankPadded(info.label, 32), ret));
		sprintf(ret, "manufacturerID of C_GetTokenInfo in slot %d should be blank padded", (int)slot);
		assert2(behavior, message(isBlankPadded(info.manufacturerID, 32), ret));
		sprintf(ret, "model of C_GetTokenInfo in slot %d should be blank padded", (int)slot);
		assert2(behavior, message(isBlankPadded(info.model, 16), ret));
		sprintf(ret, "serialNumber of C_GetTokenInfo in slot %d should be blank padded", (int)slot);
		assert2(behavior, message(isBlankPadded(info.serialNumber, 15), ret));
		

		if (info.flags & CKF_CLOCK_ON_TOKEN)
		{
			assert2(behavior, message(info.utcTime[14]=='0' && info.utcTime[15]=='0', "C_GetTokenInfo has CKF_CLOCK_ON_TOKEN flag, but utcTime does not finish with '00'"));
		}
		
		assert2(behavior, message(!(info.flags & CKF_SECONDARY_AUTHENTICATION), "flags of C_GetTokenInfo should not have CKF_SECONDARY_AUTHENTICATION flag"));
		
		sprintf(ret, "C_GetTokenInfo has ulMinPinLen = %d > ulMaxPinLen = %d", (int)info.ulMinPinLen, (int)info.ulMaxPinLen);
		assert2(behavior, message(info.ulMinPinLen <= info.ulMaxPinLen, ret));
		
	}
	free(buffer);
	
	//COMPROBACION FLAG CKF_TOKEN_INITIALIZED
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithInitToken[i], &info);
		sprintf(ret, "Call to C_GetTokenInfo with slot with initialized token(%d)", (int)slotsWithInitToken[i]);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		   
		sprintf(ret, "flags of C_GetTokenInfo with slot with initialized token(%d) should have CKF_TOKEN_INITIALIZED flag", (int)slotsWithInitToken[i]);
		assert2(behavior, message(info.flags & CKF_TOKEN_INITIALIZED, ret));	
	}
	
	for (i = 0; i < numberOfSlotsWithNotInitToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithNotInitToken[i], &info);
		sprintf(ret, "Call to C_GetTokenInfo with slot with not intialized token(%d)", (int)slotsWithNotInitToken[i]);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		   
		sprintf(ret, "flags of C_GetTokenInfo with slot with not initialized token(%d) should not have CKF_TOKEN_INITIALIZED flag", (int)slotsWithNotInitToken[i]);
		assert2(behavior, message(!(info.flags & CKF_TOKEN_INITIALIZED), ret));
	}
	//COMPROBACION FLAG CKF_TOKEN_INITIALIZED
	

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithInitToken[i], &info);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_GetTokenInfo after calling C_Finalize"));
	}
	
	printlnLevel(showMessage, "End: test C_GetTokenInfo", level);
}

//////
void stressGetTokenInfo(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_GetTokenInfo", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testGetTokenInfo(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_GetTokenInfo", level);
	}
}


//
void testInitToken(int level, int showMessage)
{
        printlnLevel(showMessage, "Start: test C_InitToken", level);
        
        char * textLabel = "A token";
        CK_UTF8CHAR paddedLabel[32];
        memset(paddedLabel, ' ', sizeof(paddedLabel));
        memcpy(paddedLabel, textLabel, strlen(textLabel));

	CK_RV rv;
	int i;
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_InitToken(slotsWithInitToken[i], soPINs[i], strlen(soPINs[i]), paddedLabel);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_InitToken before calling C_Initialize"));
	}
		

 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));
        
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_InitToken(slotsWithInitToken[i], NULL_PTR, 0, paddedLabel);
		assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_InitToken with NULL_PTR second argument")); //We assume that there are not other authentication mechanism

		rv = C_InitToken(slotsWithInitToken[i], soPINs[i], strlen(soPINs[i]), NULL_PTR);
		assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_InitToken with NULL_PTR fourth argument"));
	}

	rv = C_InitToken(slotInvalid, "7654321", 7, paddedLabel);
	assert2(behavior, verifyCode(rv, CKR_SLOT_ID_INVALID, "Call to C_InitToken with an invalid slot"));
	
        CK_ULONG size;
	CK_SLOT_INFO info;	
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_FALSE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		rv = C_GetSlotInfo(slot, &info);
		sprintf(ret, "Call to C_GetSlotInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		
		if (!(info.flags & CKF_TOKEN_PRESENT))
		{
			rv = C_InitToken(slot, "7654321", 7, paddedLabel);	
			sprintf(ret, "Call to C_InitToken with slotID(%d), which does not have token", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_TOKEN_NOT_PRESENT, ret));
			
		}
		else
		{
			CK_TOKEN_INFO infoToken;
			rv = C_GetTokenInfo(slot, &infoToken);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetTokenInfo with CKF_TOKEN_PRESENT flag"));
			if (infoToken.flags & CKF_TOKEN_INITIALIZED)//REINIT
			{
				
				if (!(infoToken.flags & CKF_WRITE_PROTECTED))
				{
					sprintf(ret, "Call to C_InitToken with slotID(%d), with CKF_TOKEN_PRESENT flag", (int)slot);
					int ind = indexOfElem((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
					rv = C_InitToken(slot, soPINs[ind], strlen(soPINs[ind]), paddedLabel);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));
				}
			
			}
		}
	}
	free(buffer);

	//For every token-soPIN pair initialized
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		CK_UTF8CHAR badSoPIN[strlen(soPINs[i])];
		strcpy(badSoPIN, soPINs[i]);
		badSoPIN[0] = badSoPIN[0]+ 1;
		sprintf(ret, "Call to C_InitToken with slotID %d, and incorrect soPIN", (int)slotsWithInitToken[i]); 
		rv = C_InitToken(slotsWithInitToken[i], badSoPIN, strlen(badSoPIN), paddedLabel);
		assert2(behavior, verifyCode(rv, CKR_PIN_INCORRECT, ret));
	

	
		rv = C_GetSlotInfo(slotsWithInitToken[i], &info);
		sprintf(ret, "Call to C_GetSlotInfo with slotID(%d)", (int)slotsWithInitToken[i]);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
	}

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_InitToken(slotsWithInitToken[i], soPINs[i], strlen(soPINs[i]), paddedLabel);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_InitToken after calling C_Finalize"));	
	}

	printlnLevel(showMessage, "End: test C_InitToken", level);
}

/////////
void stressInitToken(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_InitToken", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testInitToken(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_InitToken", level);
	}
}

/////
void testOpenSession(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_OpenSession", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	int i;
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_OpenSession(slotsWithInitToken[i], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
	    	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_OpenSession before calling C_Initialize"));
	}

 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_OpenSession(slotsWithInitToken[i], 0, NULL_PTR, NULL_PTR, &hSession[0]);
		assert2(behavior, verifyCode(rv, CKR_SESSION_PARALLEL_NOT_SUPPORTED, "Call to C_OpenSession without CKF_SERIAL_SESSION flag"));

		rv = C_OpenSession(slotsWithInitToken[i], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, NULL_PTR);
		assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_OpenSession with fifth argument NULL_PTR"));
	}
	
	rv = C_OpenSession(slotInvalid, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
	assert2(behavior, verifyCode(rv, CKR_SLOT_ID_INVALID, "Call to C_OpenSession with invalid slotID"));


	CK_ULONG size;
	CK_SLOT_INFO info;	
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_FALSE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		rv = C_GetSlotInfo(slot, &info);
		sprintf(ret, "Call to C_GetSlotInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		if (!(info.flags & CKF_TOKEN_PRESENT))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) and without CKF_TOKEN_PRESENT flag", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_TOKEN_NOT_PRESENT, ret));
		}
		else
		{
			CK_TOKEN_INFO infoToken;
			rv = C_GetTokenInfo(slot, &infoToken);
			sprintf(ret, "Call to C_GetTokenInfo with CKF_TOKEN_PRESENT flag");
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			if (!(infoToken.flags & CKF_TOKEN_INITIALIZED))
			{
				rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
				sprintf(ret, "Call to C_OpenSession with slotID(%d) and CKF_TOKEN_PRESENT but without CKF_TOKEN_INITIALIZED flag", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_TOKEN_NOT_RECOGNIZED, ret));
			}
			else
			{
				if(!(infoToken.flags & CKF_WRITE_PROTECTED))
				{
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
					sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
					sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
					char * textLabel = "A token";
        				CK_UTF8CHAR paddedLabel[32];
        				memset(paddedLabel, ' ', sizeof(paddedLabel));
				        memcpy(paddedLabel, textLabel, strlen(textLabel));
					int ind = indexOfElem((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
					rv = C_InitToken(slot, soPINs[ind], strlen(soPINs[ind]), paddedLabel);
					sprintf(ret, "Call to C_InitToken with slotID(%d) where there is a open session", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_SESSION_EXISTS, ret));
					
				}
			}
		}
	}
	free(buffer);

	

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_OpenSession(slotsWithInitToken[i], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_OpenSession after calling C_Finalize"));	
	}

	printlnLevel(showMessage, "End: test C_OpenSession", level);
}

///////
void stressOpenSession(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_OpenSession", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testOpenSession(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_OpenSession", level);
	}
}


////
void testCloseSession(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_CloseSession", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];

	rv = C_CloseSession(hSession[0]);
    	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_CloseSession before calling C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_CloseSession(CK_INVALID_HANDLE);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Call to C_CloseSession with an invalid handle"));	


	CK_ULONG size;
	unsigned int i;
	CK_SLOT_INFO info;	
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		if (infoToken.flags & CKF_TOKEN_INITIALIZED)
		{
			if (!(infoToken.flags & CKF_WRITE_PROTECTED))
			{	
				rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
				sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
				rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
				sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				rv = C_CloseSession(hSession[0]);
				sprintf(ret, "Call to C_CloseSession with slotID(%d) of C_GetSlotList(CK_TRUE) y with flag CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, after opening this session(R/O)", (int)slot );
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				rv = C_CloseSession(hSession[0]);
				sprintf(ret, "Call to C_CloseSession with slotID(%d) after closing this session (R/O)", (int)slot );
				assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, ret));

				rv = C_CloseSession(hSession[1]);
				sprintf(ret, "Call to C_CloseSession with slotID(%d) after opening this session(R/W)", (int)slot );
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				rv = C_CloseSession(hSession[1]);
				sprintf(ret, "Call to C_CloseSession with slotID(%d) after closing this session (R/W)", (int)slot );
				assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, ret));

				
				
				
				
				//CHECK TOKEN/SESSION FIELDS
				rv = C_GetTokenInfo(slot, &infoToken);
				sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);

				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				int maximoOS;//OpenSessionss
				maximoOS = infoToken.ulMaxSessionCount == CK_UNAVAILABLE_INFORMATION ? 1 :
	 (infoToken.ulMaxSessionCount == CK_EFFECTIVELY_INFINITE)? 10 : infoToken.ulMaxSessionCount ;	
				
				if (infoToken.ulSessionCount != CK_UNAVAILABLE_INFORMATION)
				{
					sprintf(ret, "Token with slotID(%d), without open sessions should have ulSessionCount 0, but has %d", (int)slot, (int)infoToken.ulSessionCount);
					assert2(behavior, message(infoToken.ulSessionCount == 0, ret));		
				}

				CK_SESSION_HANDLE hTestSession[maximoOS];
					
				int j;
				for(j = 0; j < maximoOS; ++j)
				{
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hTestSession[j]);
					sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token with slotID(%d), with %d open sessions should have this in ulSessionCount, but has %d", (int)slot, (j+1), (int)infoToken.ulSessionCount);
						assert2(behavior, message(infoToken.ulSessionCount == (j+1), ret));	
					}
				}
				
				if (infoToken.ulMaxSessionCount != CK_UNAVAILABLE_INFORMATION && infoToken.ulMaxSessionCount != CK_EFFECTIVELY_INFINITE)
				{
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hTestSession[j]);
					sprintf(ret, "Call to C_OpenSession with slotID(%d) which has initialized a number of session equals to the maximium(%d)", (int)slot, (int)infoToken.ulMaxSessionCount);
					assert2(behavior, verifyCode(rv, CKR_SESSION_COUNT, ret));
				}

				//Closing the sessions
				for(j = maximoOS - 1; j >= 0; j--)
				{
					rv = C_CloseSession(hTestSession[j]);
					sprintf(ret, "Call to C_CloseSession with slotID(%d), with open session", (int)slot);
					
					assert2(behavior, verifyCode(rv, CKR_OK ,ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Call to C_GetTokenInfo with slotID(%d) of C_GetSlotList(CK_TRUE)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token with slotID(%d), with %d open session should have this in ulSessionCount , but has %d", (int)slot, (j), (int)infoToken.ulSessionCount);
						assert2(behavior, message(infoToken.ulSessionCount == j, ret));	
					}
					
				}
	
				//Now with R/W
				rv = C_GetTokenInfo(slot, &infoToken);
				sprintf(ret, "Call to C_GetTokenInfo with slotID(%d) of C_GetSlotList(CK_TRUE)", (int)slot);

				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				int maximoRW;
				maximoRW = infoToken.ulMaxRwSessionCount == CK_UNAVAILABLE_INFORMATION ? 1 :
	 (infoToken.ulMaxRwSessionCount == CK_EFFECTIVELY_INFINITE)? 10 : infoToken.ulMaxRwSessionCount ;	
				
				if (infoToken.ulRwSessionCount != CK_UNAVAILABLE_INFORMATION)
				{
					sprintf(ret, "Token with slotID(%d), without open r/w session should have ulRwSessionCount 0, but has %d", (int)slot, (int)infoToken.ulRwSessionCount);
					assert2(behavior, message(infoToken.ulRwSessionCount == 0, ret));		
				}

				CK_SESSION_HANDLE hTestSessionRW[maximoRW];
					
				for(j = 0; j < maximoRW; ++j)
				{
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hTestSessionRW[j]);
					sprintf(ret, "Call to C_OpenSession with slotID(%d), trying to open a R/W session", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulRwSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token with slotID(%d), with %d open R/W sessions should have this in ulRwSessionCount , but has %d", (int)slot, (j+1), (int)infoToken.ulRwSessionCount);
						assert2(behavior, message(infoToken.ulRwSessionCount == (j+1), ret));	
					}
				}

				if (infoToken.ulMaxRwSessionCount != CK_UNAVAILABLE_INFORMATION && infoToken.ulMaxRwSessionCount != CK_EFFECTIVELY_INFINITE)
				{
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hTestSessionRW[j]);
					sprintf(ret, "Call to C_OpenSession with slotID(%d) which has initialized a number of R/W session equals to the maximium", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_SESSION_COUNT, ret));
				}

				//Closing the sessions
				for(j = maximoRW - 1; j >= 0; j--)
				{
					rv = C_CloseSession(hTestSessionRW[j]);
					sprintf(ret, "Call to C_CloseSession with slotID(%d), with an open r/W session", (int)slot);
					
					assert2(behavior, verifyCode(rv, CKR_OK ,ret));
//
					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulRwSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token with slotID(%d), with %d open R/W sessions should have this in  ulRwSessionCount, but has %d", (int)slot, (j), (int)infoToken.ulSessionCount);
						assert2(behavior, message(infoToken.ulRwSessionCount == j, ret));	
					}
					
				}
			}
		}
	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	rv = C_CloseSession(hSession[0]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_CloseSession after calling C_Finalize"));	
	
	printlnLevel(showMessage, "End: test C_CloseSession", level);
}

////
void stressCloseSession(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_CloseSession", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testCloseSession(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_CloseSession", level);
	}
}

////
void testCloseAllSessions(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_CloseAllSessions", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	int i;
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_CloseAllSessions(slotsWithInitToken[i]);
	    	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_CloseAllSessions before calling C_Initialize"));
	}

 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	
	rv = C_CloseAllSessions(slotInvalid);
	assert2(behavior, verifyCode(rv, CKR_SLOT_ID_INVALID, "Call to C_CloseAllSessions with an invalid slotID"));	

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_CloseAllSessions(slotsWithInitToken[i]);
		assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CloseAllSessions without open sessions"));
	}



	CK_ULONG size;
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_FALSE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_SLOT_INFO info;
		rv = C_GetSlotInfo(slot, &info);
		sprintf(ret, "Call to C_GetSlotInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		if (!(info.flags & CKF_TOKEN_PRESENT))
		{
			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Call to C_CloseAllSessions with slotID(%d) without CKF_TOKEN_PRESENT flag", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_TOKEN_NOT_PRESENT, ret));
		}

		else
		{

			CK_TOKEN_INFO infoToken;
			rv = C_GetTokenInfo(slot, &infoToken);
			sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			if (!(infoToken.flags & CKF_TOKEN_INITIALIZED))
			{
				rv = C_CloseAllSessions(slot);
				sprintf(ret, "Call to C_CloseAllSessions with slotID(%d) without CKF_TOKEN_INITIALIZED flag", (int)slot);
				assert2(behavior, verifyCode2(rv, CKR_TOKEN_NOT_PRESENT, CKR_OK, ret));//There is not good return code
			}
			else
			{
				if (!(infoToken.flags & CKF_WRITE_PROTECTED))
				{	
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
					sprintf(ret, "Call to C_OpenSession with slotID(%d)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
					sprintf(ret, "Call to C_OpenSession with slotID(%d)trying to open a r/w session", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token with slotID(%d), with 2 open sessions should have ulSessionCount 2, but has %d", (int)slot, (int)infoToken.ulSessionCount);
						assert2(behavior, message(infoToken.ulSessionCount == 2, ret));		
					}
					if (infoToken.ulRwSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token with slotID(%d), with 2 open sessions(1 R/W) should have ulRwSessionCount 1, but has %d", (int)slot, (int)infoToken.ulRwSessionCount);
						assert2(behavior, message(infoToken.ulRwSessionCount == 1, ret));		
					}
					
					//Closing sessions
					rv = C_CloseAllSessions(slot);
					sprintf(ret, "Call to C_CloseAllSessions with slotID(%d)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK ,ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token with slotID(%d), after calling C_CloseAllSessions should have ulSessionCount 0, but has %d", (int)slot, (int)infoToken.ulSessionCount);
						assert2(behavior, message(infoToken.ulSessionCount == 0, ret));	
					}
					if (infoToken.ulRwSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token with slotID(%d), after calling C_CloseAllSessions should have ulRwSessionCount  0, but has %d", (int)slot, (int)infoToken.ulRwSessionCount);
						assert2(behavior, message(infoToken.ulRwSessionCount == 0, ret));	
					}
					
				}
			}
		}
	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_CloseAllSessions(slotsWithInitToken[i]);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Call to C_CloseAllSessions after calling C_Finalize"));	
	}
	
	printlnLevel(showMessage, "End: test C_CloseAllSessions", level);
}



////
void stressCloseAllSessions(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_CloseAllSessions", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testCloseAllSessions(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_CloseAllSessions", level);
	}

}


//Test of functions which needs a session handle
void testSessionHandleNeeded(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test of functions which needs a session handle", level);
	
	testSessionHandleManagement(level + 1, showMessage);
	testObjectManagementFunctions(level + 1, showMessage);
	testMechanisms(level + 1, showMessage);
	testRNGFunctions(level + 1, showMessage);
	printlnLevel(showMessage, "End: test of functions which needs a session handle", level);
}


//Test of functions which needs a handle session to work, and are management functions
//C_GetSessionInfo, C_InitPIN, C_SetPIN, C_Login, C_Logout
void testSessionHandleManagement(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test of management functions", level);
	testGetSessionInfo(level + 1, showMessage);
	stressGetSessionInfo(level + 1, repetitions, showMessage);

	testInitPin(level + 1, showMessage);
	stressInitPin(level + 1, repetitions, showMessage);
	

	testLogin(level + 1, showMessage);
	stressLogin(level + 1, repetitions, showMessage);
	testLogout(level + 1, showMessage);
	stressLogout(level + 1, repetitions, showMessage);

	testSetPin(level + 1, showMessage);
	stressSetPin(level + 1, repetitions, showMessage);

	printlnLevel(showMessage, "End: test of management functions", level);
}

//////
void testGetSessionInfo(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_GetSessionInfo", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	CK_SESSION_INFO infoSession;
	

	rv = C_GetSessionInfo(hSession[0], &infoSession);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_GetSessionInfo before calling C_Initialize"));


 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));


	rv = C_GetSessionInfo(CK_INVALID_HANDLE, &infoSession);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Call to C_GetSessionInfo with invalid handle"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			//R/O			
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_GetSessionInfo(hSession[0], NULL_PTR);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GetSessionInfo with second argument NULL_PTR"));

			rv = C_GetSessionInfo(hSession[0], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with a R/O session handle"));


			sprintf(ret, "Result of C_GetSessionInfo says that slot is %d, but it is %d", (int)infoSession.slotID, (int)slot);
			assert2(behavior, message(infoSession.slotID == slot, ret));			
			
			assert2(behavior, message(infoSession.flags & CKF_SERIAL_SESSION, "Result of C_GetSessionInfo of a R/O session should have CKF_SERIAL_SESSION flag"));	

			assert2(behavior, message(!(infoSession.flags & CKF_RW_SESSION), "Result of C_GetSessionInfo of a R/W session, should not have CKF_RW_SESSION flag"));		
			
			//R/W		
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_GetSessionInfo(hSession[1], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with a R/W session handle"));


			sprintf(ret, "Result of C_GetSessionInfo says that slot is %d, but it is %d", (int)infoSession.slotID, (int)slot);
			assert2(behavior, message(infoSession.slotID == slot, ret));			
			
			assert2(behavior, message(infoSession.flags & CKF_SERIAL_SESSION, "Result of C_GetSessionInfo of a R/W session should have CKF_SERIAL_SESSION flag"));
			
			assert2(behavior, message(infoSession.flags & CKF_RW_SESSION, "Result of C_GetSessionInfo of a R/W session should have CKF_RW_SESSION flag"));			


			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Call to C_CloseAllSessions with slotID(%d)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
		}
	}
	free(buffer);

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	rv = C_GetSessionInfo(hSession[0], &infoSession);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_GetSessionInfo after calling C_Finalize"));	

	printlnLevel(showMessage, "End: test C_GetSessionInfo", level);
}

////
void stressGetSessionInfo(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_GetSessionInfo", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testGetSessionInfo(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_GetSessionInfo", level);
	}
}
//
////USARE C_Login sin testear
void testInitPin(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_InitPIN", level);
	
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	rv = C_InitPIN(hSession, userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_InitPIN before calling C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));
	
	rv = C_InitPIN(CK_INVALID_HANDLE, userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Call to C_InitPIN with invalid session handle"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			int ind = indexOfElem((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
			rv = C_Login(hSession, CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Call to C_Login with a R/W open session in slot(%d)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_InitPIN(hSession, NULL_PTR, 0);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_InitPIN with R/W SO state, and second argument NULL_PTR"));
	
			
			CK_UTF8CHAR_PTR longPIN = (CK_UTF8CHAR_PTR)malloc((infoToken.ulMaxPinLen + 2)*sizeof(CK_UTF8CHAR));
			int j;
			for(j = 0; j < infoToken.ulMaxPinLen + 1; ++j)
			{
				*(longPIN + j*sizeof(CK_UTF8CHAR)) = (CK_UTF8CHAR)'1';
			}
			*(longPIN + j*sizeof(CK_UTF8CHAR)) = 0;
			rv = C_InitPIN(hSession, longPIN, infoToken.ulMaxPinLen + 1);
			assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, "Call to C_InitPIN  in R/W SO state, with a userPIN which has 1 more char than specified in ulMaxPinLen(C_GetTokenInfo)"));
			free(longPIN);

			if (infoToken.ulMinPinLen > 0)
			{
				CK_UTF8CHAR shortPIN [] = {""};
				rv = C_InitPIN(hSession, shortPIN, 0);
				assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, "Call to C_InitPIN  in R/W SO state, with a userPIN of 0 chars(\"\")"));
			}

			rv = C_InitPIN(hSession, userPIN, strlen(userPIN));
			sprintf(ret, "Call to C_InitPIN  in R/W SO state, second argument %s y third argument %d", (char *)userPIN, (int)strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_GetTokenInfo(slot, &infoToken);
			sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			assert2(behavior, message(infoToken.flags & CKF_USER_PIN_INITIALIZED, "Result of C_GetTokenInfo after calling C_InitPIN should have CKF_USER_PIN_INITIALIZED flag"));

			
		}
	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	rv = C_InitPIN(hSession, userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_InitPIN after calling C_Finalize"));	

	printlnLevel(showMessage, "End: test C_InitPIN", level);
}



///
void stressInitPin(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_InitPIN", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testInitPin(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_InitPIN", level);
	}

}


///
void testLogin(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_Login", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	CK_SESSION_INFO infoSession;
	
	rv = C_Login(hSession[0], CKU_USER, userPIN, strlen(userPIN)); //The PIN was initialized
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_Login before calling C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_Login(CK_INVALID_HANDLE, CKU_USER, userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Call to C_Login with invalid session handle"));	

	
	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with R/W session handle"));
			
			char sState[100];
			getStateName(infoSession.state, sState);
			sprintf(ret, "state of C_GetSessionInfo should have CKS_RW_PUBLIC_SESSION, but has %s", sState);
			assert2(behavior, message(infoSession.state == CKS_RW_PUBLIC_SESSION, ret));
			//SESSIONINFOVERIFY
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN
			rv = C_InitPIN(hSession[1], userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_InitPIN with session in RW-public state"));	
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN

			rv = C_Login(hSession[1], CKU_USER, NULL_PTR, 0);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Login with third argumento NULL_PTR"));
			
			rv = C_Login(hSession[1], 3, userPIN, strlen(userPIN));//3 is an invalid user type
			assert2(behavior, verifyCode(rv, CKR_USER_TYPE_INVALID, "Call to C_Login with an invalid user type(3)"));

			CK_UTF8CHAR badPIN[] = {"123455"};
			rv = C_Login(hSession[1], CKU_USER, badPIN, strlen(badPIN));
			assert2(behavior, verifyCode(rv, CKR_PIN_INCORRECT, "Call to C_Login with an incorrect PIN"));
			
			rv = C_Login(hSession[1], CKU_CONTEXT_SPECIFIC, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv ,CKR_OPERATION_NOT_INITIALIZED, "Call to C_Login with user type CKU_CONTEXT_SPECIFIC and without an operation"));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[0], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with an R/O session handle"));
			
			getStateName(infoSession.state, sState);
			sprintf(ret, "state of C_GetSessionInfo should have CKS_RO_PUBLIC_SESSION, but has %s", sState);
			assert2(behavior, message(infoSession.state == CKS_RO_PUBLIC_SESSION, ret));
			//SESSIONINFOVERIFY
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN
			rv = C_InitPIN(hSession[0], userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_InitPIN with R/O-public state"));	
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN			

			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));
			
			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with R/W session handle"));
			
			getStateName(infoSession.state, sState);
			sprintf(ret, "state of C_GetSessionInfo should have CKS_RW_USER_FUNCTIONS, but has %s", sState);
			assert2(behavior, message(infoSession.state == CKS_RW_USER_FUNCTIONS, ret));
			//SESSIONINFOVERIFY
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN
			rv = C_InitPIN(hSession[1], userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_InitPIN with RW-user state"));	
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN


			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[0], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with a R/O session handle"));
			
			getStateName(infoSession.state, sState);
			sprintf(ret, "state of C_GetSessionInfo should have CKS_RO_USER_FUNCTIONS, but has %s", sState);
			assert2(behavior, message(infoSession.state == CKS_RO_USER_FUNCTIONS, ret));
			//SESSIONINFOVERIFY
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN
			rv = C_InitPIN(hSession[0], userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_InitPIN with RO-user state"));	
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN			
			
			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Call to C_CloseAllSessions with slotID(%d)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
			

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			//after clossing all session the new state is public
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with R/W session handle"));
			
			getStateName(infoSession.state, sState);
			sprintf(ret, "state of C_GetSessionInfo should have CKS_RW_PUBLIC_SESSION after closing all sessions and open a new one, but has %s", sState);;
			assert2(behavior, message(infoSession.state == CKS_RW_PUBLIC_SESSION, ret));

			//after clossing all session the new state is public(FIN)
			int ind = indexOfElem((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
			
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY_EXISTS, "Call to C_Login with CKU_SO user type and a R/W open session"));

			rv = C_CloseSession(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_OK ,"Call to C_CloseSession of an R/O session"));

			
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_SO user type"));
			
			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with R/W session handle"));
			
			getStateName(infoSession.state, sState);
			sprintf(ret, "state of C_GetSessionInfo should have CKS_RW_SO_FUNCTIONS, but has %s", sState);
			assert2(behavior, message(infoSession.state == CKS_RW_SO_FUNCTIONS, ret));
			//SESSIONINFOVERIFY

			
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) in SO state trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_WRITE_SO_EXISTS, ret));

			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_USER_ALREADY_LOGGED_IN, "Call to C_Login in SO state with CKU_SO user type"));
			
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_USER_ANOTHER_ALREADY_LOGGED_IN, "Call to C_Login in SO state with CKU_USER user type"));

		}
	}
	free(buffer);
	

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	rv = C_Login(hSession[0], CKU_USER, userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_Login after calling C_Finalize"));

	printlnLevel(showMessage, "End: test C_Login", level);

}


///
void stressLogin(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_Login", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testLogin(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_Login", level);
	}


}


///
void testLogout(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_Logout", level);
		
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	CK_SESSION_INFO infoSession;
	
	rv = C_Logout(hSession[0]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_Logout before calling C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_Logout(CK_INVALID_HANDLE);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Call to C_Logout with invalid session handle"));	

	
	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_Logout(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_Logout with a R/O-public state"));
					
			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_Logout with a R/W-public state"));			
			
			int ind = indexOfElem((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);

			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));
			
			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_Logout with a logged out session"));
			
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with a R/W session handle"));
			assert2(behavior, message(infoSession.state == CKS_RW_PUBLIC_SESSION, "state of C_GetSessionInfo(of a R/W session) should be CKS_RW_PUBLIC_SESSION, after logging out"));


			rv = C_GetSessionInfo(hSession[0], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with a R/O session handle"));
			assert2(behavior, message(infoSession.state == CKS_RO_PUBLIC_SESSION, "state of C_GetSessionInfo(of a R/O session) should be CKS_RO_PUBLIC_SESSION, after logging out"));

			
			rv = C_CloseSession(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_OK , "Call to C_CloseSession of a R/O session"));
						
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_SO user type"));

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));
			
			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSessionInfo with with a R/W session handle"));
			
			assert2(behavior, message(infoSession.state == CKS_RW_PUBLIC_SESSION, "state of C_GetSessionInfo(R/W session) should be CKS_RW_PUBLIC_SESSION, after logging out"));
			//SESSIONINFOVERIFY
		}

	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	rv = C_Logout(hSession[0]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_Logout after calling C_Finalize"));
	
	printlnLevel(showMessage, "End: test C_Logout", level);

}


///
void stressLogout(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_Logout", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testLogout(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_Logout", level);
	}
}


///
void testSetPin(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_SetPIN", level);
	
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	
	rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_SetPIN before calling C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_SetPIN(CK_INVALID_HANDLE, userPIN, strlen(userPIN), userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Call to C_SetPIN with invalid session handle"));	

	
	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			

			rv = C_SetPIN(hSession[0], userPIN, strlen(userPIN), userPIN, strlen(userPIN));			
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, "Call to C_SetPIN with R/O-public state"));	


			//FUNNY TESTS CK_RW_PUBLIC_SESSION
			rv = C_SetPIN(hSession[1], NULL_PTR, 0, userPIN, strlen(userPIN));			
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_SetPIN in R/W-public state with second argument NULL_PTR"));
				
			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), NULL_PTR, 0);			
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_SetPIN in R/W-public state with fourth argument NULL_PTR"));

			CK_UTF8CHAR_PTR longPIN = (CK_UTF8CHAR_PTR)malloc((infoToken.ulMaxPinLen + 2)*sizeof(CK_UTF8CHAR));
			int j;
			for(j = 0; j < infoToken.ulMaxPinLen + 1; ++j)
			{
				*(longPIN + j*sizeof(CK_UTF8CHAR)) = (CK_UTF8CHAR)'1';
			}
			*(longPIN + j*sizeof(CK_UTF8CHAR)) = 0;
			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), longPIN, infoToken.ulMaxPinLen + 1);
			assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, "Call to C_SetPIN in R/W-public, with a userPIN which has 1 more char than specified in ulMaxPinLen(C_GetTokenInfo)"));
			
			if (infoToken.ulMinPinLen > 0)
			{
				CK_UTF8CHAR shortPIN [] = {""};
				rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), shortPIN, 0);
				assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, "Call to C_SetPIN  in R/W-public state, with a userPIN of 0 chars(\"\")"));
			}
			
			CK_UTF8CHAR badPIN[] = {"123455"};
			rv = C_SetPIN(hSession[1], badPIN, strlen(badPIN),userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_PIN_INCORRECT, "Call to C_SetPIN in R/W-public with an incorrect oldPIN"));
			//_____
			

			CK_UTF8CHAR anotherPIN[] = {"123455"};
			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN),anotherPIN, strlen(anotherPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_SetPIN"));

			rv = C_SetPIN(hSession[1], anotherPIN, strlen(anotherPIN),userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_SetPIN to do(oldPIN->newPIN, newPIN->oldPIN)"));

			
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));

			rv = C_SetPIN(hSession[0], userPIN, strlen(userPIN), userPIN, strlen(userPIN));			
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, "Call to C_SetPIN with R/O-user state"));
			

			//FUNNY TEST CK_RW_USER_FUNCTIONS
			rv = C_SetPIN(hSession[1], NULL_PTR, 0, userPIN, strlen(userPIN));			
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_SetPIN in R/W-user state with second argument NULL_PTR"));
				
			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), NULL_PTR, 0);			
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_SetPIN in R/W-user state with fourth argument NULL_PTR"));			

			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), longPIN, infoToken.ulMaxPinLen + 1);
			assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, "Call to C_SetPIN in R/W-user, with a userPIN which has 1 more char than specified in ulMaxPinLen(C_GetTokenInfo)"));
			

			if (infoToken.ulMinPinLen > 0)
			{
				CK_UTF8CHAR shortPIN [] = {""};
				rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), shortPIN, 0);
				assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, "Call to C_SetPIN  in R/W-user state, with a userPIN of 0 chars(\"\")"));
			}

			rv = C_SetPIN(hSession[1], badPIN, strlen(badPIN),userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_PIN_INCORRECT, "Call to C_SetPIN in R/W-user with an incorrect oldPIN"));
			//_____

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));
			
			rv = C_CloseSession(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_OK , "Call to C_CloseSession with a R/O session handle"));
			int ind = indexOfElem((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);			
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_SO user type"));

			//FUNNY TEST CK_RW_SO_FUNCTIONS
			rv = C_SetPIN(hSession[1], NULL_PTR, 0, soPINs[ind], strlen(soPINs[ind]));			
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_SetPIN in R/W-SO state with second argument NULL_PTR"));
				
			rv = C_SetPIN(hSession[1], soPINs[ind], strlen(soPINs[ind]), NULL_PTR, 0);			
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_SetPIN in R/W-SO state with fourth argument NULL_PTR"));
		
			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), longPIN, infoToken.ulMaxPinLen + 1);
			assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, "Call to C_SetPIN in R/W-SO, with a userPIN which has 1 more char than specified in ulMaxPinLen(C_GetTokenInfo)"));
			free(longPIN);

			if (infoToken.ulMinPinLen > 0)
			{
				CK_UTF8CHAR shortPIN [] = {""};
				rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), shortPIN, 0);
				assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, "Call to C_SetPIN  in R/W-SO state, with a userPIN of 0 chars(\"\")"));
			}

			rv = C_SetPIN(hSession[1], badPIN, strlen(badPIN),userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_PIN_INCORRECT, "Call to C_SetPIN in R/W-SO with an incorrect oldPIN"));
			//_____
		}
	}
	free(buffer);
	
	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_SetPIN after calling C_Finalize"));

	printlnLevel(showMessage, "End: test C_SetPIN", level);
}

///
void stressSetPin(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_SetPIN", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testSetPin(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_SetPIN", level);
	}

}


//Test of functions of object management
//Estas son C_CreateObject, C_DestroyObject, C_GenerateKeyPair, C_GetAttribute,
//C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal
void testObjectManagementFunctions(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test functions of object management", level);
	testCreateObject(level + 1, showMessage);
	stressCreateObject(level + 1, repetitions, showMessage);
	testDestroyObject(level + 1, showMessage);
	stressDestroyObject(level + 1, repetitions, showMessage);
	testGenerateKeyPair(level + 1, showMessage);
	stressGenerateKeyPair(level + 1, repetitions, showMessage);
	testGetAttributeValue(level + 1, showMessage);
	stressGetAttributeValue(level + 1, repetitions, showMessage);
	testFindObjectsMechanism(level + 1, showMessage);
	stressFindObjectsMechanism(level + 1, repetitions, showMessage);
	printlnLevel(showMessage, "End: test functions of object management", level);
}

///
void testCreateObject(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_CreateObject", level);
	CK_RV rv;
	static CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
  	static CK_BYTE modulus[] = { 0xcb, 0x12, 0x9d, 0xba, 0x22, 0xfa, 0x2b, 0x33, 0x7e, 0x2a, 0x24, 0x65, 0x09, 0xa9,
                               0xfb, 0x41, 0x1a, 0x0e, 0x2f, 0x89, 0x3a, 0xd6, 0x97, 0x49, 0x77, 0x6d, 0x2a, 0x6e, 0x98,
                               0x48, 0x6b, 0xa8, 0xc4, 0x63, 0x8e, 0x46, 0x90, 0x70, 0x2e, 0xd4, 0x10, 0xc0, 0xdd, 0xa3,
                               0x56, 0xcf, 0x97, 0x2f, 0x2f, 0xfc, 0x2d, 0xff, 0x2b, 0xf2, 0x42, 0x69, 0x4a, 0x8c, 0xf1,
                               0x6f, 0x76, 0x32, 0xc8, 0xe1, 0x37, 0x52, 0xc1, 0xd1, 0x33, 0x82, 0x39, 0x1a, 0xb3, 0x2a,
                               0xa8, 0x80, 0x4e, 0x19, 0x91, 0xa6, 0xa6, 0x16, 0x65, 0x30, 0x72, 0x80, 0xc3, 0x5c, 0x84,
                               0x9b, 0x7b, 0x2c, 0x6d, 0x2d, 0x75, 0x51, 0x9f, 0xc9, 0x6d, 0xa8, 0x4d, 0x8c, 0x41, 0x41,
                               0x12, 0xc9, 0x14, 0xc7, 0x99, 0x31, 0xe4, 0xcd, 0x97, 0x38, 0x2c, 0xca, 0x32, 0x2f, 0xeb,
                               0x78, 0x37, 0x17, 0x87, 0xc8, 0x09, 0x5a, 0x1a, 0xaf, 0xe4, 0xc4, 0xcc, 0x83, 0xe3, 0x79,
                               0x01, 0xd6, 0xdb, 0x8b, 0xd6, 0x24, 0x90, 0x43, 0x7b, 0xc6, 0x40, 0x57, 0x58, 0xe4, 0x49,
                               0x2b, 0x99, 0x61, 0x71, 0x52, 0xf4, 0x8b, 0xda, 0xb7, 0x5a, 0xbf, 0xf7, 0xc5, 0x2a, 0x8b,
                               0x1f, 0x25, 0x5e, 0x5b, 0xfb, 0x9f, 0xcc, 0x8d, 0x1c, 0x92, 0x21, 0xe9, 0xba, 0xd0, 0x54,
                               0xf6, 0x0d, 0xe8, 0x7e, 0xb3, 0x9d, 0x9a, 0x47, 0xba, 0x1e, 0x45, 0x4e, 0xdc, 0xe5, 0x20,
                               0x95, 0xd8, 0xe5, 0xe9, 0x51, 0xff, 0x1f, 0x9e, 0x9e, 0x60, 0x3c, 0x27, 0x1c, 0xf3, 0xc7,
                               0xf4, 0x89, 0xaa, 0x2a, 0x80, 0xd4, 0x03, 0x5d, 0xf3, 0x39, 0xa3, 0xa7, 0xe7, 0x3f, 0xa9,
                               0xd1, 0x31, 0x50, 0xb7, 0x0f, 0x08, 0xa2, 0x71, 0xcc, 0x6a, 0xb4, 0xb5, 0x8f, 0xcb, 0xf7,
                               0x1f, 0x4e, 0xc8, 0x16, 0x08, 0xc0, 0x03, 0x8a, 0xce, 0x17, 0xd1, 0xdd, 0x13, 0x0f, 0xa3,
                               0xbe, 0xa3 };
  	
	static CK_BYTE id[] = { 123 };
  	static CK_BBOOL true = CK_TRUE, false = CK_FALSE;
  	static CK_BYTE label[] = "label";
  	static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  	static CK_KEY_TYPE keyType = CKK_RSA;
  	CK_ATTRIBUTE pubTemplate[] = {
    	{CKA_CLASS, &pubClass, sizeof(pubClass)},
    	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    	{CKA_LABEL, label, sizeof(label)},
    	{CKA_ID, id, sizeof(id)},
    	{CKA_TOKEN, &false, sizeof(false)},
    	{CKA_VERIFY, &true, sizeof(true)},
    	{CKA_ENCRYPT, &false, sizeof(false)},
    	{CKA_PRIVATE, &false, sizeof(false)},
    	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    	{CKA_MODULUS, modulus, sizeof(modulus)}
  	};
	CK_SESSION_HANDLE hSession[2];
	CK_OBJECT_HANDLE hObject[2];



	rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_CreateObject before calling C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_CreateObject(CK_INVALID_HANDLE, pubTemplate, 10, &hObject[1]);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_CreateObject with invalid session handle"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//BEFORELOGINNORMAL	
			pubTemplate[7] = (CK_ATTRIBUTE){CKA_PRIVATE, &true, sizeof(true)};
			
			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_CreateObject with  R/W-public state triying to create a session private object"));

			rv = C_CreateObject(hSession[0], pubTemplate, 10, &hObject[0]);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_CreateObject with  R/O-public state trying to create a session private object"));


			pubTemplate[4] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			
			rv = C_CreateObject(hSession[0], pubTemplate, 10, &hObject[0]);
			assert2(behavior, verifyCode2(rv, CKR_SESSION_READ_ONLY, CKR_USER_NOT_LOGGED_IN, "Call to C_CreateObject with  R/O-public state trying to create a token private object"));


			pubTemplate[4] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			
			//BEFORELOGINNORMAL(FIN)	
			
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK,  "Call to C_Login with CKU_USER user type"));
				//____
			//AFTERLOGINNORMAL
			


			rv = C_CreateObject(hSession[1], NULL_PTR, 0, &hObject[1]);
			sprintf(ret, "Call to C_CreateObject with sesion R/W abierta y logueada en normal user  n slotID(%d) of C_GetSlotList(CK_TRUE) y with flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y with segundo argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_CreateObject with second argument NULL_PTR"));

			rv = C_CreateObject(hSession[1], pubTemplate, 10, NULL_PTR);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_CreateObject with fourth argument NULL_PTR"));
			
			CK_ATTRIBUTE insufficientTemplate[] = {
    			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		    	{CKA_LABEL, label, sizeof(label)},
    			{CKA_ID, id, sizeof(id)},
		    	{CKA_TOKEN, &false, sizeof(false)},
		    	{CKA_VERIFY, &true, sizeof(true)},
		    	{CKA_ENCRYPT, &false, sizeof(false)},
		    	{CKA_WRAP, &false, sizeof(false)},
		    	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    			{CKA_MODULUS, modulus, sizeof(modulus)}
		  	};
			
			rv = C_CreateObject(hSession[1], insufficientTemplate, 9, &hObject[1]);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT, "Call to C_CreateObject with template which does not have the CKA_CLASS attribute"));//BECAUSE PAGE 101

			CK_ATTRIBUTE inconsistentTemplate[] = {
			{CKA_CLASS, &pubClass, sizeof(pubClass)},
    			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		    	{CKA_LABEL, label, sizeof(label)},
    			{CKA_ID, id, sizeof(id)},
		    	{CKA_TOKEN, &true, sizeof(true)},
			{CKA_TOKEN, &false, sizeof(false)},
		    	{CKA_VERIFY, &true, sizeof(true)},
		    	{CKA_ENCRYPT, &false, sizeof(false)},
		    	{CKA_WRAP, &false, sizeof(false)},
		    	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    			{CKA_MODULUS, modulus, sizeof(modulus)}
		  	};

			//PAGE 64
			rv = C_CreateObject(hSession[1], inconsistentTemplate, 11, &hObject[1]);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID ,CKR_TEMPLATE_INCONSISTENT, "Call to C_CreateObject with template which specifies CKA_TOKEN true and false"));//BECAUSE PAGE 101
			
			CK_OBJECT_CLASS invalid;
			invalid = 8;
			pubTemplate[0].pValue = &invalid;
			pubTemplate[0].ulValueLen = sizeof(invalid);

			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT, "Call to C_CreateObject with template which specifies an invalid CKA_CLASS attribute"));//BECAUSE PAGE 101



			pubTemplate[0].pValue = &pubClass;
			pubTemplate[0].ulValueLen = sizeof(pubClass);

			pubTemplate[7] = (CK_ATTRIBUTE){CKA_CERTIFICATE_CATEGORY, NULL_PTR, 0};
			
			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_TYPE_INVALID, "Call to C_CreateObject with template which specifies an invalid kind of attribute"));


			pubTemplate[7] = (CK_ATTRIBUTE){CKA_PRIVATE, &false, sizeof(false)};			
			
			pubTemplate[4] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};

			rv = C_CreateObject(hSession[0], pubTemplate, 10, &hObject[0]);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, "Call to C_CreateObject with R/O-user state trying to create a token public object"));


			pubTemplate[4] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			

			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject with R/O-user state trying to create a session public object"));

			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject with R/W-user state trying to create a session public object"));
			//AFTERLOGINNORMAL

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));
			
			rv = C_CloseSession(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_OK ,"Call to C_CloseSession with a R/O session handle"));
		}
	}
	free(buffer);
	



	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));

	rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_CreateObject after calling C_Finalize"));

	printlnLevel(showMessage, "End: test C_CreateObject", level);
}


///
void stressCreateObject(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_CreateObject", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testCreateObject(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_CreateObject", level);
	}
}


///AND ANALISYS OF CAPABILITIES
void testDestroyObject(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_DestroyObject", level);
	CK_RV rv;
	static CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
  	static CK_BYTE modulus[] = { 0xcb, 0x12, 0x9d, 0xba, 0x22, 0xfa, 0x2b, 0x33, 0x7e, 0x2a, 0x24, 0x65, 0x09, 0xa9,
                               0xfb, 0x41, 0x1a, 0x0e, 0x2f, 0x89, 0x3a, 0xd6, 0x97, 0x49, 0x77, 0x6d, 0x2a, 0x6e, 0x98,
                               0x48, 0x6b, 0xa8, 0xc4, 0x63, 0x8e, 0x46, 0x90, 0x70, 0x2e, 0xd4, 0x10, 0xc0, 0xdd, 0xa3,
                               0x56, 0xcf, 0x97, 0x2f, 0x2f, 0xfc, 0x2d, 0xff, 0x2b, 0xf2, 0x42, 0x69, 0x4a, 0x8c, 0xf1,
                               0x6f, 0x76, 0x32, 0xc8, 0xe1, 0x37, 0x52, 0xc1, 0xd1, 0x33, 0x82, 0x39, 0x1a, 0xb3, 0x2a,
                               0xa8, 0x80, 0x4e, 0x19, 0x91, 0xa6, 0xa6, 0x16, 0x65, 0x30, 0x72, 0x80, 0xc3, 0x5c, 0x84,
                               0x9b, 0x7b, 0x2c, 0x6d, 0x2d, 0x75, 0x51, 0x9f, 0xc9, 0x6d, 0xa8, 0x4d, 0x8c, 0x41, 0x41,
                               0x12, 0xc9, 0x14, 0xc7, 0x99, 0x31, 0xe4, 0xcd, 0x97, 0x38, 0x2c, 0xca, 0x32, 0x2f, 0xeb,
                               0x78, 0x37, 0x17, 0x87, 0xc8, 0x09, 0x5a, 0x1a, 0xaf, 0xe4, 0xc4, 0xcc, 0x83, 0xe3, 0x79,
                               0x01, 0xd6, 0xdb, 0x8b, 0xd6, 0x24, 0x90, 0x43, 0x7b, 0xc6, 0x40, 0x57, 0x58, 0xe4, 0x49,
                               0x2b, 0x99, 0x61, 0x71, 0x52, 0xf4, 0x8b, 0xda, 0xb7, 0x5a, 0xbf, 0xf7, 0xc5, 0x2a, 0x8b,
                               0x1f, 0x25, 0x5e, 0x5b, 0xfb, 0x9f, 0xcc, 0x8d, 0x1c, 0x92, 0x21, 0xe9, 0xba, 0xd0, 0x54,
                               0xf6, 0x0d, 0xe8, 0x7e, 0xb3, 0x9d, 0x9a, 0x47, 0xba, 0x1e, 0x45, 0x4e, 0xdc, 0xe5, 0x20,
                               0x95, 0xd8, 0xe5, 0xe9, 0x51, 0xff, 0x1f, 0x9e, 0x9e, 0x60, 0x3c, 0x27, 0x1c, 0xf3, 0xc7,
                               0xf4, 0x89, 0xaa, 0x2a, 0x80, 0xd4, 0x03, 0x5d, 0xf3, 0x39, 0xa3, 0xa7, 0xe7, 0x3f, 0xa9,
                               0xd1, 0x31, 0x50, 0xb7, 0x0f, 0x08, 0xa2, 0x71, 0xcc, 0x6a, 0xb4, 0xb5, 0x8f, 0xcb, 0xf7,
                               0x1f, 0x4e, 0xc8, 0x16, 0x08, 0xc0, 0x03, 0x8a, 0xce, 0x17, 0xd1, 0xdd, 0x13, 0x0f, 0xa3,
                               0xbe, 0xa3 };
  	
	static CK_BYTE id[] = { 123 };
  	static CK_BBOOL true = CK_TRUE, false = CK_FALSE;
  	static CK_BYTE label[] = "label";
  	static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  	static CK_KEY_TYPE keyType = CKK_RSA;
  	CK_ATTRIBUTE pubTemplate[] = {
    	{CKA_CLASS, &pubClass, sizeof(pubClass)},
    	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_TOKEN, &true, sizeof(true)},  //2 	
	{CKA_ID, id, sizeof(id)},
    	{CKA_VERIFY, &true, sizeof(true)},
    	{CKA_ENCRYPT, &false, sizeof(false)},
	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
	{CKA_PRIVATE, &true, sizeof(true)},   //7
    	{CKA_MODULUS, modulus, sizeof(modulus)}
  	};
	CK_SESSION_HANDLE hSession[2];
	CK_OBJECT_HANDLE hObject[8];



	rv = C_DestroyObject(hSession[1], hObject[1]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_DestroyObject before calling C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_DestroyObject(CK_INVALID_HANDLE, hObject[1]);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_DestroyObject with invalid session handle"));


	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//BEFORELOGINNORMAL	
			rv = C_DestroyObject(hSession[1], CK_INVALID_HANDLE);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject with an invalid object handle"));


			//BEFORELOGINNORMAL(FIN)	
			
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));
				//____
			//AFTERLOGINNORMAL
			


			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[0]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a token private object"));
			//

			pubTemplate[2].pValue = &true;
			pubTemplate[2].ulValueLen = sizeof(true);
			pubTemplate[7].pValue = &false;
			pubTemplate[7].ulValueLen = sizeof(false);


			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a token public object"));

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[6]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a token public object, same to one already created"));

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[7]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a token public object, same to one already created"));
			//
			pubTemplate[2].pValue = &false;
			pubTemplate[2].ulValueLen = sizeof(false);
			pubTemplate[7].pValue = &true;
			pubTemplate[7].ulValueLen = sizeof(true);

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[2]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a session private object"));

			rv = C_CreateObject(hSession[0], pubTemplate, 9, &hObject[4]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a session private object, same to one already created"));
			//

			pubTemplate[2].pValue = &false;
			pubTemplate[2].ulValueLen = sizeof(false);
			pubTemplate[7].pValue = &false;
			pubTemplate[7].ulValueLen = sizeof(false);

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[3]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a session public object"));

			rv = C_CreateObject(hSession[0], pubTemplate, 9, &hObject[5]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a session public object, same to one already created"));
			//
			
			pubTemplate[2].pValue = &true;
			pubTemplate[2].ulValueLen = sizeof(true);
			pubTemplate[7].pValue = &true;
			pubTemplate[7].ulValueLen = sizeof(true);

			rv = C_DestroyObject(hSession[0], hObject[0]);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, "Call to C_DestroyObject with R/O-user state trying to destroy a token private object"));
			
			rv = C_DestroyObject(hSession[0], hObject[1]);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, "Call to C_DestroyObject with R/O-user state trying to destroy a token private object"));
			//AFTERLOGINNORMAL

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to Logout"));


			rv = C_DestroyObject(hSession[0], hObject[0]);
			assert2(behavior, verifyCode2(rv, CKR_SESSION_READ_ONLY, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject with R/O-public state trying to destroy a token private object"));

			rv = C_DestroyObject(hSession[0], hObject[1]);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, "Call to C_DestroyObject with R/O-public state trying to destroy a token public object"));
			
			rv = C_DestroyObject(hSession[0], hObject[2]);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject with R/O-public state trying to destroy a session private object"));//There is not a good return code	

			rv = C_DestroyObject(hSession[1], hObject[0]);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject with R/W-public state trying to destroy a token private object"));//There is not a good return code

			rv = C_DestroyObject(hSession[1], hObject[2]);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject with R/W-public state trying to destroy a session private object"));//There is not a good return code	
			
			rv = C_CloseSession(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_OK ,"Call to C_CloseSession with a R/O session handle"));

			int ind = indexOfElem((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);			
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_SO user type"));

			rv = C_DestroyObject(hSession[1], hObject[0]);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject with R/W-SO state trying to destroy a token private object"));//There is not a good return code

			rv = C_DestroyObject(hSession[1], hObject[2]);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject with R/W-SO state trying to destroy a session private object"));//There is not a good return code

			

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));

			rv = C_DestroyObject(hSession[1], hObject[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_DestroyObject with R/W-public state trying to destroy a token public object"));

			rv = C_DestroyObject(hSession[1], hObject[6]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_DestroyObject with R/W-public state trying to destroy a token public object"));

			rv = C_DestroyObject(hSession[1], hObject[3]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_DestroyObject with R/W-public state trying to destroy a session public object"));
			
			rv = C_DestroyObject(hSession[1], hObject[4]);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject with R/W-public state trying to destroy a session private object"));//There is not a good return code

			rv = C_DestroyObject(hSession[1], hObject[5]);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject trying to destroy a session public object, which was destroyed its father session"));

			
						
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));

			rv = C_DestroyObject(hSession[1], hObject[0]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_DestroyObject trying to destroy a token private object after logging out and logging in"));

			rv = C_DestroyObject(hSession[1], hObject[2]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_DestroyObject trying to destroy a session private object after logging out and logging in"));//this session was not destroyed

			rv = C_DestroyObject(hSession[1], hObject[2]);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject trying to destroy an object which was destroyed before"));

			rv = C_DestroyObject(hSession[1], hObject[4]);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject trying to destroy a session private object, which was destroyed its father session"));

			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Call to C_CloseAllSessions with slotID(%d)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
			

			char * textLabel = "A token";
        		CK_UTF8CHAR paddedLabel[32];
        		memset(paddedLabel, ' ', sizeof(paddedLabel));
        		memcpy(paddedLabel, textLabel, strlen(textLabel));
			
			sprintf(ret, "Call to C_InitToken with slotID(%d)", (int)slot);
			rv = C_InitToken(slot, soPINs[ind], strlen(soPINs[ind]), paddedLabel);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_SO user type"));

			rv = C_InitPIN(hSession[1], userPIN, strlen(userPIN));
			sprintf(ret, "Call to C_InitPIN with a R/W session handle, second argument %s and third argument %d", (char *)userPIN, (int)strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));

			rv = C_DestroyObject(hSession[1], hObject[7]);
			sprintf(ret, "Call to C_DestroyObject with sesion R/W abierta en slotID(%d) of C_GetSlotList(CK_TRUE) y with flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, luego de reinicializar el token", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_DestroyObject after reinitializing token"));
		
			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Call to C_CloseAllSessions with slotID(%d)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
			
		}
	}
	free(buffer);
	



	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));

	rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_CreateObject after calling C_Finalize"));
	
	printlnLevel(showMessage, "End: test C_DestroyObject", level);

}

///
void stressDestroyObject(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_DestroyObject", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testDestroyObject(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_DestroyObject", level);
	}

}

///
void testGenerateKeyPair(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_GenerateKeyPair", level);

	CK_RV rv;
	static CK_ULONG modulusBits = 768;
  	static CK_BBOOL true = CK_TRUE, false = CK_FALSE;
  	static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  	static CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;
  	static CK_KEY_TYPE keyType = CKK_RSA;
	static CK_BYTE id[] = { 123 };
	static CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
	static CK_BYTE modulus[] = { 0xcb, 0x12, 0x9d, 0xba, 0x22, 0xfa, 0x2b, 0x33, 0x7e, 0x2a, 0x24, 0x65, 0x09, 0xa9,
                               0xfb, 0x41, 0x1a, 0x0e, 0x2f, 0x89, 0x3a, 0xd6, 0x97, 0x49, 0x77, 0x6d, 0x2a, 0x6e, 0x98,
                               0x48, 0x6b, 0xa8, 0xc4, 0x63, 0x8e, 0x46, 0x90, 0x70, 0x2e, 0xd4, 0x10, 0xc0, 0xdd, 0xa3,
                               0x56, 0xcf, 0x97, 0x2f, 0x2f, 0xfc, 0x2d, 0xff, 0x2b, 0xf2, 0x42, 0x69, 0x4a, 0x8c, 0xf1,
                               0x6f, 0x76, 0x32, 0xc8, 0xe1, 0x37, 0x52, 0xc1, 0xd1, 0x33, 0x82, 0x39, 0x1a, 0xb3, 0x2a,
                               0xa8, 0x80, 0x4e, 0x19, 0x91, 0xa6, 0xa6, 0x16, 0x65, 0x30, 0x72, 0x80, 0xc3, 0x5c, 0x84,
                               0x9b, 0x7b, 0x2c, 0x6d, 0x2d, 0x75, 0x51, 0x9f, 0xc9, 0x6d, 0xa8, 0x4d, 0x8c, 0x41, 0x41,
                               0x12, 0xc9, 0x14, 0xc7, 0x99, 0x31, 0xe4, 0xcd, 0x97, 0x38, 0x2c, 0xca, 0x32, 0x2f, 0xeb,
                               0x78, 0x37, 0x17, 0x87, 0xc8, 0x09, 0x5a, 0x1a, 0xaf, 0xe4, 0xc4, 0xcc, 0x83, 0xe3, 0x79,
                               0x01, 0xd6, 0xdb, 0x8b, 0xd6, 0x24, 0x90, 0x43, 0x7b, 0xc6, 0x40, 0x57, 0x58, 0xe4, 0x49,
                               0x2b, 0x99, 0x61, 0x71, 0x52, 0xf4, 0x8b, 0xda, 0xb7, 0x5a, 0xbf, 0xf7, 0xc5, 0x2a, 0x8b,
                               0x1f, 0x25, 0x5e, 0x5b, 0xfb, 0x9f, 0xcc, 0x8d, 0x1c, 0x92, 0x21, 0xe9, 0xba, 0xd0, 0x54,
                               0xf6, 0x0d, 0xe8, 0x7e, 0xb3, 0x9d, 0x9a, 0x47, 0xba, 0x1e, 0x45, 0x4e, 0xdc, 0xe5, 0x20,
                               0x95, 0xd8, 0xe5, 0xe9, 0x51, 0xff, 0x1f, 0x9e, 0x9e, 0x60, 0x3c, 0x27, 0x1c, 0xf3, 0xc7,
                               0xf4, 0x89, 0xaa, 0x2a, 0x80, 0xd4, 0x03, 0x5d, 0xf3, 0x39, 0xa3, 0xa7, 0xe7, 0x3f, 0xa9,
                               0xd1, 0x31, 0x50, 0xb7, 0x0f, 0x08, 0xa2, 0x71, 0xcc, 0x6a, 0xb4, 0xb5, 0x8f, 0xcb, 0xf7,
                               0x1f, 0x4e, 0xc8, 0x16, 0x08, 0xc0, 0x03, 0x8a, 0xce, 0x17, 0xd1, 0xdd, 0x13, 0x0f, 0xa3,
                               0xbe, 0xa3 };


	CK_ATTRIBUTE privateKeyTemplate[] = {
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_PRIVATE, &true, sizeof(true)},
	{CKA_CLASS, &priClass, sizeof(priClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
   	{CKA_ID, id, sizeof(id)},
    	{CKA_SENSITIVE, &true, sizeof(true)},
    	{CKA_DECRYPT, &true, sizeof(true)},
    	{CKA_SIGN, &true, sizeof(true)},
    	{CKA_UNWRAP, &true, sizeof(true)}
    	
  	};
	
	CK_ATTRIBUTE publicKeyTemplate[] = {
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_PRIVATE, &true, sizeof(true)},
	{CKA_CLASS, &priClass, sizeof(priClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    	{CKA_ENCRYPT, &true, sizeof(true)},
    	{CKA_VERIFY, &true, sizeof(true)},
    	{CKA_WRAP, &true, sizeof(true)},
    	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    	
    	{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  	};  	
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_SESSION_HANDLE hSession[2];
	CK_OBJECT_HANDLE hPrivateKey, hPublicKey;



	rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_GenerateKeyPair before calling C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_GenerateKeyPair(CK_INVALID_HANDLE, &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_GenerateKeyPair with invalid session handle"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//BEFORELOGINNORMAL	
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_GenerateKeyPair with R/W-public state trying to create private keys"));

			rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_GenerateKeyPair with R/O-public state trying to create session private keys"));


			privateKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			publicKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, "Call to C_GenerateKeyPair with R/W-public state trying to create token private keys"));
			
			privateKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			publicKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			
			//BEFORELOGINNORMAL(FIN)	
			
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));
				//____
			//AFTERLOGINNORMAL
			

			rv = C_GenerateKeyPair(hSession[1], &mechanism, NULL_PTR, 0, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GenerateKeyPair with third argument NULL_PTR"));

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, NULL_PTR, 0, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GenerateKeyPair with fifth argument NULL_PTR"));

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, NULL_PTR, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GenerateKeyPair with sixth argument NULL_PTR"));

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, NULL_PTR);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GenerateKeyPair with seventh argument NULL_PTR"));
			
			CK_ATTRIBUTE insufficientTemplate[] = {
			{CKA_TOKEN, &false, sizeof(false)},
			{CKA_PRIVATE, &true, sizeof(true)},
			{CKA_CLASS, &priClass, sizeof(priClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    			{CKA_ENCRYPT, &true, sizeof(true)},
    			{CKA_VERIFY, &true, sizeof(true)},
    			{CKA_WRAP, &true, sizeof(true)},
    			};  
			
			rv = C_GenerateKeyPair(hSession[1], &mechanism, insufficientTemplate, 7, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT, "Call to C_GenerateKeyPair trying to create a RSA key pair without the CKA_MODULUS_BITS"));//BECAUSE PAGE 101

			CK_ATTRIBUTE inconsistentTemplate[] = {
			{CKA_TOKEN, &true, sizeof(true)},
			{CKA_TOKEN, &false, sizeof(false)},
			{CKA_PRIVATE, &true, sizeof(true)},
			{CKA_CLASS, &priClass, sizeof(priClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    			{CKA_ENCRYPT, &true, sizeof(true)},
    			{CKA_VERIFY, &true, sizeof(true)},
    			{CKA_WRAP, &true, sizeof(true)},
    			{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    			{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  		}; 
			rv = C_GenerateKeyPair(hSession[1], &mechanism, inconsistentTemplate, 10, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT, "Call to C_GenerateKeyPair specifying CKA_TOKEN true and false"));//BECAUSE PAGE 101
			
			CK_KEY_TYPE another;
			another = CKK_DSA;
			publicKeyTemplate[3].pValue = &another;
			publicKeyTemplate[3].ulValueLen = sizeof(another);
			privateKeyTemplate[3].pValue = &another;
			privateKeyTemplate[3].ulValueLen = sizeof(another);

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_TEMPLATE_INCONSISTENT, "Call to C_GenerateKeyPair trying to create a RSA key pair, but specifying CKA_KEY_TYPE CKK_DSA"));
			
			publicKeyTemplate[3].pValue = &keyType;
			publicKeyTemplate[3].ulValueLen = sizeof(keyType);
			privateKeyTemplate[3].pValue = &keyType;
			privateKeyTemplate[3].ulValueLen = sizeof(keyType);


			CK_OBJECT_CLASS invalid;
			invalid = 8;
			publicKeyTemplate[2].pValue = &invalid;
			publicKeyTemplate[2].ulValueLen = sizeof(invalid);
			privateKeyTemplate[2].pValue = &invalid;
			privateKeyTemplate[2].ulValueLen = sizeof(invalid);

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_TEMPLATE_INCONSISTENT, "Call to C_GenerateKeyPair trying to create a RSA key pair specifying an invalid CKA_CLASS(8)"));

			publicKeyTemplate[2].pValue = &pubClass;
			publicKeyTemplate[2].ulValueLen = sizeof(pubClass);
			privateKeyTemplate[2].pValue = &priClass;
			privateKeyTemplate[2].ulValueLen = sizeof(priClass);

			
			publicKeyTemplate[3] = (CK_ATTRIBUTE){CKA_CERTIFICATE_CATEGORY, NULL_PTR, 0};
			privateKeyTemplate[3] = (CK_ATTRIBUTE){CKA_CERTIFICATE_CATEGORY, NULL_PTR, 0};
			
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_TYPE_INVALID, "Call to C_GenerateKeyPair with an invalid attribute type"));
			
			publicKeyTemplate[3] = (CK_ATTRIBUTE){CKA_KEY_TYPE, &keyType, sizeof(keyType)};
			privateKeyTemplate[3] = (CK_ATTRIBUTE){CKA_KEY_TYPE, &keyType, sizeof(keyType)};
			
			//
			publicKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			privateKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			
			rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, "Call to C_GenerateKeyPair in R/O-user state trying to create a token private keys"));

			publicKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			privateKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			
			mechanism.mechanism = 0x9999;
				
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_INVALID, "Call to C_GenerateKeyPair specifying an invalid mechanism(0x9999)"));



			mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
			
			CK_BYTE otherPublicValue[128];
    			mechanism.pParameter = otherPublicValue ;
			mechanism.ulParameterLen = sizeof(otherPublicValue);
			//196			
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_PARAM_INVALID, "Call to C_GenerateKeyPair specifying a valid mechanism, but with invalid parameter"));
				
			mechanism.pParameter = NULL_PTR ;
			mechanism.ulParameterLen = 0;
			
			///

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GenerateKeyPair trying to create a token private keys"));


			CK_ATTRIBUTE publicKeyTemplate[] = {
			{CKA_TOKEN, &false, sizeof(false)},
			{CKA_PRIVATE, &true, sizeof(true)},
			{CKA_CLASS, &priClass, sizeof(priClass)},
			{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		    	{CKA_ENCRYPT, &true, sizeof(true)},
		    	{CKA_VERIFY, &true, sizeof(true)},
		    	{CKA_WRAP, &true, sizeof(true)},
		    	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    			{CKA_MODULUS, modulus, sizeof(modulus)},
		    	{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  			};  
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT, "Call to C_GenerateKeyPair trying to create a RSA key pair, but specifying its CKA_MODULUS"));

			//AFTERLOGINNORMAL

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));
			
			rv = C_CloseSession(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_OK ,"Call to C_CloseSession with a R/O session handle"));
		}
	}
	free(buffer);
	



	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));

	rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_GenerateKeyPair after calling C_Finalize"));

	printlnLevel(showMessage, "End: test C_GenerateKeyPair", level);

}

///
void stressGenerateKeyPair(int level, int repetitions, int showMessage)
{

	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_GenerateKeyPair", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testGenerateKeyPair(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_GenerateKeyPair", level);
	}

}

///
void testGetAttributeValue(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_GetAttributeValue", level);
	
	CK_RV rv;

	static CK_BYTE modulus[] = { 0xcb, 0x12, 0x9d, 0xba, 0x22, 0xfa, 0x2b, 0x33, 0x7e, 0x2a, 0x24, 0x65, 0x09, 0xa9,
                               0xfb, 0x41, 0x1a, 0x0e, 0x2f, 0x89, 0x3a, 0xd6, 0x97, 0x49, 0x77, 0x6d, 0x2a, 0x6e, 0x98,
                               0x48, 0x6b, 0xa8, 0xc4, 0x63, 0x8e, 0x46, 0x90, 0x70, 0x2e, 0xd4, 0x10, 0xc0, 0xdd, 0xa3,
                               0x56, 0xcf, 0x97, 0x2f, 0x2f, 0xfc, 0x2d, 0xff, 0x2b, 0xf2, 0x42, 0x69, 0x4a, 0x8c, 0xf1,
                               0x6f, 0x76, 0x32, 0xc8, 0xe1, 0x37, 0x52, 0xc1, 0xd1, 0x33, 0x82, 0x39, 0x1a, 0xb3, 0x2a,
                               0xa8, 0x80, 0x4e, 0x19, 0x91, 0xa6, 0xa6, 0x16, 0x65, 0x30, 0x72, 0x80, 0xc3, 0x5c, 0x84,
                               0x9b, 0x7b, 0x2c, 0x6d, 0x2d, 0x75, 0x51, 0x9f, 0xc9, 0x6d, 0xa8, 0x4d, 0x8c, 0x41, 0x41,
                               0x12, 0xc9, 0x14, 0xc7, 0x99, 0x31, 0xe4, 0xcd, 0x97, 0x38, 0x2c, 0xca, 0x32, 0x2f, 0xeb,
                               0x78, 0x37, 0x17, 0x87, 0xc8, 0x09, 0x5a, 0x1a, 0xaf, 0xe4, 0xc4, 0xcc, 0x83, 0xe3, 0x79,
                               0x01, 0xd6, 0xdb, 0x8b, 0xd6, 0x24, 0x90, 0x43, 0x7b, 0xc6, 0x40, 0x57, 0x58, 0xe4, 0x49,
                               0x2b, 0x99, 0x61, 0x71, 0x52, 0xf4, 0x8b, 0xda, 0xb7, 0x5a, 0xbf, 0xf7, 0xc5, 0x2a, 0x8b,
                               0x1f, 0x25, 0x5e, 0x5b, 0xfb, 0x9f, 0xcc, 0x8d, 0x1c, 0x92, 0x21, 0xe9, 0xba, 0xd0, 0x54,
                               0xf6, 0x0d, 0xe8, 0x7e, 0xb3, 0x9d, 0x9a, 0x47, 0xba, 0x1e, 0x45, 0x4e, 0xdc, 0xe5, 0x20,
                               0x95, 0xd8, 0xe5, 0xe9, 0x51, 0xff, 0x1f, 0x9e, 0x9e, 0x60, 0x3c, 0x27, 0x1c, 0xf3, 0xc7,
                               0xf4, 0x89, 0xaa, 0x2a, 0x80, 0xd4, 0x03, 0x5d, 0xf3, 0x39, 0xa3, 0xa7, 0xe7, 0x3f, 0xa9,
                               0xd1, 0x31, 0x50, 0xb7, 0x0f, 0x08, 0xa2, 0x71, 0xcc, 0x6a, 0xb4, 0xb5, 0x8f, 0xcb, 0xf7,
                               0x1f, 0x4e, 0xc8, 0x16, 0x08, 0xc0, 0x03, 0x8a, 0xce, 0x17, 0xd1, 0xdd, 0x13, 0x0f, 0xa3,
                               0xbe, 0xa3 };

	static CK_ULONG modulusBits = 768;
  	static CK_BBOOL true = CK_TRUE, false = CK_FALSE;
  	static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  	static CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;
  	static CK_KEY_TYPE keyType = CKK_RSA;
	static CK_BYTE id[] = { 123 };
	static CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
  	
	static CK_BYTE id2[] = { 124 };
  	static CK_BYTE label[] = "label";
  	

	CK_ATTRIBUTE pubTemplate[] = {
    	{CKA_CLASS, &pubClass, sizeof(pubClass)},
    	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    	{CKA_LABEL, label, sizeof(label)},
    	{CKA_ID, id2, sizeof(id2)},
    	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_PRIVATE, &true, sizeof(true)},
    	{CKA_VERIFY, &true, sizeof(true)},
    	{CKA_ENCRYPT, &false, sizeof(false)},
    	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    	{CKA_MODULUS, modulus, sizeof(modulus)}
  	};
	
	CK_ATTRIBUTE privateKeyTemplate[] = {
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_PRIVATE, &true, sizeof(true)},
	{CKA_CLASS, &priClass, sizeof(priClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
   	{CKA_ID, id, sizeof(id)},
    	{CKA_DECRYPT, &true, sizeof(true)},
    	{CKA_SIGN, &true, sizeof(true)},
	{CKA_EXTRACTABLE, &false, sizeof(false)},
	{CKA_SENSITIVE, &false, sizeof(false)}
	};
	
	CK_ATTRIBUTE publicKeyTemplate[] = {
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_CLASS, &priClass, sizeof(priClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    	{CKA_ENCRYPT, &true, sizeof(true)},
    	{CKA_VERIFY, &true, sizeof(true)},
    	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    	{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
	};  	

	CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_SESSION_HANDLE hSession[2];
	CK_OBJECT_HANDLE hPrivateKey, hPublicKey, hPrivateKey2, hPublicKey2, hCreateKey;

	CK_ATTRIBUTE template1[] = {
	{CKA_CLASS, NULL_PTR, 0}
	};

	rv = C_GetAttributeValue(hSession[1], hPublicKey, template1, 1);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_GetAttributeValue before calling C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_GetAttributeValue(CK_INVALID_HANDLE, hPublicKey, template1, 1);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_GetAttributeValue with invalid session handle"));


	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_GetAttributeValue(hSession[1], CK_INVALID_HANDLE, template1, 1);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, "Call to C_GetAttributeValue with invalid object handle" ));
			

			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));

			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hCreateKey);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a session public object"));
			
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 7, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GenerateKeyPair trying to generate a session private keys"));
			
			privateKeyTemplate[7] = (CK_ATTRIBUTE){CKA_EXTRACTABLE, &true, sizeof(true)};
			privateKeyTemplate[8] = (CK_ATTRIBUTE){CKA_SENSITIVE, &true, sizeof(true)};
			
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 7, privateKeyTemplate, 9, &hPublicKey2, &hPrivateKey2);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GenerateKeyPair trying to generate a session private keys"));
			privateKeyTemplate[7] = (CK_ATTRIBUTE){CKA_EXTRACTABLE, &false, sizeof(false)};
			privateKeyTemplate[8] = (CK_ATTRIBUTE){CKA_SENSITIVE, &false, sizeof(false)};

			rv = C_GetAttributeValue(hSession[1], hCreateKey, NULL_PTR, 0);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_GetAttributeValue with third argument NULL_PTR"));

			CK_ATTRIBUTE senTemplate[] = {
			{CKA_PRIME_1, NULL_PTR, 0}			
			};			

			rv = C_GetAttributeValue(hSession[1], hPrivateKey, senTemplate, 1);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_SENSITIVE, "Call to C_GetAttributeValue trying to get a non-extractable attribute"));

			
			sprintf(ret, "ulValueLen should be -1 but it is %d after calling C_GetAttributeValue trying to get a non-extractable attribute", (int)senTemplate[0].ulValueLen);
			assert2(behavior, message(((CK_LONG)senTemplate[0].ulValueLen) == -1, ret));
			
			senTemplate[0].ulValueLen == 0;

			rv = C_GetAttributeValue(hSession[1], hPrivateKey2, senTemplate, 1);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_SENSITIVE, "Call to C_GetAttributeValue trying to get a sensitive attribute"));

			
			sprintf(ret, "ulValueLen should be -1 but it is %d after calling C_GetAttributeValue trying to get a sensitive attribute", (int)senTemplate[0].ulValueLen);
			assert2(behavior, message(((CK_LONG)senTemplate[0].ulValueLen) == -1, ret));
			
			
			CK_ATTRIBUTE invalidTypeTemplate[] = {
			{CKA_CERTIFICATE_CATEGORY, NULL_PTR, 0}
			};
			
			rv = C_GetAttributeValue(hSession[1], hCreateKey, invalidTypeTemplate, 1);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_TYPE_INVALID, "Call to C_GetAttributeValue with template which specifies an invalid attribute type"));

			sprintf(ret, "ulValueLen should be -1 but it is %d after calling C_GetAttributeValue trying to get an invalid attribute type", (int)invalidTypeTemplate[0].ulValueLen);
			assert2(behavior, message(((CK_LONG)invalidTypeTemplate[0].ulValueLen) == -1, ret));


			rv = C_GetAttributeValue(hSession[1], hCreateKey, template1, 1);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to which tries to get CKA_CLASS attribute"));

			CK_ULONG len = template1[0].ulValueLen;
			template1[0].pValue = (CK_BYTE_PTR)malloc(len);
			template1[0].ulValueLen = 0;

			rv = C_GetAttributeValue(hSession[1], hCreateKey, template1, 1);
			assert2(behavior, verifyCode(rv, CKR_BUFFER_TOO_SMALL, "Call to C_GetAttributeValue with enough memory, but ulValueLen 0"));

			sprintf(ret, "ulValueLen should be -1 but it is %d after calling C_GetAttributeValue andng a CKR_BUFFER_TOO_SMALL error", (int)template1[0].ulValueLen);
			assert2(behavior, message(((CK_LONG)template1[0].ulValueLen) == -1, ret));
			
			template1[0].ulValueLen = len;

			rv = C_GetAttributeValue(hSession[1], hCreateKey, template1, 1);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetAttributeValue with enough memory and ulValueLen"));
			
			CK_OBJECT_CLASS_PTR result = (CK_OBJECT_CLASS_PTR)(template1[0].pValue);
			char class[100];
			getClassName(*result, class);
			sprintf(ret, "Result of C_GetAttributeValue does not have the right CKA_CLASS value(CKO_PUBLIC KEY), it has %s", class);
			assert2(behavior, message(*result == pubClass, ret));


			free(template1[0].pValue);
			template1[0].pValue = NULL_PTR;
			template1[0].ulValueLen = 0;
			

			CK_ATTRIBUTE partialTemplate[] = {
			{CKA_CLASS, NULL_PTR, 0},
			{CKA_PRIME_1, NULL_PTR, 0}
			};

			rv = C_GetAttributeValue(hSession[1], hPrivateKey2, partialTemplate, 2);
			sprintf(ret, "Call to C_GetAttributeValue with slotID(%d) of C_GetSlotList(CK_TRUE) y with flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, with un template que pide el atributo CKA_CLASS y un atributo sensible", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_SENSITIVE, "Call to C_GetAttributeValue trying to get CKA_CLASS and a sensitive attribute"));

			sprintf(ret, "ulValueLen(of sensitive attribute) should be -1 but it is %d after calling C_GetAttributeValue trying to get CKA_CLASS and a sensitive attribute", (int)partialTemplate[1].ulValueLen);
			assert2(behavior, message(((CK_LONG)partialTemplate[1].ulValueLen) == -1, ret));

			sprintf(ret, "ulValueLen(of CKA_CLASS) should be !=-1 and != 0 but it is %d after calling C_GetAttributeValue trying to get CKA_CLASS and a sensitive attribute", (int)slot);
			assert2(behavior, message(((CK_LONG)partialTemplate[0].ulValueLen) != -1 && ((CK_LONG)partialTemplate[0].ulValueLen) != 0, ret));

/////
			CK_ATTRIBUTE localTemplate[] = {
			{CKA_LOCAL, NULL_PTR, 0}
			};
			
			rv = C_GetAttributeValue(hSession[1], hCreateKey, localTemplate, 1);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetAttributeValue trying to get CKA_LOCAL attribute"));

			localTemplate[0].pValue = (CK_BYTE_PTR)malloc(localTemplate[0].ulValueLen);
			
			rv = C_GetAttributeValue(hSession[1], hCreateKey, localTemplate, 1);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetAttributeValue trying to get CKA_LOCAL attribute with enough memory and ulValueLen"));

			CK_BBOOL * result2 = (CK_BBOOL *)(localTemplate[0].pValue);
			assert2(behavior, message(*result2 == CK_FALSE, "CKA_LOCAL result of C_GetAttribute of a C_CreateObject object should be CK_FALSE"));


			free(localTemplate[0].pValue);
			localTemplate[0].pValue = NULL_PTR;
			localTemplate[0].ulValueLen = 0;


			rv = C_GetAttributeValue(hSession[1], hPublicKey, localTemplate, 1);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetAttributeValue trying to get CKA_LOCAL attribute"));

			localTemplate[0].pValue = (CK_BYTE_PTR)malloc(localTemplate[0].ulValueLen);
			
			rv = C_GetAttributeValue(hSession[1], hPublicKey, localTemplate, 1);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetAttributeValue trying to get CKA_LOCAL attribute with enough memory and ulValueLen"));

			result2 = (CK_BBOOL *)(localTemplate[0].pValue);
			assert2(behavior, message(*result2 == CK_TRUE, "CKA_LOCAL result of C_GetAttribute of a C_GenerateKeyPair object should be CK_TRUE"));


			free(localTemplate[0].pValue);
			localTemplate[0].pValue = NULL_PTR;
			localTemplate[0].ulValueLen = 0;
			
		}
	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));

	rv = C_GetAttributeValue(hSession[1], hPublicKey, template1, 1);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_GetAttributeValue after calling C_Finalize"));

	printlnLevel(showMessage, "End: test C_GetAttributeValue", level);
}


///
void stressGetAttributeValue(int level, int repetitions, int showMessage)
{

	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_GetAttributeValue", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testGetAttributeValue(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_GetAttributeValue", level);
	}

}


///
void testFindObjectsMechanism(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test Find Objects(C_FindObjects|Init|Final)", level);
	
	CK_RV rv;

	static CK_BYTE modulus[] = { 0xcb, 0x12, 0x9d, 0xba, 0x22, 0xfa, 0x2b, 0x33, 0x7e, 0x2a, 0x24, 0x65, 0x09, 0xa9,
                               0xfb, 0x41, 0x1a, 0x0e, 0x2f, 0x89, 0x3a, 0xd6, 0x97, 0x49, 0x77, 0x6d, 0x2a, 0x6e, 0x98,
                               0x48, 0x6b, 0xa8, 0xc4, 0x63, 0x8e, 0x46, 0x90, 0x70, 0x2e, 0xd4, 0x10, 0xc0, 0xdd, 0xa3,
                               0x56, 0xcf, 0x97, 0x2f, 0x2f, 0xfc, 0x2d, 0xff, 0x2b, 0xf2, 0x42, 0x69, 0x4a, 0x8c, 0xf1,
                               0x6f, 0x76, 0x32, 0xc8, 0xe1, 0x37, 0x52, 0xc1, 0xd1, 0x33, 0x82, 0x39, 0x1a, 0xb3, 0x2a,
                               0xa8, 0x80, 0x4e, 0x19, 0x91, 0xa6, 0xa6, 0x16, 0x65, 0x30, 0x72, 0x80, 0xc3, 0x5c, 0x84,
                               0x9b, 0x7b, 0x2c, 0x6d, 0x2d, 0x75, 0x51, 0x9f, 0xc9, 0x6d, 0xa8, 0x4d, 0x8c, 0x41, 0x41,
                               0x12, 0xc9, 0x14, 0xc7, 0x99, 0x31, 0xe4, 0xcd, 0x97, 0x38, 0x2c, 0xca, 0x32, 0x2f, 0xeb,
                               0x78, 0x37, 0x17, 0x87, 0xc8, 0x09, 0x5a, 0x1a, 0xaf, 0xe4, 0xc4, 0xcc, 0x83, 0xe3, 0x79,
                               0x01, 0xd6, 0xdb, 0x8b, 0xd6, 0x24, 0x90, 0x43, 0x7b, 0xc6, 0x40, 0x57, 0x58, 0xe4, 0x49,
                               0x2b, 0x99, 0x61, 0x71, 0x52, 0xf4, 0x8b, 0xda, 0xb7, 0x5a, 0xbf, 0xf7, 0xc5, 0x2a, 0x8b,
                               0x1f, 0x25, 0x5e, 0x5b, 0xfb, 0x9f, 0xcc, 0x8d, 0x1c, 0x92, 0x21, 0xe9, 0xba, 0xd0, 0x54,
                               0xf6, 0x0d, 0xe8, 0x7e, 0xb3, 0x9d, 0x9a, 0x47, 0xba, 0x1e, 0x45, 0x4e, 0xdc, 0xe5, 0x20,
                               0x95, 0xd8, 0xe5, 0xe9, 0x51, 0xff, 0x1f, 0x9e, 0x9e, 0x60, 0x3c, 0x27, 0x1c, 0xf3, 0xc7,
                               0xf4, 0x89, 0xaa, 0x2a, 0x80, 0xd4, 0x03, 0x5d, 0xf3, 0x39, 0xa3, 0xa7, 0xe7, 0x3f, 0xa9,
                               0xd1, 0x31, 0x50, 0xb7, 0x0f, 0x08, 0xa2, 0x71, 0xcc, 0x6a, 0xb4, 0xb5, 0x8f, 0xcb, 0xf7,
                               0x1f, 0x4e, 0xc8, 0x16, 0x08, 0xc0, 0x03, 0x8a, 0xce, 0x17, 0xd1, 0xdd, 0x13, 0x0f, 0xa3,
                               0xbe, 0xa3 };
	static CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
	static CK_ULONG modulusBits = 2048;
  	static CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;
	static CK_BBOOL true = CK_TRUE, false = CK_FALSE;
  	static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  	static CK_KEY_TYPE keyType = CKK_RSA;
	static CK_BYTE id[] = { 123 };

  	
  	CK_ATTRIBUTE pubTemplate[] = {
    	{CKA_CLASS, &pubClass, sizeof(pubClass)},
    	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_TOKEN, &true, sizeof(true)},  //2 	
	{CKA_ID, id, sizeof(id)},
    	{CKA_VERIFY, &true, sizeof(true)},
    	{CKA_ENCRYPT, &false, sizeof(false)},
	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
	{CKA_PRIVATE, &true, sizeof(true)},   //7
    	{CKA_MODULUS, modulus, sizeof(modulus)}
  	};


	CK_ATTRIBUTE privateKeyTemplate[] = {
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_PRIVATE, &true, sizeof(true)},
	{CKA_CLASS, &priClass, sizeof(priClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
   	{CKA_ID, id, sizeof(id)},
    	{CKA_DECRYPT, &true, sizeof(true)},
    	{CKA_SIGN, &true, sizeof(true)},
	{CKA_EXTRACTABLE, &false, sizeof(false)},
	{CKA_SENSITIVE, &false, sizeof(false)}
	};
	
	CK_ATTRIBUTE publicKeyTemplate[] = {
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_CLASS, &priClass, sizeof(priClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    	{CKA_ENCRYPT, &true, sizeof(true)},
    	{CKA_VERIFY, &true, sizeof(true)},
    	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    	{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
	};  	

	CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_OBJECT_HANDLE hPrivateKey, hPublicKey;

	
	
	CK_SESSION_HANDLE hSession[2];
	CK_OBJECT_HANDLE hObject[5];
	CK_OBJECT_HANDLE hReceiver[10];
	CK_ULONG returned;

	rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_FindObjectsInit before calling C_Initialize"));

	rv = C_FindObjects(hSession[1], &hReceiver[0], 1, &returned);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_FindObjects before calling C_Initialize"));	

	rv = C_FindObjectsFinal(hSession[1]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_FindObjectsFinal before calling C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_FindObjectsInit(CK_INVALID_HANDLE, NULL_PTR, 0);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_FindObjectsInit with invalid session handle"));

	rv = C_FindObjects(CK_INVALID_HANDLE, &hReceiver[0], 1, &returned);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_FindObjects with invalid session handle"));

	rv = C_FindObjectsFinal(CK_INVALID_HANDLE);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_FindObjectsFinal with invalid session handle"));



	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			
			////	
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));

			////

			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 1);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_FindObjectsInit with second argument NULL_PTR and third != 0"));

			if (rv == CKR_OK)
			{
				reinitFindObjects(slot, hSession);
			}

			
			rv = C_FindObjects(hSession[1], &hReceiver[0], 1, &returned);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_FindObjects before calling C_FindObjectsInit"));

			rv = C_FindObjectsFinal(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_FindObjectsFinal before calling C_FindObjectsInit"));

			//First 0 objects
			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsInit in R/W-user state getting all the objects"));

			rv = C_FindObjects(hSession[1], NULL_PTR, 1, &returned);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_FindObjects with second argument NULL_PTR"));

			rv = C_FindObjects(hSession[1], &hReceiver[0], 1, NULL_PTR);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_FindObjects with fourth argument NULL_PTR"));



			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_ACTIVE, "Call to C_FindObjectsInit with an initialized search"));


			rv = C_FindObjects(hSession[0], &hReceiver[0], 1, &returned);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_FindObjects with R/O session handle which has not initialized a search"));

			rv = C_FindObjectsFinal(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_FindObjectsFinal with R/O session handle which has not initialized a search"));
			
			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjects with 0 created objects"));

			
			sprintf(ret, "Found objects by C_FindObjects Mechanism should be 0 but it is %d", (int)returned);
			assert2(behavior, message(returned == 0, ret));


			rv = C_FindObjectsFinal(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsFinal"));

			rv = C_FindObjects(hSession[1], &hReceiver[0], 1, &returned);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_FindObjects after calling C_FindObjectsFnial"));

			rv = C_FindObjectsFinal(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_FindObjectsFinal after calling C_FindObjectsFinal"));

			
			//CREATE OBJECTS
			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[0]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a token private object"));
			//

			pubTemplate[2].pValue = &true;
			pubTemplate[2].ulValueLen = sizeof(true);
			pubTemplate[7].pValue = &false;
			pubTemplate[7].ulValueLen = sizeof(false);


			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a token public object"));

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[4]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a token public object"));

			//
			pubTemplate[2].pValue = &false;
			pubTemplate[2].ulValueLen = sizeof(false);
			pubTemplate[7].pValue = &true;
			pubTemplate[7].ulValueLen = sizeof(true);

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[2]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a session private object"));

			//

			pubTemplate[2].pValue = &false;
			pubTemplate[2].ulValueLen = sizeof(false);
			pubTemplate[7].pValue = &false;
			pubTemplate[7].ulValueLen = sizeof(false);

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[3]);
			sprintf(ret, "Call to C_CreateObject with sesion R/W abierta y logueada en normal user  n slotID(%d) of C_GetSlotList(CK_TRUE) y with flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a session public object"));

			//
			
			pubTemplate[2].pValue = &true;
			pubTemplate[2].ulValueLen = sizeof(true);
			pubTemplate[7].pValue = &true;
			pubTemplate[7].ulValueLen = sizeof(true);
			//CREATE OBJECTS(FIN)

			//CAP
			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsInit in R/W-user state getting all the objects"));

			//CAPCHECK NORMAL
			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjects in R/W-user state"));

			
			sprintf(ret, "Found objects by C_FindObjects Mechanism should be 5 but it is %d", (int)returned);
			assert2(behavior, message(returned == 5, ret));			



			rv = C_FindObjectsFinal(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsFinal"));


			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));
			
			rv = C_CloseSession(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_OK ,"Call to C_CloseSession with R/O session handle"));

			int ind = indexOfElem((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_SO user type"));

			//CAP
			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsInit in R/W-SO state getting all the objects"));

			//CAPCHECK SO
			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjects in R/W-SO state"));

			
			sprintf(ret, "Found objects by C_FindObjects Mechanism should be 3 but it is %d", (int)returned);
			assert2(behavior, message(returned == 3, ret));

			rv = C_FindObjectsFinal(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsFinal"));

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));


			//RESULT CHECK
			CK_ATTRIBUTE classTemplate[] = {
			{CKA_CLASS, &pubClass, sizeof(pubClass)}
			};
			rv = C_FindObjectsInit(hSession[1], classTemplate, 1);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsInit in R/W-public state getting objects which has CKA_CLASS CKO_PUBLIC_KEY"));

			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjects in R/W-public state"));

			
			sprintf(ret, "Found objects by C_FindObjects Mechanism should be 3 but it is %d", (int)returned);
			assert2(behavior, message(returned == 3, ret));

			rv = C_FindObjectsFinal(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsFinal"));
			

			classTemplate[0] = (CK_ATTRIBUTE){CKA_CLASS, &priClass, sizeof(priClass)};
			rv = C_FindObjectsInit(hSession[1], classTemplate, 1);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsInit in R/W-public state getting objects which has CKA_CLASS CKO_PRIVATE_KEY"));

			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjects in R/W-public state"));			

			sprintf(ret, "Found objects by C_FindObjects Mechanism should be 0 but it is %d", (int)returned);
			assert2(behavior, message(returned == 0, ret));

			rv = C_FindObjectsFinal(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsFinal"));			
	
			//REINIT
			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Call to C_CloseAllSessions with slotID(%d)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
			

			char * textLabel = "A token";
        		CK_UTF8CHAR paddedLabel[32];
        		memset(paddedLabel, ' ', sizeof(paddedLabel));
        		memcpy(paddedLabel, textLabel, strlen(textLabel));
	
			sprintf(ret, "Call to C_InitToken with slotID(%d)", (int)slot);
			rv = C_InitToken(slot, soPINs[ind], strlen(soPINs[ind]), paddedLabel);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_SO user type"));

			rv = C_InitPIN(hSession[1], userPIN, strlen(userPIN));
			sprintf(ret, "Call to C_InitPIN with a R/W session handle, second argument %s and third argument %d", (char *)userPIN, (int)strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));
			
			//CAP
			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsInit in R/W-public state getting all the objects"));


			//CAPCHECK REINIT
			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjects in R/W-public state"));

			
			sprintf(ret, "Found objects by C_FindObjects Mechanism should be 0(after reinit token) but it is %d", (int)returned);
			assert2(behavior, message(returned == 0, ret));
	
			rv = C_FindObjectsFinal(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_FindObjectsFinal"));
			
		}
	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));

	rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_FindObjectsInit after calling C_Finalize"));

	rv = C_FindObjects(hSession[1], &hReceiver[0], 1, &returned);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_FindObjects after calling C_Finalize"));


	rv = C_FindObjectsFinal(hSession[1]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_FindObjectsFinal after calling C_Finalize"));

	
	printlnLevel(showMessage, "End: test Find Objects(C_FindObjects|Init|Final)", level);
}

//
void reinitFindObjects(CK_SLOT_ID slot, CK_SESSION_HANDLE_PTR hSession)
{
			CK_RV rv;
			
			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Call to C_CloseAllSessions with slotID(%d)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));	
			
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			
			////	
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));

}


///
void reinitFindObjectsCreated(CK_SLOT_ID slot, CK_SESSION_HANDLE_PTR hSession, CK_OBJECT_HANDLE_PTR hObject, CK_ATTRIBUTE_PTR pubTemplate)
{
			CK_RV rv;
			CK_BBOOL false = CK_FALSE;
			CK_BBOOL true = CK_TRUE;			
			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Call to C_CloseAllSessions with slotID(%d)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
			

			char * textLabel = "A token";
        		CK_UTF8CHAR paddedLabel[32];
        		memset(paddedLabel, ' ', sizeof(paddedLabel));
        		memcpy(paddedLabel, textLabel, strlen(textLabel));
	
			int ind = indexOfElem((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
			sprintf(ret, "Call to C_InitToken with slotID(%d)", (int)slot);
			rv = C_InitToken(slot, soPINs[ind], strlen(soPINs[ind]), paddedLabel);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_SO user type"));

			rv = C_InitPIN(hSession[1], userPIN, strlen(userPIN));
			sprintf(ret, "Call to C_InitPIN with a R/W session handle, second argument %s and third argument %d", (char *)userPIN, (int)strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));

			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));

			pubTemplate[2].pValue = &true;
			pubTemplate[2].ulValueLen = sizeof(true);
			pubTemplate[7].pValue = &false;
			pubTemplate[7].ulValueLen = sizeof(false);


			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a token public object"));

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[4]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a token public object"));

			//
			pubTemplate[2].pValue = &false;
			pubTemplate[2].ulValueLen = sizeof(false);
			pubTemplate[7].pValue = &true;
			pubTemplate[7].ulValueLen = sizeof(true);

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[2]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a session private object"));

			//

			pubTemplate[2].pValue = &false;
			pubTemplate[2].ulValueLen = sizeof(false);
			pubTemplate[7].pValue = &false;
			pubTemplate[7].ulValueLen = sizeof(false);

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[3]);
			sprintf(ret, "Call to C_CreateObject with sesion R/W abierta y logueada en normal user  n slotID(%d) of C_GetSlotList(CK_TRUE) y with flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_CreateObject trying to create a session public object"));

			//
			
			pubTemplate[2].pValue = &true;
			pubTemplate[2].ulValueLen = sizeof(true);
			pubTemplate[7].pValue = &true;
			pubTemplate[7].ulValueLen = sizeof(true);

}

///
void stressFindObjectsMechanism(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress Find Objects(C_FindObjects|Init|Final)", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testFindObjectsMechanism(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress Find Objects(C_FindObjects|Init|Final)", level);
	}
}
///Test of crypto mechanisms
void testMechanisms(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test of crypto mechanisms", level);
	testSignMechanism(level + 1, showMessage);
	stressSignMechanism(level + 1, repetitions, showMessage);
	testDigestMechanism(level + 1, showMessage);
	stressDigestMechanism(level + 1, repetitions, showMessage);
	printlnLevel(showMessage, "End: test of crypto mechanisms", level);
}

///
void testSignMechanism(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test Sign(C_Sign|Init)", level);
	CK_RV rv;
	static CK_ULONG modulusBits = 768;
  	static CK_BBOOL true = CK_TRUE, false = CK_FALSE;
  	static CK_OBJECT_CLASS pubClass = CKO_PUBLIC_KEY;
  	static CK_OBJECT_CLASS priClass = CKO_PRIVATE_KEY;
	static CK_OBJECT_CLASS secClass = CKO_SECRET_KEY;
  	static CK_KEY_TYPE keyType = CKK_RSA;
	static CK_KEY_TYPE secretKeyType = CKK_DES;
	static CK_BYTE id[] = { 123 };
	static CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
	static CK_BYTE value[8] = "aVALUEEE";


	CK_ATTRIBUTE secretTemplate[] = {
    	{CKA_CLASS, &secClass, sizeof(secClass)},
    	{CKA_KEY_TYPE, &secretKeyType, sizeof(secretKeyType)},
    	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_PRIVATE, &true, sizeof(true)},
    	{CKA_VALUE, &value, sizeof(value)}
  	};

	CK_ATTRIBUTE privateKeyTemplate[] = {
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_PRIVATE, &true, sizeof(true)},
	{CKA_CLASS, &priClass, sizeof(priClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
   	{CKA_ID, id, sizeof(id)},
    	{CKA_SENSITIVE, &false, sizeof(false)},
	{CKA_EXTRACTABLE, &true, sizeof(true)},
	{CKA_DECRYPT, &true, sizeof(true)},
    	{CKA_SIGN, &true, sizeof(true)},
    	{CKA_UNWRAP, &true, sizeof(true)}
    	
  	};
		
	CK_ATTRIBUTE privateKeyTemplateNoSign[] = {
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_PRIVATE, &true, sizeof(true)},
	{CKA_CLASS, &priClass, sizeof(priClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
   	{CKA_ID, id, sizeof(id)},
    	{CKA_SENSITIVE, &true, sizeof(true)},
    	{CKA_DECRYPT, &true, sizeof(true)},
    	{CKA_SIGN, &false, sizeof(false)},
    	{CKA_UNWRAP, &true, sizeof(true)}
    	
  	};
	
	CK_ATTRIBUTE publicKeyTemplate[] = {
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_PRIVATE, &true, sizeof(true)},
	{CKA_CLASS, &priClass, sizeof(priClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    	{CKA_ENCRYPT, &true, sizeof(true)},
    	{CKA_VERIFY, &true, sizeof(true)},
    	{CKA_WRAP, &true, sizeof(true)},
    	{CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    	{CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  	};  

	
	
	CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
	CK_SESSION_HANDLE hSession[2];
	CK_OBJECT_HANDLE hPrivateKey, hPrivateNoSignKey, hPublicKey, hPublicNoSignKey, hSecretKey;
	
	CK_BYTE otherPublicValue[128];
	CK_MECHANISM signMechanism [] = {
	{0x9999, NULL_PTR, 0},//INVALID MECHANISM
	{CKM_RSA_PKCS, otherPublicValue, sizeof(otherPublicValue)},//MECHANISM PARAM INVALID
	{CKM_RSA_PKCS, NULL_PTR, 0},
	{CKM_SHA1_RSA_PKCS, NULL_PTR, 0}
	};
	CK_ULONG maxInput[4] = {0, 0, modulusBits/8 - 11, 0}; // If 0 does not test
	CK_ULONG lengths [4] = {0, 0, modulusBits/8, modulusBits/8};
	CK_ULONG n = 4;
	CK_BYTE_PTR data = "Some data";
	CK_ULONG signatureLen;
		
	rv = C_SignInit(hSession[1], &signMechanism[2], hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_SignInit before calling C_Initialize"));

	rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_Sign before calling C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_SignInit(CK_INVALID_HANDLE, &signMechanism[2], hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_SignInit with invalid session handle"));

	rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_Sign with invalid session handle"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	int signInitialized;
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));
			//____
			//Create Keys
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 10, &hPublicKey, &hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GenerateKeyPair in R/W-user state"));

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplateNoSign, 9, &hPublicNoSignKey, &hPrivateNoSignKey);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GenerateKeyPair in R/W-user state"));


			rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_Sign before calling C_SignInit"));
			
			rv = C_SignInit(hSession[1], &signMechanism[2], CK_INVALID_HANDLE);
			assert2(behavior, verifyCode(rv, CKR_KEY_HANDLE_INVALID, "Call to C_SignInit with invalid key handle"));
			
///
			if (rv == CKR_OK)
			{
				reinitSign(slot, hSession, mechanism, publicKeyTemplate, privateKeyTemplate, privateKeyTemplateNoSign, &hPublicKey, &hPrivateKey, &hPublicNoSignKey, &hPrivateNoSignKey);
			}
///

			rv = C_SignInit(hSession[1], NULL_PTR, hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_SignInit with second argument NULL_PTR"));
///
			if (rv == CKR_OK)
			{
				reinitSign(slot, hSession, mechanism, publicKeyTemplate, privateKeyTemplate, privateKeyTemplateNoSign, &hPublicKey, &hPrivateKey, &hPublicNoSignKey, &hPrivateNoSignKey);
			}
///			

			rv = C_SignInit(hSession[1], &signMechanism[0], hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_INVALID, "Call to C_SignInit with invalid sign mehanism"));
///
			if (rv == CKR_OK)
			{
				reinitSign(slot, hSession, mechanism, publicKeyTemplate, privateKeyTemplate, privateKeyTemplateNoSign, &hPublicKey, &hPrivateKey, &hPublicNoSignKey, &hPrivateNoSignKey);
			}
///
			
			rv = C_SignInit(hSession[1], &signMechanism[1], hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_PARAM_INVALID, "Call to C_SignInit with valid mechanism but an invalid paremeter"));
///
			if (rv == CKR_OK)
			{
				reinitSign(slot, hSession, mechanism, publicKeyTemplate, privateKeyTemplate, privateKeyTemplateNoSign, &hPublicKey, &hPrivateKey, &hPublicNoSignKey, &hPrivateNoSignKey);
			}
///
			
			rv = C_SignInit(hSession[1], &signMechanism[2], hPrivateNoSignKey);
			assert2(behavior, verifyCode(rv, CKR_KEY_FUNCTION_NOT_PERMITTED, "Call to C_SignInit with key which has CKA_SIGN false"));
///
			if (rv == CKR_OK)
			{
				reinitSign(slot, hSession, mechanism, publicKeyTemplate, privateKeyTemplate, privateKeyTemplateNoSign, &hPublicKey, &hPrivateKey, &hPublicNoSignKey, &hPrivateNoSignKey);
			}
///
			rv = C_SignInit(hSession[1], &signMechanism[2], hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_SignInit in R/W-user state"));


			rv = C_SignInit(hSession[1], &signMechanism[2], hPrivateKey);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_ACTIVE, "Call to C_SignInit with a previus call to C_SignInit"));


			rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, NULL_PTR);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Sign with fourth argument NULL_PTR"));

			rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_Sign after a wrong call to C_Sign"));
			
			if(rv == CKR_OPERATION_NOT_INITIALIZED)
			{			
				rv = C_SignInit(hSession[1], &signMechanism[2], hPrivateKey);
				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_SignInit after a wrong call to C_Sign"));
			}

			rv = C_Sign(hSession[0], data, strlen(data), NULL_PTR, &signatureLen);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_Sign with a session which has not initiailized a Sign"));

			rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
    			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Sign in R/W-user state"));
			
			CK_BYTE_PTR pSignature = (CK_BYTE_PTR)malloc(signatureLen*sizeof(CK_BYTE));

			signatureLen = 0;
			rv = C_Sign(hSession[1], data, strlen(data), pSignature, &signatureLen);
    			assert2(behavior, verifyCode(rv, CKR_BUFFER_TOO_SMALL, "Call to C_Sign with enough memory but signatureLen 0"));

			rv = C_Sign(hSession[1], data, strlen(data), pSignature, &signatureLen);
    			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Sign after a CKR_BUFFER_TOO_SMALL return code of C_Sign"));

			rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
    			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_Sign after a finished call to C_Sign"));


			free(pSignature);

			//COMPROBACIONES(with the first and then call succesfully)

			//TEST DE RESULTADOS
			int j;
			for(j = 2; j < n; ++j)
			{
				char meca [100];
				getMechanismName((signMechanism[j].mechanism), meca);
				
				rv = C_SignInit(hSession[1], &signMechanism[j], hPrivateKey);
				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_SignInit with R/W-user state"));
				if (maxInput[j])
				{
					CK_BYTE maxData[maxInput[j] + 1];
					rv = C_Sign(hSession[1], maxData, maxInput[j] + 1, NULL_PTR, &signatureLen);
    					sprintf(ret, "Call to C_Sign, with a data which has 1 more char than let for the mechanism(%s)", meca);	
					assert2(behavior, verifyCode(rv, CKR_DATA_LEN_RANGE, ret));	
					if(rv == CKR_DATA_LEN_RANGE)
					{						
						rv = C_SignInit(hSession[1], &signMechanism[j], hPrivateKey);
						assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_SignInit after a wrong call to C_Sign"));
					}
					
				}

				rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
    				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Sign with R/W-user state"));
				
				if (lengths[j])
				{	
					sprintf(ret, "signatreLen of C_Sign of mechanism %s, should be %d, but it is %d", meca, (int)(lengths[j]), (int)signatureLen);
					assert2(behavior, message(signatureLen == lengths[j],ret));				
				}

				pSignature = (CK_BYTE_PTR)malloc(signatureLen*sizeof(CK_BYTE));
				
				rv = C_Sign(hSession[1], data, strlen(data), pSignature, &signatureLen);
	    			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Sign with R/W-user state"));

				if(j == 2)
				{
					

					CK_BYTE_PTR modulo;
					CK_BYTE_PTR exponentePublico;
					CK_BYTE_PTR exponentePrivado;
					
					CK_ATTRIBUTE temp[] = {
					{CKA_MODULUS, NULL_PTR, 0},
					{CKA_PUBLIC_EXPONENT, NULL_PTR,0},
					{CKA_PRIVATE_EXPONENT, NULL_PTR,0}
					};
					
					rv = C_GetAttributeValue(hSession[1], hPrivateKey, temp, 3);
					assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetAttributeValue trying to get the CKA_MODULUS, CKA_PUBLIC_EXPONENT and CKA_PRIVATE_EXPONENT(from an extractable and non sensitive RSA private key)"));					
	
					
					modulo = (CK_BYTE_PTR)malloc(temp[0].ulValueLen);
					exponentePublico = (CK_BYTE_PTR)malloc(temp[1].ulValueLen);
					exponentePrivado = (CK_BYTE_PTR)malloc(temp[2].ulValueLen);

					temp[0].pValue = modulo;
					temp[1].pValue = exponentePublico;
					temp[2].pValue = exponentePrivado;

					rv = C_GetAttributeValue(hSession[1], hPrivateKey, temp, 3);
					assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetAttributeValue trying to get the CKA_MODULUS, CKA_PUBLIC_EXPONENT and CKA_PRIVATE_EXPONENT(from an extractable and non sensitive RSA private key)"));					
					
					int r;
					unsigned char * signature = malloc(2048/8*sizeof(unsigned char));
	
					RSA * rsa = RSA_new();
	
					BIGNUM * modul = BN_new();
					BIGNUM * expon = BN_new();    	
					BIGNUM * pexpon = BN_new();

				    	BN_bin2bn(modulo, temp[0].ulValueLen, modul);
					BN_bin2bn(exponentePublico, temp[1].ulValueLen, expon);
					BN_bin2bn(exponentePrivado, temp[2].ulValueLen, pexpon);

					rsa->n = modul;
					rsa->e = expon;
					rsa->d = pexpon;
					
					r = RSA_private_encrypt(strlen(data),data,signature,rsa,RSA_PKCS1_PADDING);
										
					if (r == 0)
					{
						unsigned long err = ERR_get_error();
						ERR_load_crypto_strings();
						char message[500];
						printf("OpenSSL error\n");
						ERR_error_string(err,message);
						printf("\n%s\n",message);
						ERR_free_strings();	
						exit(0);	
					}
					else
					{
						assert2(behavior, message(strncmp(pSignature, signature, signatureLen) == 0,"Result of C_Sign should be same than the equivalent result in OpenSSL"));				
					}
					free(modulo);
					free(exponentePublico);
					free(exponentePrivado);
					free(signature);
					RSA_free(rsa);
				}


				//Es funcion?
				CK_BYTE_PTR pSignature2;

				rv = C_SignInit(hSession[1], &signMechanism[j], hPrivateKey);
				assert2(behavior, verifyCode(rv, CKR_OK,  "Call to C_SignInit with R/W-user state"));

				rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
    				assert2(behavior, verifyCode(rv, CKR_OK,  "Call to C_Sign with R/W-user state"));
				
				pSignature2 = (CK_BYTE_PTR)malloc(signatureLen*sizeof(CK_BYTE));
				
				rv = C_Sign(hSession[1], data, strlen(data), pSignature2, &signatureLen);
	    			assert2(behavior, verifyCode(rv, CKR_OK,  "Call to C_Sign with R/W-user state"));
				
				sprintf(ret, "Apply 2 times the C_Sign mechanism(%s) does not return the same result", meca);
				assert2(behavior, message(strncmp(pSignature, pSignature2, signatureLen) == 0,ret));

				free(pSignature);
				free(pSignature2);
			}			


			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));
			
			rv = C_CloseSession(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_OK ,"Call to C_CloseSession with a R/O session handle"));
		}
	}
	free(buffer);
	
	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));

	rv = C_SignInit(hSession[1], &signMechanism[0], hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_SignInit after calling C_Finalize"));

	rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_Sign after calling C_Finalize"));

	printlnLevel(showMessage, "End: test Sign(C_Sign|Init)", level);
}

//Reinti a sign mechanism after a SignInit error happens
void reinitSign(CK_SLOT_ID slot, CK_SESSION_HANDLE_PTR hSession, CK_MECHANISM mechanism, CK_ATTRIBUTE_PTR publicKeyTemplate, CK_ATTRIBUTE_PTR privateKeyTemplate, CK_ATTRIBUTE_PTR privateKeyTemplateNoSign, CK_OBJECT_HANDLE_PTR pHPublicKey, CK_OBJECT_HANDLE_PTR pHPrivateKey, CK_OBJECT_HANDLE_PTR pHPublicNoSignKey, CK_OBJECT_HANDLE_PTR pHPrivateNoSignKey)
{
		CK_RV rv;
		rv = C_CloseAllSessions(slot);
		sprintf(ret, "Call to C_CloseAllSessions with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK ,ret));				

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
		sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
		assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 10, pHPublicKey, pHPrivateKey);
		assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GenerateKeyPair in R/W-user state"));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplateNoSign, 9, pHPublicNoSignKey, pHPrivateNoSignKey);
		assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GenerateKeyPair in R/W-user state"));
}


///
void stressSignMechanism(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress Sign(C_Sign|Init)", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testSignMechanism(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress Sign(C_Sign|Init)", level);
	}
}


///ACA VOY
void testDigestMechanism(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test Digest(C_Digest|Init)", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	
	CK_BYTE otherPublicValue[128];
	CK_MECHANISM digestMechanism [] = {
	{0x9999, NULL_PTR, 0},//INVALID MECHANISM
	{CKM_MD5, otherPublicValue, sizeof(otherPublicValue)},//MECHANISM PARAM INVALID
	{CKM_MD5, NULL_PTR, 0},
	{CKM_SHA_1, NULL_PTR, 0},
	{CKM_SHA256, NULL_PTR, 0},
	{CKM_SHA384, NULL_PTR, 0},
	{CKM_SHA512, NULL_PTR, 0}
	};

	CK_ULONG lengths [7] = {0, 0, 16, 20, 32, 48, 64};
	CK_ULONG n = 7;

	CK_BYTE_PTR data = "Some data";
	CK_ULONG digestLen;
		
	rv = C_DigestInit(hSession[1], &digestMechanism[2]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_DigestInit before calling C_Initialize "));

	rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_Digest before calling C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_DigestInit(CK_INVALID_HANDLE, &digestMechanism[2]);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_DigestInit with invalid session handle"));

	rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_Digest with invalid session handle"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));
			//____
			
			rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_Digest before calling C_DigestInit"));

			rv = C_DigestInit(hSession[1], NULL_PTR);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_DigestInit with second argument NULL_PTR"));
///
			if (rv == CKR_OK)
			{
				reinitDigest(slot, hSession);
			}
///
			rv = C_DigestInit(hSession[1], &digestMechanism[0]);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_INVALID, "Call to C_DigestInit with invalid mechanism"));
			
///
			if (rv == CKR_OK)
			{
				reinitDigest(slot, hSession);
			}
///

			rv = C_DigestInit(hSession[1], &digestMechanism[1]);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_PARAM_INVALID, "Call to C_DigestInit with a valid mechanism but invalid parameter"));

///
			if (rv == CKR_OK)
			{
				reinitDigest(slot, hSession);
			}
///

			rv = C_DigestInit(hSession[1], &digestMechanism[2]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_DigestInit with R/W-user state"));


			rv = C_DigestInit(hSession[1], &digestMechanism[2]);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_ACTIVE, "Call to C_DigestInit after calling C_DigestInit"));
			
			rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, NULL_PTR);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Call to C_Digest with fourth argument NULL_PTR"));

			rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_Digest after a wrong call to C_Digest"));
			
			if (rv == CKR_OPERATION_NOT_INITIALIZED)
			{
				rv = C_DigestInit(hSession[1], &digestMechanism[2]);
				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_DigestInit after a wrong call to C_Sign"));
			}			

			rv = C_Digest(hSession[0], data, strlen(data), NULL_PTR, &digestLen);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_Digest with a session which has not initialized a Digest"));

			rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
    			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Digest in R/W-user state"));

			CK_BYTE_PTR pDigest = (CK_BYTE_PTR)malloc(digestLen*sizeof(CK_BYTE));

			digestLen = 0;
			rv = C_Digest(hSession[1], data, strlen(data), pDigest, &digestLen);
    			assert2(behavior, verifyCode(rv, CKR_BUFFER_TOO_SMALL, "Call to C_Digest with enough memory but digestLen 0"));

			
			rv = C_Digest(hSession[1], data, strlen(data), pDigest, &digestLen);
    			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Digest after a CKR_BUFFER_TOO_SMALL return code of C_Digest"));

			rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
    			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, "Call to C_Digest after a finished call to C_Digest"));
			free(pDigest);

			//TEST DE RESULTADOS
			int j;
			for(j = 2; j < n; ++j)
			{
				char meca [100];
				getMechanismName((digestMechanism[j].mechanism), meca);
				rv = C_DigestInit(hSession[1], &digestMechanism[j]);
				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_DigestInit with R/W-user state"));

				rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
    				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Digest with R/W-user state"));

				sprintf(ret, "digestLen of C_Digest of mechanism %s, should be %d, but it is %d", meca, (int)(lengths[j]), (int)digestLen);
				assert2(behavior, message(digestLen == lengths[j], ret));				
				
				pDigest = (CK_BYTE_PTR)malloc(digestLen*sizeof(CK_BYTE));
				
				rv = C_Digest(hSession[1], data, strlen(data), pDigest, &digestLen);
	    			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Digest with R/W-user state"));

				//Es funcion?
				CK_BYTE_PTR pDigest2;

				rv = C_DigestInit(hSession[1], &digestMechanism[j]);
				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_DigestInit with R/W-user state"));

				rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
    				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Digest with R/W-user state"));
				//ACA VOY
				pDigest2 = (CK_BYTE_PTR)malloc(digestLen*sizeof(CK_BYTE));
				
				rv = C_Digest(hSession[1], data, strlen(data), pDigest2, &digestLen);
	    			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Digest with R/W-user state"));
				
				sprintf(ret, "Apply 2 times the C_Digest mechanism(%s) does not return the same result", meca);
				assert2(behavior, message(strncmp(pDigest, pDigest2, digestLen) == 0,ret));
				if ( j == 2) //MD5
				{
					unsigned char obuf[16];
					MD5(data, strlen(data), obuf);
					sprintf(ret, "Result of C_Digest(%s) should be same than the equivalent result in OpenSSL", meca);
					assert2(behavior, message(strncmp(pDigest, obuf, digestLen) == 0,ret));

				}
				if (j == 3) //SHA1
				{
					unsigned char obuf[20];
					SHA1(data, strlen(data), obuf);
					sprintf(ret, "Result of C_Digest(%s) should be same than the equivalent result in OpenSSL", meca);
					assert2(behavior, message(strncmp(pDigest, obuf, digestLen) == 0,ret));
					
				}
				free(pDigest);
				free(pDigest2);
			}
			
			

			rv = C_Logout(hSession[1]);
			assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Logout"));
			
			rv = C_CloseSession(hSession[0]);
			assert2(behavior, verifyCode(rv, CKR_OK ,"Call to C_CloseSession with R/O session handle"));
		}
	}
	free(buffer);
	
	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));

	rv = C_DigestInit(hSession[1], &digestMechanism[0]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_DigestInit after calling C_Finalize"));

	rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_Digest after calling C_Finalize"));

	printlnLevel(showMessage, "End: test Digest(C_Digest|Init)", level);
}

void reinitDigest(CK_SLOT_ID slot, CK_SESSION_HANDLE_PTR hSession)
{
		CK_RV rv;
		rv = C_CloseAllSessions(slot);
		sprintf(ret, "Call to C_CloseAllSessions with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK ,ret));				

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
		sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
		assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));
}

///
void stressDigestMechanism(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress Digest(C_Digest|Init)", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testDigestMechanism(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress Digest(C_Digest|Init)", level);
	}
}

//Test of random functions
//Son C_SeedRandom y C_GenerateRandom
void testRNGFunctions(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test of random functions", level);
	testSeedRandom(level + 1, showMessage);
	stressSeedRandom(level + 1, repetitions, showMessage);

	testGenerateRandom(level + 1, showMessage);
	stressGenerateRandom(level + 1, repetitions, showMessage);

	printlnLevel(showMessage, "End: test of random functions", level);

}

///
void testSeedRandom(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_SeedRandom", level);
	
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	CK_BYTE seed[] = {"Some random data"};
	
	rv = C_SeedRandom(hSession[0], seed, strlen(seed));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_SeedRandom before calling C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_SeedRandom(CK_INVALID_HANDLE, seed, strlen(seed));
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_SeedRandom with an invalid session handle"));	

	
	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			if((infoToken.flags & CKF_RNG))
			{

				rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));
				//____
				
				rv = C_SeedRandom(hSession[1], NULL_PTR, 0);
				assert2(behavior, verifyCode2(rv,  CKR_ARGUMENTS_BAD, CKR_RANDOM_SEED_NOT_SUPPORTED, "Call to C_SeedRandom with second argument NULL_PTR"));

				
				rv = C_SeedRandom(hSession[1], seed, strlen(seed));
				assert2(behavior, verifyCode2(rv,  CKR_OK, CKR_RANDOM_SEED_NOT_SUPPORTED, "Call to C_SeedRandom in R/W-user state"));
			
				rv = C_SeedRandom(hSession[0], seed, strlen(seed));
				assert2(behavior, verifyCode2(rv,  CKR_OK, CKR_RANDOM_SEED_NOT_SUPPORTED, "Call to C_SeedRandom in R/O-user state"));
			}
			else
			{
				rv = C_SeedRandom(hSession[1], seed, strlen(seed));
				sprintf(ret, "Call to C_SeedRandom in R/W-user state with slotID(%d) which does not CKF_RNG flag", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_RANDOM_NO_RNG, ret));
			
				rv = C_SeedRandom(hSession[0], seed, strlen(seed));
				sprintf(ret, "Call to C_SeedRandom in R/W-user state with slotID(%d) which does not CKF_RNG flag", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_RANDOM_NO_RNG, ret));
			}
		}
	}
	free(buffer);

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	rv = C_SeedRandom(hSession[1], seed, strlen(seed));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_SeedRandom after calling C_Finalize"));

	printlnLevel(showMessage, "End: test C_SeedRandom", level);
}


void stressSeedRandom(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_SeedRandom", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testSeedRandom(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_SeedRandom", level);
	}

}

///ACA VOY
void testGenerateRandom(int level, int showMessage)
{
	printlnLevel(showMessage, "Start: test C_GenerateRandom", level);
	
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	CK_BYTE randomData[40];
	
	rv = C_GenerateRandom(hSession[0], randomData, 40);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_GenerateRandom before calling C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Initialize with NULL_PTR"));

	rv = C_GenerateRandom(CK_INVALID_HANDLE, randomData, 40);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Call to C_GenerateRandom with an invalid session handle"));	
	
	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Call to C_GetTokenInfo with slotID(%d)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/W session", (int)slot);
			assert2(behavior, verifyCode(rv,  CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Call to C_OpenSession with slotID(%d) trying to open a R/O session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			if((infoToken.flags & CKF_RNG))
			{

				rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Login with CKU_USER user type"));
				//____
				
				rv = C_GenerateRandom(hSession[1], NULL_PTR, 0);
				assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD , "Call to C_GenerateRandom with second argument NULL_PTR"));

				
				rv = C_GenerateRandom(hSession[1], randomData, 40);
				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GenerateRandom in R/W-user state"));
			
				rv = C_GenerateRandom(hSession[0], randomData, 40);
				assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GenerateRandom in R/W-user state"));

				//LITTLE TEST OF RANDOMESS
				
				int thereIsRepetition = 0;
				int j;
				int repetitions = 10;
				for(j = 0; j < repetitions-1; ++j)
				{
					CK_BYTE otherRandomData[40];
					rv = C_GenerateRandom(hSession[1], otherRandomData, 40);
					assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_GenerateRandom in R/W-user state"));

					thereIsRepetition = thereIsRepetition ||  (strcmp((char *)randomData, (char *)otherRandomData) == 0);
				}

				sprintf(ret, "%d calls to C_GenerateRandom in R/W state always returns the same value",repetitions);
				assert2(behavior, message(!thereIsRepetition, ret));
				
				//LITTLE TEST OF RANDOMESS
			}
			else
			{
				rv = C_GenerateRandom(hSession[1], randomData, 40);
				sprintf(ret, "Call to C_GenerateRandom in R/W-user state with slotID(%d) which does not CKF_RNG flag", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_RANDOM_NO_RNG, ret));
			
				rv = C_GenerateRandom(hSession[0], randomData, 40);
				sprintf(ret, "Call to C_GenerateRandom in R/W-user state with slotID(%d) which does not CKF_RNG flag", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_RANDOM_NO_RNG, ret));
			}
		}
	}
	free(buffer);

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Call to C_Finalize with NULL_PTR"));
	
	
	rv = C_GenerateRandom(hSession[1], randomData, 40);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Call to C_GenerateRandom after calling C_Finalize"));

	printlnLevel(showMessage, "End: test C_GenerateRandom", level);

}

///
void stressGenerateRandom(int level, int repetitions, int showMessage)
{
	if(repetitions)
	{	
		printlnLevel(showMessage, "Start: stress C_GenerateRandom", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repetitions; ++i)
		{
			testGenerateRandom(level + 1, 0);
		}

		printlnLevel(showMessage, "End: stress C_GenerateRandom", level);
	}
}

