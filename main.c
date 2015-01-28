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
int repeticiones;

//Main; metodo invocado al ejecutar testPKCS11
int main(int argc, char **argv)
{
	// Propio de SoftHSM
	#ifdef WIN32
  	_putenv("SOFTHSM_CONF=./softhsm.conf");
	#else
	setenv("SOFTHSM_CONF", "./softhsm.conf", 1);
	#endif
	//Propio de SoftHSM

	repeticiones = 0;
	showMessage = 1;

	if (argc < 4)
	{
		printf("\nSe debe especificar la ubicacion del archivo .so \n\nseguido de \"n\", el numero de slots de la libreria, \n\nseguido de una o mas opciones\n(-f(FAIL) indica que el test se detiene si ocurre un error durante la ejecucion, -a(ASK) indica que se le pregunta al usuario cada vez que haya un error en la ejecucion, -p(PASS) indica que el test se ejecuta completo independiente de errores en las ejecucion, -r(REPEAT) indica que se solicita hacer tests de esfuerzo, -h(HIDE) indica que no se impriman informes de avance del test\n\n seguido de \"n(>0)\" pares SLOT TIPO, \ndonde SLOT es el id del slot y TIPO el tipo de slot, siendo posibles NOTOKEN, NOINIT o un numero, el cual representa el PIN del security officer de un token inicializado\n");
		printf("Ejemplo: Usando la libreria de softhsm en modo PASS, ocultando la informacion de avance, con 3 slot(0 no tiene token, el 1 tiene PIN 12345678 y el 2 no esta inicializado)\n");
		printf("./testPKCS11 -ph /usr/lib/softhsm/libsofthsm.so 3 0 NOTOKEN 1 12345678 2 NOINIT\n");
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
				repeticiones = 3;
			break;
			case 'h':
				showMessage = 0;
			break;
			default :
				printf("\nSe debe especificar la ubicacion del archivo .so \n\nseguido de \"n\", el numero de slots de la libreria, \n\nseguido de una o mas opciones\n(-f(FAIL) indica que el test se detiene si ocurre un error durante la ejecucion, -a(ASK) indica que se le pregunta al usuario cada vez que haya un error en la ejecucion, -p(PASS) indica que el test se ejecuta completo independiente de errores en las ejecucion, -r(REPEAT) indica que se solicita hacer tests de esfuerzo, -h(HIDE) indica que no se impriman informes de avance del test\n\n seguido de \"n(>0)\" pares SLOT TIPO, \ndonde SLOT es el id del slot y TIPO el tipo de slot, siendo posibles NOTOKEN, NOINIT o un numero, el cual representa el PIN del security officer de un token inicializado\n");
				printf("Ejemplo: Usando la libreria de softhsm en modo PASS, ocultando la informacion de avance, con 3 slot(0 no tiene token, el 1 tiene PIN 12345678 y el 2 no esta inicializado)\n");
				printf("./testPKCS11 -ph /usr/lib/softhsm/libsofthsm.so 3 0 NOTOKEN 1 12345678 2 NOINIT\n");
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
				printf("\nSe debe especificar la ubicacion del archivo .so \n\nseguido de \"n\", el numero de slots de la libreria, \n\nseguido de una o mas opciones\n(-f(FAIL) indica que el test se detiene si ocurre un error durante la ejecucion, -a(ASK) indica que se le pregunta al usuario cada vez que haya un error en la ejecucion, -p(PASS) indica que el test se ejecuta completo independiente de errores en las ejecucion, -r(REPEAT) indica que se solicita hacer tests de esfuerzo, -h(HIDE) indica que no se impriman informes de avance del test\n\n seguido de \"n(>0)\" pares SLOT TIPO, \ndonde SLOT es el id del slot y TIPO el tipo de slot, siendo posibles NOTOKEN, NOINIT o un numero, el cual representa el PIN del security officer de un token inicializado\n");
				printf("Ejemplo: Usando la libreria de softhsm en modo PASS, ocultando la informacion de avance, con 3 slot(0 no tiene token, el 1 tiene PIN 12345678 y el 2 no esta inicializado)\n");
				printf("./testPKCS11 -ph /usr/lib/softhsm/libsofthsm.so 3 0 NOTOKEN 1 12345678 2 NOINIT\n");
				exit(1);
			}
		}
	}
	else
	{
			printf("\nSe debe especificar la ubicacion del archivo .so \n\nseguido de \"n\", el numero de slots de la libreria, \n\nseguido de una o mas opciones\n(-f(FAIL) indica que el test se detiene si ocurre un error durante la ejecucion, -a(ASK) indica que se le pregunta al usuario cada vez que haya un error en la ejecucion, -p(PASS) indica que el test se ejecuta completo independiente de errores en las ejecucion, -r(REPEAT) indica que se solicita hacer tests de esfuerzo, -h(HIDE) indica que no se impriman informes de avance del test\n\n seguido de \"n(>0)\" pares SLOT TIPO, \ndonde SLOT es el id del slot y TIPO el tipo de slot, siendo posibles NOTOKEN, NOINIT o un numero, el cual representa el PIN del security officer de un token inicializado\n");
			printf("Ejemplo: Usando la libreria de softhsm en modo PASS, ocultando la informacion de avance, con 3 slot(0 no tiene token, el 1 tiene PIN 12345678 y el 2 no esta inicializado)\n");
			printf("./testPKCS11 -ph /usr/lib/softhsm/libsofthsm.so 3 0 NOTOKEN 1 12345678 2 NOINIT\n");
			exit(1);
	}

	if (!initDynamicLibrary(argv[2]))
	{
		exit(1);
	}
	
	//API_TEST
	int level = 0;
	printlnLevel(showMessage, "Inicio : Test Compliance PKCS#11(cryptoki)v2.20", level);
	testNoToken(level + 1, showMessage);
	testNoSessionHandle(level + 1, showMessage);
	testSessionHandleNeeded(level + 1, showMessage);
	printlnLevel(showMessage, "Fin : Test Compliance PKCS#11(cryptoki)v2.20", level);
	//API_TEST
	
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

//Conjunto de tests, que testean funciones que no necesitan de un token para funcionar
//C_Initialize, C_Finalize, C_GetInfo, C_GetFunctionList, C_GetSlotList, C_GetSlotInfo
void testNoToken(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test de funciones que no necesitan token", level);

	testInitializeFinalize(level + 1, showMessage);
	esfuerzoInitializeFinalize(level + 1, repeticiones, showMessage);
	testGetFunctionList(level + 1, showMessage);
	esfuerzoGetFunctionList(level + 1, repeticiones, showMessage);
	testGetInfo(level + 1, showMessage);
	esfuerzoGetInfo(level + 1, repeticiones, showMessage);
	testGetSlotList(level + 1, showMessage);
	esfuerzoGetSlotList(level + 1, repeticiones, showMessage);
	testGetSlotInfo(level + 1, showMessage);
	esfuerzoGetSlotInfo(level + 1, repeticiones, showMessage);

	printlnLevel(showMessage, "Fin: test de funciones que no necesitan token", level);	
}

//Funcion que testea las funciones C_Initialize
//y C_Finalize
void testInitializeFinalize(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_Initialize, C_Finalize", level);

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
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize con pReserved != NULL_PTR"));
	
	args.pReserved = NULL_PTR;
	
	//SE PRUEBA QUE CUANDO ALGUNO, PERO NO TODOS LOS ARGUMENTOS SON != NULL, DEBE RETORNAR CODIGO CKR_ARGUMENTS_BAD (14 casos)
	args.CreateMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD,"Llamada a C_Initialize solo con CreateMutex != NULL_PTR"));
	
	args.CreateMutex = NULL_PTR;
	
	args.DestroyMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con DestroyMutex != NULL_PTR"));

	args.DestroyMutex = NULL_PTR;

	args.LockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con LockMutex != NULL_PTR"));
	
	args.LockMutex = NULL_PTR;

	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con UnlockMutex != NULL_PTR"));
		
	args.UnlockMutex = NULL_PTR;
	
	args.CreateMutex = (void *)1;
	args.DestroyMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con CreateMutex y DestroyMutex != NULL_PTR"));

	args.CreateMutex = NULL_PTR;
	args.DestroyMutex = NULL_PTR;

	args.CreateMutex = (void *)1;
	args.LockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con CreateMutex y LockMutex != NULL_PTR"));

	args.CreateMutex = NULL_PTR;
	args.LockMutex = NULL_PTR;

	
	args.CreateMutex = (void *)1;
	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con CreateMutex y UnlockMutex != NULL_PTR"));

	args.CreateMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;

	args.DestroyMutex = (void *)1;
	args.LockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con DestroyMutex y LockMutex != NULL_PTR"));

	args.DestroyMutex = NULL_PTR;
	args.LockMutex = NULL_PTR;

	args.DestroyMutex = (void *)1;
	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con DestroyMutex y UnlockMutex != NULL_PTR"));

	args.DestroyMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;

	args.LockMutex = (void *)1;
	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con LockMutex y UnlockMutex != NULL_PTR"));

	args.LockMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;

	args.CreateMutex = (void *)1;
	args.DestroyMutex = (void *)1;
	args.LockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con CreateMutex, DestroyMutex y LockMutex != NULL_PTR"));
	
	args.CreateMutex = NULL_PTR;
	args.DestroyMutex = NULL_PTR;
	args.LockMutex = NULL_PTR;

	args.CreateMutex = (void *)1;
	args.DestroyMutex = (void *)1;
	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con CreateMutex, DestroyMutex y UnlockMutex != NULL_PTR"));
	
	args.CreateMutex = NULL_PTR;
	args.DestroyMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;
	
	args.CreateMutex = (void *)1;
	args.LockMutex = (void *)1;
	args.UnlockMutex = (void *)1;
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con CreateMutex, LockMutex y UnlockMutex != NULL_PTR"));
	
	args.CreateMutex = NULL_PTR;
	args.LockMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;

	args.DestroyMutex = (void *)1;
	args.LockMutex = (void *)1;
	args.UnlockMutex = (void *)1;	
	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Initialize solo con DestroyMutex, LockMutex, UnlockMutex != NULL_PTR"));
	
	args.DestroyMutex = NULL_PTR;
	args.LockMutex = NULL_PTR;
	args.UnlockMutex = NULL_PTR;

	//FIN : SE PRUEBA QUE CUANDO ALGUNO, PERO NO TODOS LOS ARGUMENTOS SON != NULL, DEBE RETORNAR CODIGO CKR_ARGUMENTS_BAD (14 casos)

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamada a C_Finalize antes de alguna llamada a C_Initialize exitosa"));

	
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_ALREADY_INITIALIZED, "Llamada a C_Initialize luego de llamada a C_Initialized"));	
	
	rv = C_Finalize((void *)1);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_Finalize con argumento != NULL_PTR"));

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamada a C_Finalize despues de llamada a C_Finalize"));

	rv = C_Initialize(&args);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con argumentos NULOS debio ser equivalente a una llamada con NULL_PTR, es decir"));

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));

	printlnLevel(showMessage, "Fin: test C_Initialize, C_Finalize", level);
}

void esfuerzoInitializeFinalize(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_Initialize C_Finalize", level);
		CK_RV rv;	
		int i;	
		for (i = 0; i < repeticiones; ++i)
		{
			testInitializeFinalize(level + 1, 0);
		}
	
		printlnLevel(showMessage, "Fin: esfuerzo C_Initialize C_Finalize", level);
	}
}


void testGetFunctionList(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_GetFunctionList", level);
	CK_RV rv;
	
	rv = C_GetFunctionList(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_GetFunctionList con puntero nulo"));
	
	CK_FUNCTION_LIST_PTR pfunctionList;
	
	rv = C_GetFunctionList(&pfunctionList);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_GetFunctionList antes de C_Initialize"));

	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));
	
	rv = C_GetFunctionList(&pfunctionList);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_GetFunctionList entre un C_Initialize y su correspondiente C_Finalize"));

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));

	rv = C_GetFunctionList(&pfunctionList);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_GetFunctionList despues de C_Finalize"));
	char * functionName;
	if ((functionName = checkCkFunctionList(pfunctionList)) != NULL_PTR)
	{
		sprintf(ret, "Llamada a C_GetFunctionList, retorno una estructura que contiene el puntero a %s como NULL_PTR, el cual deberia apuntar a una funcion que siempre arroje CKR_FUNCTION_NOT_SUPPORTED", functionName);
		free(functionName);
		assert2(behavior, message(0, ret));	
	}	
	printlnLevel(showMessage, "Fin: test C_GetFunctionList", level);
}

//Test de esfuerzo de GetFunctionList
void esfuerzoGetFunctionList(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_GetFunctionList", level);
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testGetFunctionList(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_GetFunctionList", level);
	}
}

//Tests funcion C_GetInfo
void testGetInfo(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_GetInfo", level);
	CK_RV rv;
	CK_INFO info;
	
	rv = C_GetInfo(&info);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_GetInfo sin un llamado previo a C_Initialize"));
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));
	
	rv = C_GetInfo(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_GetInfo con NULL_PTR"));
	
	rv = C_GetInfo(&info);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_GetInfo"));
		
	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	rv = C_GetInfo(&info);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_GetInfo luego de un llamado a C_Finalize"));

	sprintf(ret, "Version de cryptoki en resultado de C_GetInfo debe se 2.20, pero es %d.%d", (int)info.cryptokiVersion.major, (int)info.cryptokiVersion.minor);
	assert2(behavior, message(info.cryptokiVersion.major == 2 && info.cryptokiVersion.minor == 20, ret));
	
	sprintf(ret, "flags en resultado de C_GetInfo debe ser 0, pero es %d", (int)info.flags);
	assert2(behavior, message(info.flags == 0, ret));
	
	
	assert2(behavior, message(isBlankPadded(info.manufacturerID, 32), "manufacturerID en resultado de C_GetInfo debe ser rellenado con espacios en blanco"));
	assert2(behavior, message(isBlankPadded(info.libraryDescription, 32), "libraryDescription en resultado de C_GetInfo debe ser rellenado con espacios en blanco"));
	
	printlnLevel(showMessage, "Fin: test C_GetInfo", level);
}

//Test de esfuerzo de GetInfo
void esfuerzoGetInfo(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_GetInfo", level);
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testGetInfo(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_GetInfo", level);
	}
}

//Tests de funcion C_GetSlotList
void testGetSlotList(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_GetSlotList", level);
	CK_RV rv;
	CK_SLOT_ID_PTR buffer;	
	CK_ULONG size;
	int i;
	
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_GetSlotList sin un llamado previo a C_Initialize"));
	

	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));
	
	rv = C_GetSlotList(CK_TRUE, buffer, NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_GetSlotList con tercer parametro NULL_PTR"));

	rv = C_GetSlotList(CK_TRUE, NULL_PTR, NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_GetSlotList con segundo y tercer parametro NULL_PTR"));

	//CK_FALSE
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_GetSlotList para obtener el numero de slots"));
	
	sprintf(ret, "El numero de slots entregado por C_GetSlotList(%d) es distinto al especificado(%d)", (int)size, (int)numberOfSlots);	
	assert2(behavior, message(size == numberOfSlots, ret));
	
	for(i = -1; i < size; ++i)
	{
		size = i;
		rv = C_GetSlotList(CK_FALSE, buffer, &size);
		sprintf(ret, "Llamada a C_GetSlotList con un ulCount = %d menor al numero de slots(%d)", i, (int)numberOfSlots);
		assert2(behavior, verifyCode(rv, CKR_BUFFER_TOO_SMALL, ret));	
		
		sprintf(ret, "El numero de slots entregado por C_GetSlotList(%d) es distinto al especificado(%d), en iteracion %d", (int)size, (int)numberOfSlots, (i+2));	
		assert2(behavior, message(size == numberOfSlots, ret));

	}
	buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_FALSE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	

	sprintf(ret, "El numero de slots entregado por C_GetSlotList(%d) es distinto al especificado(%d)", (int)size, (int)numberOfSlots);
	assert2(behavior, message(size == numberOfSlots, ret));
	
	int slotsR [size];
	for (i = 0; i < size; ++i)
	{
		slotsR[i] = buffer[i];
	}
	

	for(i = 0; i < numberOfSlots; ++i)
	{
		CK_SLOT_ID slotID = slotsR[i];
		sprintf(ret, "Al resultado de C_GetSlotList(CK_FALSE) le falto un slot(%d) de los especificados", (int)slotID);
		assert2(behavior, message(contains(slotsR, (int)size, (int)slotID), ret));
	}
	free(buffer);
	


	//CK_TRUE
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_GetSlotList para obtener el numero de slots con token"));
	
	sprintf(ret, "El numero de slots con token entregado por C_GetSlotList(%d) es distinto al especificado(%d)", (int)size, (int)numberOfSlotsWithInitToken + (int)numberOfSlotsWithNotInitToken);
	assert2(behavior, message(size == (int)numberOfSlotsWithInitToken + (int)numberOfSlotsWithNotInitToken, ret));
	
	for(i = -1; i < size; ++i)
	{
		size = i;
		rv = C_GetSlotList(CK_TRUE, buffer, &size);
		sprintf(ret, "Llamada a C_GetSlotList con un ulCount = %d menor al numero de slots con token(%d)", i, (int)numberOfSlotsWithInitToken+(int)numberOfSlotsWithNotInitToken);
		assert2(behavior, verifyCode(rv, CKR_BUFFER_TOO_SMALL, ret));	
		
		sprintf(ret, "El numero de slots con token entregado por C_GetSlotList(%d) es distinto al especificado(%d), en la iteracion %d", (int)size, (int)numberOfSlotsWithInitToken+(int)numberOfSlotsWithNotInitToken, (i+2));
		assert2(behavior, message(size == (int)numberOfSlotsWithInitToken+(int)numberOfSlotsWithNotInitToken, ret));

	}
	buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
		
	
	sprintf(ret, "El numero de slots con token entregado por C_GetSlotList(%d) es distinto al especificado(%d)", (int)size, (int)numberOfSlotsWithInitToken+(int)numberOfSlotsWithNotInitToken);
	assert2(behavior, message(size == (int)numberOfSlotsWithInitToken+(int)numberOfSlotsWithNotInitToken, ret));

	int slotsToken [size];
	for (i = 0; i < size; ++i)
	{
		slotsToken[i] = buffer[i];
	}

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		CK_SLOT_ID slotID = slotsWithInitToken[i];
		sprintf(ret, "Al resultado de C_GetSlotList(CK_TRUE) le falto un slot(%d) de los especificados", (int)slotID);
		assert2(behavior, message(contains(slotsToken, (int)size, (int)slotID), ret));
	}
	
	for (i = 0; i < numberOfSlotsWithNotInitToken; ++i)
	{
		CK_SLOT_ID slotID = slotsWithNotInitToken[i];
		sprintf(ret, "Al resultado de C_GetSlotList(CK_TRUE) le falto un slot(%d) de los especificados", (int)slotID);
		assert2(behavior, message(contains(slotsToken, (int)size, (int)slotID), ret));
	}
	free(buffer);
	
	
	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_GetSlotList luego de un llamado a C_Finalize"));

	printlnLevel(showMessage, "Fin: test C_GetSlotList", level);
}

//Test de esfuerzo de C_GetSlotList
void esfuerzoGetSlotList(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_GetSlotList", level);
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testGetSlotList(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_GetSlotList", level);
	}
}

//tests para la funcion C_GetSlotInfo
void testGetSlotInfo(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_GetSlotInfo", level);
	CK_RV rv;
	CK_SLOT_INFO info;
	int i;

	CK_SLOT_ID_PTR buffer;	
	CK_ULONG size;

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetSlotInfo(slotsWithInitToken[i], &info);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_GetSlotInfo sin un llamado previo a C_Initialize"));
	}

	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetSlotInfo(slotsWithInitToken[i], NULL_PTR);
		assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_GetSlotInfo con segundo parametro NULL_PTR"));
	}

	rv = C_GetSlotInfo(slotInvalid, &info);
	sprintf(ret, "Llamada a C_GetSlotInfo con ID de slot invalido(%d)", (int)slotInvalid);
	assert2(behavior, verifyCode(rv, CKR_SLOT_ID_INVALID, ret));
	
	
	//CK_FALSE, comprobaciones generales
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_FALSE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));

	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];	
		rv = C_GetSlotInfo(slot, &info);
		sprintf(ret, "Llamado a C_GetSlotInfo con un slotID(%d) retornado por C_GetSlotList(CK_FALSE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		
		sprintf(ret, "slotDescription en resultado de C_GetSlotInfo(slot %d) debe ser rellenado con espacios en blanco", (int)slot);
		assert2(behavior, message(isBlankPadded(info.slotDescription, 64), ret));
		sprintf(ret, "manufacturerID en resultado de C_GetSlotInfo(slot %d) debe ser rellenado con espacios en blanco", (int)slot);
		assert2(behavior, message(isBlankPadded(info.manufacturerID, 32), ret));
		
		//COMPROBACION FALLO CKF_REMOVABLE_DEVICE isntSet => CKF_TOKEN_PRESENT isSet
		sprintf(ret, "Llamado a C_GetSlotInfo con un slotID(%d) retornado por C_GetSlotList(CK_FALSE) no cumple la regla: Si CKF_REMOVABLE_DEVICE no esta, entonces CKF_TOKEN_PRESENT debe estar, en el campo flags de su resultado", (int)slot);
		assert2(behavior, message((info.flags & CKF_TOKEN_PRESENT)|| (info.flags & CKF_REMOVABLE_DEVICE), ret));
		//COMPROBACION FALLO CKF_REMOVABLE_DEVICE isntSet => CKF_TOKEN_PRESENT isSet
	}
	free(buffer);

	//CK_TRUE, comprobacion de flag
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));

	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		rv = C_GetSlotInfo(slot, &info);
		sprintf(ret, "Llamado a C_GetSlotInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		assert2(behavior, message(info.flags & CKF_TOKEN_PRESENT, "Resultado de llamada a C_GetSlotInfo con un slotID retornado por C_GetSlotList(CK_TRUE), debio tener encendido el flag CKF_TOKEN_PRESENT"));	
	}
	free(buffer);
	

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetSlotInfo(slotsWithInitToken[i], &info);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_GetSlotInfo luego de un llamado a C_Finalize"));	
	}

	printlnLevel(showMessage, "Fin: test C_GetSlotInfo", level);

}

//test de esfuerzo para la funcion C_GetSlotInfo
void esfuerzoGetSlotInfo(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_GetSlotInfo", level);
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testGetSlotInfo(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_GetSlotInfo", level);
	}
}



//TESTS de funciones que no necesitan un handle de session(excepto por C_CloseSession)
//, pero si un slot con token
//C_GetTokenInfo, C_InitToken, C_OpenSession, C_CloseAllSessions, C_CloseSession
void testNoSessionHandle(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test de funciones que no necesitan handle de sesion pero si de un slot con token", level);
	
	testGetTokenInfo(level + 1, showMessage);
	esfuerzoGetTokenInfo(level + 1, repeticiones, showMessage);
	testInitToken(level + 1, showMessage);
        esfuerzoInitToken(level + 1, repeticiones, showMessage);
	testOpenSession(level + 1, showMessage);
	esfuerzoOpenSession(level + 1, repeticiones, showMessage);
	testCloseSession(level + 1, showMessage);
	esfuerzoCloseSession(level + 1, repeticiones, showMessage);
	testCloseAllSessions(level + 1, showMessage);
	esfuerzoCloseAllSessions(level + 1, repeticiones, showMessage);

	printlnLevel(showMessage, "Fin: test de funciones que no necesitan handle de sesion pero si de un slot con token", level);
}

/////////
void testGetTokenInfo(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_GetTokenInfo", level);
	CK_RV rv;
	CK_TOKEN_INFO info;
	CK_ULONG size;
	CK_SLOT_ID_PTR buffer;
	int i;
	

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithInitToken[i], &info);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_GetTokenInfo sin un llamado previo a C_Initialize"));
	}
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithInitToken[i], NULL_PTR);
		assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_GetTokenInfo con segundo parametro NULL_PTR"));
	}

	rv = C_GetTokenInfo(slotInvalid, &info);
	sprintf(ret, "Llamada a C_GetTokenInfo con ID de slot invalido(%d)", (int)slotInvalid);
	assert2(behavior, verifyCode(rv, CKR_SLOT_ID_INVALID, ret));

	for (i = 0; i < numberOfSlotsWithNoToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithNoToken[i], &info);
		sprintf(ret, "Llamada a C_GetTokenInfo con ID(%d) de slot valido, pero que no tiene un token", (int)slotsWithNoToken[i]);
		assert2(behavior, verifyCode(rv, CKR_TOKEN_NOT_PRESENT, ret));
	}
	
	
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));

	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		rv = C_GetTokenInfo(slot, &info);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		
		sprintf(ret, "label en resultado de C_GetTokenInfo en slot %d debe ser rellenado con espacios en blanco", (int)slot);
		assert2(behavior, message(isBlankPadded(info.label, 32), ret));
		sprintf(ret, "manufacturerID en resultado de C_GetTokenInfo en slot %d debe ser rellenado con espacios en blanco", (int)slot);
		assert2(behavior, message(isBlankPadded(info.manufacturerID, 32), ret));
		sprintf(ret, "model en resultado de C_GetTokenInfo en slot %d debe ser rellenado con espacios en blanco", (int)slot);
		assert2(behavior, message(isBlankPadded(info.model, 16), ret));
		sprintf(ret, "serialNumber en resultado de C_GetTokenInfo en slot %d debe ser rellenado con espacios en blanco", (int)slot);
		assert2(behavior, message(isBlankPadded(info.serialNumber, 15), ret));
		

		if (info.flags & CKF_CLOCK_ON_TOKEN)
		{
			sprintf(ret, "Resultado de C_GetTokenInfo en slot %d, contiene el flag CKF_CLOCK_ON_TOKEN, sin embargo el campo utcTime deberia terminar en '00'", (int)slot);
			assert2(behavior, message(info.utcTime[14]=='0' && info.utcTime[15]=='0', ret));
		}
		
		sprintf(ret, "Resultado de C_GetTokenInfo en slot %d debe tener el flag CKF_SECONDARY_AUTHENTICATION en 0", (int)slot);
		assert2(behavior, message(!(info.flags & CKF_SECONDARY_AUTHENTICATION), ret));
		
		sprintf(ret, "Resultado de C_GetTokenInfo en slot %d retorna un estado inconsistente de las campos ulMinPinLen y ulMaxPinLen(ulMinPinLen = %d > ulMaxPinLen = %d)", (int)slot, (int)info.ulMinPinLen, (int)info.ulMaxPinLen);
		assert2(behavior, message(info.ulMinPinLen <= info.ulMaxPinLen, ret));
		
	}
	free(buffer);
	
	//COMPROBACION FLAG CKF_TOKEN_INITIALIZED
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithInitToken[i], &info);
		sprintf(ret, "Llamado a C_GetTokenInfo con slot(%d) con token inicializado", (int)slotsWithInitToken[i]);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		   
		sprintf(ret, "Resultado de C_GetTokenInfo con slot(%d) con token inicializado debio tener el flag CKF_TOKEN_INITIALIZED", (int)slotsWithInitToken[i]);
		assert2(behavior, message(info.flags & CKF_TOKEN_INITIALIZED, ret));	
	}
	
	for (i = 0; i < numberOfSlotsWithNotInitToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithNotInitToken[i], &info);
		sprintf(ret, "Llamado a C_GetTokenInfo con slot(%d) con token no inicializado", (int)slotsWithNotInitToken[i]);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		   
		sprintf(ret, "Resultado de C_GetTokenInfo con slot(%d) con token no inicializado debio tener el flag CKF_TOKEN_INITIALIZED en 0", (int)slotsWithNotInitToken[i]);
		assert2(behavior, message(!(info.flags & CKF_TOKEN_INITIALIZED), ret));
	}
	//COMPROBACION FLAG CKF_TOKEN_INITIALIZED
	

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_GetTokenInfo(slotsWithInitToken[i], &info);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_GetTokenInfo luego de un llamado a C_Finalize"));
	}
	
	printlnLevel(showMessage, "Fin: test C_GetTokenInfo", level);
}

//////
void esfuerzoGetTokenInfo(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_GetTokenInfo", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testGetTokenInfo(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_GetTokenInfo", level);
	}
}


//
void testInitToken(int level, int showMessage)
{
        printlnLevel(showMessage, "Inicio: test C_InitToken", level);
        
        char * textLabel = "A token";
        CK_UTF8CHAR paddedLabel[32];
        memset(paddedLabel, ' ', sizeof(paddedLabel));
        memcpy(paddedLabel, textLabel, strlen(textLabel));

	CK_RV rv;
	int i;
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_InitToken(slotsWithInitToken[i], soPINs[i], strlen(soPINs[i]), paddedLabel);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_InitToken sin un llamado previo a C_Initialize"));
	}
		

 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));
        
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_InitToken(slotsWithInitToken[i], NULL_PTR, 0, paddedLabel);
		assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_InitToken con un NULL_PTR en su segundo argumento")); //Se asume que no hay otro mecanismo de authentication

		rv = C_InitToken(slotsWithInitToken[i], soPINs[i], strlen(soPINs[i]), NULL_PTR);
		assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_InitToken con un NULL_PTR en su cuarto argumento"));
	}

	rv = C_InitToken(slotInvalid, "7654321", 7, paddedLabel);
	assert2(behavior, verifyCode(rv, CKR_SLOT_ID_INVALID, "Llamada a C_InitToken con un slot invalido"));
	
        CK_ULONG size;
	CK_SLOT_INFO info;	
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_FALSE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		rv = C_GetSlotInfo(slot, &info);
		sprintf(ret, "Llamado a C_GetSlotInfo con un slotID(%d) retornado por C_GetSlotList(CK_FALSE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		
		if (!(info.flags & CKF_TOKEN_PRESENT))
		{
			//CAMBIA soPIN dependiendo del slot
			rv = C_InitToken(slot, "7654321", 7, paddedLabel);	
			sprintf(ret, "Llamado a C_InitToken con slotID(%d), el cual no presenta un token en el(Resultado de C_GetSlotInfo no tiene flag CKF_TOKEN_PRESENT)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_TOKEN_NOT_PRESENT, ret));
			
		}
		else
		{
			//CAMBIA soPIN dependiendo del slot
			CK_TOKEN_INFO infoToken;
			rv = C_GetTokenInfo(slot, &infoToken);
			sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_FALSE) que tiene flag CKF_TOKEN_PRESENT", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			if (infoToken.flags & CKF_TOKEN_INITIALIZED)//SOLO REINICIALIZA
			{
				
				if (!(infoToken.flags & CKF_WRITE_PROTECTED))
				{
					sprintf(ret, "Llamada a C_InitToken con slotID(%d), el cual tiene un token inicializado en el", (int)slot);
					int ind = indice((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
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
		sprintf(ret, "Llamado a C_InitToken del slotID %d, con un SOPIN incorrecto", (int)slotsWithInitToken[i]); 
		rv = C_InitToken(slotsWithInitToken[i], badSoPIN, strlen(badSoPIN), paddedLabel);
		assert2(behavior, verifyCode(rv, CKR_PIN_INCORRECT, ret));
	

	
		rv = C_GetSlotInfo(slotsWithInitToken[i], &info);
		sprintf(ret, "Llamado a C_GetSlotInfo con un slotID(%d)", (int)slotsWithInitToken[i]);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
	}

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_InitToken(slotsWithInitToken[i], soPINs[i], strlen(soPINs[i]), paddedLabel);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_InitToken luego de un llamado a C_Finalize"));	
	}

	printlnLevel(showMessage, "Fin: test C_InitToken", level);
}

/////////
void esfuerzoInitToken(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_InitToken", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testInitToken(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_InitToken", level);
	}
}

////////
void testOpenSession(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_OpenSession", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	int i;
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_OpenSession(slotsWithInitToken[i], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
	    	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_OpenSession sin un llamado previo a C_Initialize"));
	}

 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_OpenSession(slotsWithInitToken[i], 0, NULL_PTR, NULL_PTR, &hSession[0]);
		assert2(behavior, verifyCode(rv, CKR_SESSION_PARALLEL_NOT_SUPPORTED, "Llamada a C_OpenSession con flag CKF_SERIAL_SESSION apagado"));

		rv = C_OpenSession(slotsWithInitToken[i], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, NULL_PTR);
		assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, "Llamada a C_OpenSession con argumento 5 NULL_PTR"));
	}
	
	rv = C_OpenSession(slotInvalid, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
	assert2(behavior, verifyCode(rv, CKR_SLOT_ID_INVALID, "Llamada a C_OpenSession con slotID invalido"));


	CK_ULONG size;
	CK_SLOT_INFO info;	
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_FALSE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		rv = C_GetSlotInfo(slot, &info);
		sprintf(ret, "Llamado a C_GetSlotInfo con un slotID(%d) retornado por C_GetSlotList(CK_FALSE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		if (!(info.flags & CKF_TOKEN_PRESENT))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_FALSE) y con flag CKF_TOKEN_PRESENT apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_TOKEN_NOT_PRESENT, ret));
		}
		else
		{
			CK_TOKEN_INFO infoToken;
			rv = C_GetTokenInfo(slot, &infoToken);
			sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_FALSE) que tiene flag CKF_TOKEN_PRESENT", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			if (!(infoToken.flags & CKF_TOKEN_INITIALIZED))
			{
				rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
				sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_FALSE) y con flag CKF_TOKEN_PRESENT prendido y CKF_TOKEN_INITIALIZED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_TOKEN_NOT_RECOGNIZED, ret));
			}
			else
			{
				if(!(infoToken.flags & CKF_WRITE_PROTECTED))
				{
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
					sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_FALSE) y con flag CKF_TOKEN_PRESENT,CKF_TOKEN_INITIALIZED prendidos y CKF_WRITE_PROTECTED apagado, al intentar abrir una sesion R/O", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
					sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_FALSE) y con flag CKF_TOKEN_PRESENT,CKF_TOKEN_INITIALIZED prendidos y CKF_WRITE_PROTECTED apagado, al intentar abrir una sesion R/W", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
					char * textLabel = "A token";
        				CK_UTF8CHAR paddedLabel[32];
        				memset(paddedLabel, ' ', sizeof(paddedLabel));
				        memcpy(paddedLabel, textLabel, strlen(textLabel));
					int ind = indice((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
					rv = C_InitToken(slot, soPINs[ind], strlen(soPINs[ind]), paddedLabel);
					sprintf(ret, "Llamado a C_InitToken con slotID(%d), en el cual se acaba de abrir una sesion", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_SESSION_EXISTS, ret));
					
				}
			}
		}
	}
	free(buffer);

	

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_OpenSession(slotsWithInitToken[i], CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_OpenSession luego de un llamado a C_Finalize"));	
	}

	printlnLevel(showMessage, "Fin: test C_OpenSession", level);
}

///////
void esfuerzoOpenSession(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_OpenSession", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testOpenSession(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_OpenSession", level);
	}
}


/////
void testCloseSession(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_CloseSession", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];

	rv = C_CloseSession(hSession[0]);
    	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_CloseSession sin un llamado previo a C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_CloseSession(CK_INVALID_HANDLE);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Llamada a C_CloseSession con un handle invalido"));	


	CK_ULONG size;
	unsigned int i;
	CK_SLOT_INFO info;	
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
		if (infoToken.flags & CKF_TOKEN_INITIALIZED)
		{
			if (!(infoToken.flags & CKF_WRITE_PROTECTED))
			{	
				rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
				sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, al intentar abrir una sesion R/O", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
				rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
				sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, al intentar abrir una sesion R/W", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				rv = C_CloseSession(hSession[0]);
				sprintf(ret, "Llamado a C_CloseSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, inmediatamente luego de abrir esa sesion(R/O)", (int)slot );
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				rv = C_CloseSession(hSession[0]);
				sprintf(ret, "Llamado a C_CloseSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, inmediatamente luego de cerrar esa sesion(R/O)", (int)slot );
				assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, ret));

				rv = C_CloseSession(hSession[1]);
				sprintf(ret, "Llamado a C_CloseSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, inmediatamente luego de abrir esa sesion(R/W)", (int)slot );
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				rv = C_CloseSession(hSession[1]);
				sprintf(ret, "Llamado a C_CloseSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, inmediatamente luego de cerrar esa sesion(R/W)", (int)slot );
				assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, ret));

				
				
				
				
				//COMPROBACION DE CAMPOS DE TOKEN/SESSION
				rv = C_GetTokenInfo(slot, &infoToken);
				sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);

				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				int maximoOS;//OpenSessionss
				maximoOS = infoToken.ulMaxSessionCount == CK_UNAVAILABLE_INFORMATION ? 1 :
	 (infoToken.ulMaxSessionCount == CK_EFFECTIVELY_INFINITE)? 10 : infoToken.ulMaxSessionCount ;	
				
				if (infoToken.ulSessionCount != CK_UNAVAILABLE_INFORMATION)
				{
					sprintf(ret, "Token con slotID(%d), sin sesiones abiertas debio contener en su info.ulSessionCount 0, pero contiene %d", (int)slot, (int)infoToken.ulSessionCount);
					assert2(behavior, message(infoToken.ulSessionCount == 0, ret));		
				}

				CK_SESSION_HANDLE hTestSession[maximoOS];
					
				int j;
				for(j = 0; j < maximoOS; ++j)
				{
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hTestSession[j]);
					sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, al intentar abrir una sesion R/O", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token con slotID(%d), con %d sesiones abiertas debio contener en su info.ulSessionCount esa informacion, pero contiene %d", (int)slot, (j+1), (int)infoToken.ulSessionCount);
						assert2(behavior, message(infoToken.ulSessionCount == (j+1), ret));	
					}
				}
				
				if (infoToken.ulMaxSessionCount != CK_UNAVAILABLE_INFORMATION && infoToken.ulMaxSessionCount != CK_EFFECTIVELY_INFINITE)
				{
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hTestSession[j]);
					sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, que ha inicializado un numero de sesiones igual al maximo especificado en la informacion(%d) de su token", (int)slot, (int)infoToken.ulMaxSessionCount);
					assert2(behavior, verifyCode(rv, CKR_SESSION_COUNT, ret));
				}

				//CERRADO DE ESAS SESIONES
				for(j = maximoOS - 1; j >= 0; j--)
				{
					rv = C_CloseSession(hTestSession[j]);
					sprintf(ret, "Llamado a C_CloseSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, con handle session de sesion no cerrada", (int)slot);
					
					assert2(behavior, verifyCode(rv, CKR_OK ,ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token con slotID(%d), con %d sesiones abiertas debio contener en su info.ulSessionCount esa informacion, pero contiene %d", (int)slot, (j), (int)infoToken.ulSessionCount);
						assert2(behavior, message(infoToken.ulSessionCount == j, ret));	
					}
					
				}
	
				//AHORA CON R/W
				rv = C_GetTokenInfo(slot, &infoToken);
				sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);

				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				int maximoRW;
				maximoRW = infoToken.ulMaxRwSessionCount == CK_UNAVAILABLE_INFORMATION ? 1 :
	 (infoToken.ulMaxRwSessionCount == CK_EFFECTIVELY_INFINITE)? 10 : infoToken.ulMaxRwSessionCount ;	
				
				if (infoToken.ulRwSessionCount != CK_UNAVAILABLE_INFORMATION)
				{
					sprintf(ret, "Token con slotID(%d), sin sesiones R/W abiertas debio contener en su info.ulRwSessionCount 0, pero contiene %d", (int)slot, (int)infoToken.ulRwSessionCount);
					assert2(behavior, message(infoToken.ulRwSessionCount == 0, ret));		
				}

				CK_SESSION_HANDLE hTestSessionRW[maximoRW];
					
				for(j = 0; j < maximoRW; ++j)
				{
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hTestSessionRW[j]);
					sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, al intentar abrir una sesion R/W", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulRwSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token con slotID(%d), con %d sesiones R/W abiertas debio contener en su info.ulRwSessionCount esa informacion, pero contiene %d", (int)slot, (j+1), (int)infoToken.ulRwSessionCount);
						assert2(behavior, message(infoToken.ulRwSessionCount == (j+1), ret));	
					}
				}
				
				if (infoToken.ulMaxRwSessionCount != CK_UNAVAILABLE_INFORMATION && infoToken.ulMaxRwSessionCount != CK_EFFECTIVELY_INFINITE)
				{
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hTestSessionRW[j]);
					sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, que ha inicializado un numero de sesiones R/W igual al maximo especificado en la informacion de su token", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_SESSION_COUNT, ret));
				}

				//CERRADO DE ESAS SESIONES
				for(j = maximoRW - 1; j >= 0; j--)
				{
					rv = C_CloseSession(hTestSessionRW[j]);
					sprintf(ret, "Llamado a C_CloseSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, con handle session de sesion RW no cerrada", (int)slot);
					
					assert2(behavior, verifyCode(rv, CKR_OK ,ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulRwSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token con slotID(%d), con %d sesiones R/W abiertas debio contener en su info.ulRwSessionCount esa informacion, pero contiene %d", (int)slot, (j), (int)infoToken.ulSessionCount);
						assert2(behavior, message(infoToken.ulRwSessionCount == j, ret));	
					}
					
				}
			}
		}
	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	rv = C_CloseSession(hSession[0]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_CloseSession luego de un llamado a C_Finalize"));	
	
	printlnLevel(showMessage, "Fin: test C_CloseSession", level);
}

////
void esfuerzoCloseSession(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_CloseSession", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testCloseSession(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_CloseSession", level);
	}
}

////
void testCloseAllSessions(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_CloseAllSessions", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	int i;
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_CloseAllSessions(slotsWithInitToken[i]);
	    	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_CloseAllSessions sin un llamado previo a C_Initialize"));
	}

 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	
	rv = C_CloseAllSessions(slotInvalid);
	assert2(behavior, verifyCode(rv, CKR_SLOT_ID_INVALID, "Llamada a C_CloseAllSessions con un slotID invalido"));	

	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_CloseAllSessions(slotsWithInitToken[i]);
		assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_CloseAllSessions sin ninguna sesion abierta previamente"));
	}



	CK_ULONG size;
	rv = C_GetSlotList(CK_FALSE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_FALSE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_SLOT_INFO info;
		rv = C_GetSlotInfo(slot, &info);
		sprintf(ret, "Llamado a C_GetSlotInfo con un slotID(%d) retornado por C_GetSlotList(CK_FALSE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		if (!(info.flags & CKF_TOKEN_PRESENT))
		{
			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_FALSE) y flag CKF_TOKEN_PRESENT apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_TOKEN_NOT_PRESENT, ret));
		}

		else
		{

			CK_TOKEN_INFO infoToken;
			rv = C_GetTokenInfo(slot, &infoToken);
			sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_FALSE) con flag CKF_TOKEN_PRESENT encendido", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			if (!(infoToken.flags & CKF_TOKEN_INITIALIZED))
			{
				rv = C_CloseAllSessions(slot);
				sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_FALSE) y flag CKF_TOKEN_PRESENT encendido, pero CKF_TOKEN_INITIALIZED apagado", (int)slot);
				assert2(behavior, verifyCode2(rv, CKR_TOKEN_NOT_PRESENT, CKR_OK, ret));//No hay un buen codigo de retorno para esto
			}
			else
			{
				if (!(infoToken.flags & CKF_WRITE_PROTECTED))
				{	
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
					sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
					rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
					sprintf(ret, "Llamado a C_OpenSession con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado, al intentar abrir una sesion R/W", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token con slotID(%d), con 2 sesiones abiertas debio contener en su info.ulSessionCount 2, pero contenia %d", (int)slot, (int)infoToken.ulSessionCount);
						assert2(behavior, message(infoToken.ulSessionCount == 2, ret));		
					}
					if (infoToken.ulRwSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token con slotID(%d), con 2 sesiones abiertas, 1 R/W abierta debio retornar en su info.ulRwSessionCount 1, pero retorno %d", (int)slot, (int)infoToken.ulRwSessionCount);
						assert2(behavior, message(infoToken.ulRwSessionCount == 1, ret));		
					}
					
					//CERRADO DE ESAS SESIONES
					rv = C_CloseAllSessions(slot);
					sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK ,ret));

					rv = C_GetTokenInfo(slot, &infoToken);
					sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					if (infoToken.ulSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token con slotID(%d), luego de llamado a C_CloseAllSessions debio retornar en su info.ulSessionCount en 0", (int)slot);
						assert2(behavior, message(infoToken.ulSessionCount == 0, ret));	
					}
					if (infoToken.ulRwSessionCount != CK_UNAVAILABLE_INFORMATION)
					{
						sprintf(ret, "Token con slotID(%d), luego de llamado a C_CloseAllSessions debio retornar en su info.ulRwSessionCount en 0", (int)slot);
						assert2(behavior, message(infoToken.ulRwSessionCount == 0, ret));	
					}
					
				}
			}
		}
	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	for (i = 0; i < numberOfSlotsWithInitToken; ++i)
	{
		rv = C_CloseAllSessions(slotsWithInitToken[i]);
		assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED, "Llamado a C_CloseAllSessions luego de un llamado a C_Finalize"));	
	}
	
	printlnLevel(showMessage, "Fin: test C_CloseAllSessions", level);
}



////
void esfuerzoCloseAllSessions(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_CloseAllSessions", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testCloseAllSessions(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_CloseAllSessions", level);
	}

}


//Test de funciones que necesitan de un handle de session para funcionar
void testSessionHandleNeeded(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test de funciones que necesitan handle de sesion", level);
	
	testSessionHandleManagement(level + 1, showMessage);
	testObjectManagementFunctions(level + 1, showMessage);
	testMechanisms(level + 1, showMessage);
	testRNGFunctions(level + 1, showMessage);
	printlnLevel(showMessage, "Fin: test de funciones que necesitan handle de sesion", level);
}


//Test de funcioes que necesitan de un handle de session y que son de Management,
//estas son
//C_GetSessionInfo, C_InitPIN, C_SetPIN, C_Login, C_Logout
void testSessionHandleManagement(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test de funciones de administracion", level);
	testGetSessionInfo(level + 1, showMessage);
	esfuerzoGetSessionInfo(level + 1, repeticiones, showMessage);

	testInitPin(level + 1, showMessage);
	esfuerzoInitPin(level + 1, repeticiones, showMessage);
	

	testLogin(level + 1, showMessage);
	esfuerzoLogin(level + 1, repeticiones, showMessage);
	testLogout(level + 1, showMessage);
	esfuerzoLogout(level + 1, repeticiones, showMessage);

	testSetPin(level + 1, showMessage);
	esfuerzoSetPin(level + 1, repeticiones, showMessage);

	printlnLevel(showMessage, "Fin: test de funciones de administracion", level);
}

//////
void testGetSessionInfo(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_GetSessionInfo", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	CK_SESSION_INFO infoSession;
	

	rv = C_GetSessionInfo(hSession[0], &infoSession);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_GetSessionInfo sin un llamado previo a C_Initialize"));


 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));


	rv = C_GetSessionInfo(CK_INVALID_HANDLE, &infoSession);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Llamada a C_GetSessionInfo con handle invalido"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			//R/O			
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_GetSessionInfo(hSession[0], NULL_PTR);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/O creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR", (int)slot);			
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			rv = C_GetSessionInfo(hSession[0], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/O creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));


			sprintf(ret, "Resultado de llamada a C_GetSessionInfo indica que el slot de la sesion R/O abierta en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, es %d", (int)slot, (int)infoSession.slotID);
			assert2(behavior, message(infoSession.slotID == slot, ret));			
			
			sprintf(ret, "Resultado de llamada a C_GetSessionInfo de sesion R/O creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, debio tener flag CKF_SERIAL_SESSION encendido", (int)slot);	
			assert2(behavior, message(infoSession.flags & CKF_SERIAL_SESSION, ret));	

			sprintf(ret, "Resultado de llamada a C_GetSessionInfo de sesion R/W creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, debio tener flag CKF_RW_SESSION apagado", (int)slot);	
			assert2(behavior, message(!(infoSession.flags & CKF_RW_SESSION), ret));		
			
			//R/W		
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_GetSessionInfo(hSession[1], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/W creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));


			sprintf(ret, "Resultado de llamada a C_GetSessionInfo indica que el slot de la sesion R/W abierta en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, es %d", (int)slot, (int)infoSession.slotID);
			assert2(behavior, message(infoSession.slotID == slot, ret));			
			
			sprintf(ret, "Resultado de llamada a C_GetSessionInfo de sesion R/W creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, debio tener flag CKF_SERIAL_SESSION encendido", (int)slot);	
			assert2(behavior, message(infoSession.flags & CKF_SERIAL_SESSION, ret));
			
			sprintf(ret, "Resultado de llamada a C_GetSessionInfo de sesion R/W creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, debio tener flag CKF_RW_SESSION encendido", (int)slot);	
			assert2(behavior, message(infoSession.flags & CKF_RW_SESSION, ret));			


			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Llamada a C_CloseAllSessions con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado luego de abrir 1 sesion R/O y 1 R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
		}
	}
	free(buffer);

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	rv = C_GetSessionInfo(hSession[0], &infoSession);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_GetSessionInfo luego de un llamado a C_Finalize"));	

	printlnLevel(showMessage, "Fin: test C_GetSessionInfo", level);
}

////
void esfuerzoGetSessionInfo(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_GetSessionInfo", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testGetSessionInfo(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_GetSessionInfo", level);
	}
}

////USARE C_Login sin testear
void testInitPin(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_InitPIN", level);
	
	CK_RV rv;
	CK_SESSION_HANDLE hSession;

	rv = C_InitPIN(hSession, userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_InitPIN sin un llamado previo a C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));
	
	rv = C_InitPIN(CK_INVALID_HANDLE, userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Llamada a C_InitPIN con handle de sesion invalido"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			int ind = indice((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
			rv = C_Login(hSession, CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_InitPIN(hSession, NULL_PTR, 0);
			sprintf(ret, "Llamada a C_InitPIN con una sesion R/W SO abierta y logueada en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con segundo argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));
	
			
			CK_UTF8CHAR_PTR longPIN = (CK_UTF8CHAR_PTR)malloc((infoToken.ulMaxPinLen + 2)*sizeof(CK_UTF8CHAR));
			int j;
			for(j = 0; j < infoToken.ulMaxPinLen + 1; ++j)
			{
				*(longPIN + j*sizeof(CK_UTF8CHAR)) = (CK_UTF8CHAR)'1';
			}
			*(longPIN + j*sizeof(CK_UTF8CHAR)) = 0;
			rv = C_InitPIN(hSession, longPIN, infoToken.ulMaxPinLen + 1);
			sprintf(ret, "Llamada a C_InitPIN  con una sesion R/W SO abierta y logueada en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un userPIN de largo 1 mas que el especificado en el ulMaxPinLen del resultado de C_GetTokenInfo", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, ret));
			free(longPIN);

			if (infoToken.ulMinPinLen > 0)
			{
				CK_UTF8CHAR shortPIN [] = {""};
				rv = C_InitPIN(hSession, shortPIN, 0);
				sprintf(ret, "Llamada a C_InitPIN  con una sesion R/W SO abierta y logueada en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un userPIN de largo 0 (\"\")", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, ret));
			}

			rv = C_InitPIN(hSession, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_InitPIN con una sesion R/W SO abierta y logueada en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con segundo argumento %s y tercer argumento %d", (int)slot, (char *)userPIN, (int)strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_GetTokenInfo(slot, &infoToken);
			sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			sprintf(ret, "Resultado de C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE), luego de llaamr a C_InitPIN en el, debio tener el flag CKF_USER_PIN_INITIALIZED prendido", (int)slot);
			assert2(behavior, message(infoToken.flags & CKF_USER_PIN_INITIALIZED, ret));

			
		}
	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	rv = C_InitPIN(hSession, userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_InitPIN luego de un llamado a C_Finalize"));	

	printlnLevel(showMessage, "Fin: test C_InitPIN", level);
}



///
void esfuerzoInitPin(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_InitPIN", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testInitPin(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_InitPIN", level);
	}

}


///
void testLogin(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_Login", level);
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	CK_SESSION_INFO infoSession;
	
	rv = C_Login(hSession[0], CKU_USER, userPIN, strlen(userPIN)); //FUE INICIALIZADO ANTES
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_Login sin un llamado previo a C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_Login(CK_INVALID_HANDLE, CKU_USER, userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Llamada a C_Login con handle de sesion invalido"));	

	
	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/W creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			sprintf(ret, "Resultado de C_GetSessionInfo de una sesion RW sin logueo, debio tener en campo state CKSRW_PUBLIC_SESSION");
			assert2(behavior, message(infoSession.state == CKS_RW_PUBLIC_SESSION, ret));
			//SESSIONINFOVERIFY
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN
			rv = C_InitPIN(hSession[1], userPIN, strlen(userPIN));
			sprintf(ret, "Llamado a C_InitPIN con sesion abierta en slot(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado que esta en estado CKS_RW_PUBLIC_SESSION", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));	
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN

			rv = C_Login(hSession[1], CKU_USER, NULL_PTR, 0);
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED y con tercer argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			rv = C_Login(hSession[1], 3, userPIN, strlen(userPIN));//3 es un tipo de usuario invalido
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED y con tipo de usuario invalido(3)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_TYPE_INVALID, ret));

			CK_UTF8CHAR badPIN[] = {"123455"};
			rv = C_Login(hSession[1], CKU_USER, badPIN, strlen(badPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED y PIN incorrecto", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_PIN_INCORRECT, ret));
			
			rv = C_Login(hSession[1], CKU_CONTEXT_SPECIFIC, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_CONTEXT_SPECIFIC y sin una operacion previa inciada", (int)slot);
			assert2(behavior, verifyCode(rv ,CKR_OPERATION_NOT_INITIALIZED, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[0], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/O creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			sprintf(ret, "Resultado de C_GetSessionInfo de una sesion RO sin logueo, debio tener en campo state CKS_RW_PUBLIC_SESSION");
			assert2(behavior, message(infoSession.state == CKS_RO_PUBLIC_SESSION, ret));
			//SESSIONINFOVERIFY
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN
			rv = C_InitPIN(hSession[0], userPIN, strlen(userPIN));
			sprintf(ret, "Llamado a C_InitPIN con sesion abierta en slot(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado que esta en estado CKS_RO_PUBLIC_SESSION", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));	
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN			

			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			//COSAS DE VERIFICACION?, SESSIONES USER R/O y R/W abiertas
			
			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/W creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			sprintf(ret, "Resultado de C_GetSessionInfo de una sesion RW con USER logueado, debio tener en campo state CKS_RW_USER_FUNCTIONS");
			assert2(behavior, message(infoSession.state == CKS_RW_USER_FUNCTIONS, ret));
			//SESSIONINFOVERIFY
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN
			rv = C_InitPIN(hSession[1], userPIN, strlen(userPIN));
			sprintf(ret, "Llamado a C_InitPIN con sesion abierta en slot(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado que esta en estado CKS_RW_USER_FUNCTIONS", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));	
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN


			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[0], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/O creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			sprintf(ret, "Resultado de C_GetSessionInfo de una sesion RO con user logueado, debio tener en campo state CKSRO_USER_FUNCTIONS");
			assert2(behavior, message(infoSession.state == CKS_RO_USER_FUNCTIONS, ret));
			//SESSIONINFOVERIFY
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN
			rv = C_InitPIN(hSession[0], userPIN, strlen(userPIN));
			sprintf(ret, "Llamado a C_InitPIN con sesion abierta en slot(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado que esta en estado CKS_RO_USER_FUNCTIONS", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));	
			//C_InitPIN test : CKR_USER_NOT_LOGGED_IN			
			
			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
			

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			//Testear que luego de cerrar todas las sesiones, se vuelve al estado public
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/W creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			sprintf(ret, "Resultado de C_GetSessionInfo luego de cerrar todas las sesiones y abrir una RW, debio tener en su campo state el valor CKS_RW_PUBLIC_SESSION");
			assert2(behavior, message(infoSession.state == CKS_RW_PUBLIC_SESSION, ret));

			//Testear que luego de cerrar todas las sesiones, se vuelve al estado public (FIN)
			int ind = indice((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
			
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Llamada a C_Login con una sesion R/W y R/O abiertas en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_SO, y con un CKU_SO antes logueado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY_EXISTS, ret));

			rv = C_CloseSession(hSession[0]);
			sprintf(ret, "Llamado a C_CloseSession de una sesion R/O creada con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));

			
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_SO y una R/W abierta", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/W creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			sprintf(ret, "Resultado de C_GetSessionInfo de una sesion RW con SO logueado, debio tener en campo state CKS_RW_SO_FUNCTIONS");
			assert2(behavior, message(infoSession.state == CKS_RW_SO_FUNCTIONS, ret));
			//SESSIONINFOVERIFY

			//VERIFICACION DE COSAS DE SESSION? DE RW SO SESSION
			
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado y con una session SO loguada", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_WRITE_SO_EXISTS, ret));

			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_SO, y con un CKU_SO antes logueado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_ALREADY_LOGGED_IN, ret));
			
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER, y con un CKU_SO antes logueado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_ANOTHER_ALREADY_LOGGED_IN, ret));

		}
	}
	free(buffer);
	

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	rv = C_Login(hSession[0], CKU_USER, userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_Login luego de un llamado a C_Finalize"));

	printlnLevel(showMessage, "Fin: test C_Login", level);

}


///
void esfuerzoLogin(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_Login", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testLogin(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_Login", level);
	}


}


///
void testLogout(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_Logout", level);
		
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	CK_SESSION_INFO infoSession;
	
	rv = C_Logout(hSession[0]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_Logout sin un llamado previo a C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_Logout(CK_INVALID_HANDLE);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Llamada a C_Logout con handle de sesion invalido"));	

	
	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_Logout(hSession[0]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/O no logueada creada con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));
					
			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W no logueada creada con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));			
			
			int ind = indice((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);

			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con una sesion R/O y una R/W abiertas y recien deslogueadas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));
			
			
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/W creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			sprintf(ret, "Resultado de C_GetSessionInfo de una sesion RW luego de desloguear, debio tener en campo state CKS_RW_PUBLIC_SESSION");
			assert2(behavior, message(infoSession.state == CKS_RW_PUBLIC_SESSION, ret));


			rv = C_GetSessionInfo(hSession[0], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/O creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			sprintf(ret, "Resultado de C_GetSessionInfo de una sesion RO luego de desloguear, debio tener en campo state CKS_RO_PUBLIC_SESSION");
			assert2(behavior, message(infoSession.state == CKS_RO_PUBLIC_SESSION, ret));

			
			rv = C_CloseSession(hSession[0]);
			sprintf(ret, "Llamado a C_CloseSession de una sesion R/O creada con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
						
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_SO y una R/W abierta", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_SO y con una sesion R/O abierta", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			//SESSIONINFOVERIFY
			rv = C_GetSessionInfo(hSession[1], &infoSession);
			sprintf(ret, "Llamada a C_GetSessionInfo con handle de sesion R/W creada en un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			sprintf(ret, "Resultado de C_GetSessionInfo de una sesion RW con SO recien deslogueado, debio tener en campo state CKSRW_PUBLIC_SESSION");
			assert2(behavior, message(infoSession.state == CKS_RW_PUBLIC_SESSION, ret));
			//SESSIONINFOVERIFY
		}

	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	rv = C_Logout(hSession[0]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_Logout luego de un llamado a C_Finalize"));
	
	printlnLevel(showMessage, "Fin: test C_Logout", level);

}


///
void esfuerzoLogout(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_Logout", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testLogout(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_Logout", level);
	}
}


///
void testSetPin(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_SetPIN", level);
	
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	
	rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_SetPIN sin un llamado previo a C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_SetPIN(CK_INVALID_HANDLE, userPIN, strlen(userPIN), userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID, "Llamada a C_SetPIN con handle de sesion invalido"));	

	
	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			

			rv = C_SetPIN(hSession[0], userPIN, strlen(userPIN), userPIN, strlen(userPIN));			
			sprintf(ret, "Llamada a C_SetPIN con sesion R/O abierta con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, ret));	


			//FUNNY TESTS CK_RW_PUBLIC_SESSION
			rv = C_SetPIN(hSession[1], NULL_PTR, 0, userPIN, strlen(userPIN));			
			sprintf(ret, "Llamada a C_SetPIN con sesion R/W abierta con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));
				
			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), NULL_PTR, 0);			
			sprintf(ret, "Llamada a C_SetPIN con sesion R/W abierta con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con cuarto argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			CK_UTF8CHAR_PTR longPIN = (CK_UTF8CHAR_PTR)malloc((infoToken.ulMaxPinLen + 2)*sizeof(CK_UTF8CHAR));
			int j;
			for(j = 0; j < infoToken.ulMaxPinLen + 1; ++j)
			{
				*(longPIN + j*sizeof(CK_UTF8CHAR)) = (CK_UTF8CHAR)'1';
			}
			*(longPIN + j*sizeof(CK_UTF8CHAR)) = 0;
			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), longPIN, infoToken.ulMaxPinLen + 1);
			sprintf(ret, "Llamada a C_SetPIN  con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un newPIN de largo 1 mas que el especificado en el ulMaxPinLen del resultado de C_GetTokenInfo", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, ret));
			
			if (infoToken.ulMinPinLen > 0)
			{
				CK_UTF8CHAR shortPIN [] = {""};
				rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), shortPIN, 0);
				sprintf(ret, "Llamada a C_SetPIN  con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un newPIN de largo 0 (\"\")", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, ret));
			}
			
			CK_UTF8CHAR badPIN[] = {"123455"};
			rv = C_SetPIN(hSession[1], badPIN, strlen(badPIN),userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_SetPIN  con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un oldPIN incorrecto", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_PIN_INCORRECT, ret));
			//_____
			

			CK_UTF8CHAR anotherPIN[] = {"123455"};
			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN),anotherPIN, strlen(anotherPIN));
			sprintf(ret, "Llamada a C_SetPIN  con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_SetPIN(hSession[1], anotherPIN, strlen(anotherPIN),userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_SetPIN  con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, luego de hacer el seteo inverso (oldPIN->newPIN, newPIN->oldPIN)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login luego de setear userPIN con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_SetPIN(hSession[0], userPIN, strlen(userPIN), userPIN, strlen(userPIN));			
			sprintf(ret, "Llamada a C_SetPIN con sesion R/O abierta y logueada con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, ret));
			

			//FUNNY TEST CK_RW_USER_FUNCTIONS
			rv = C_SetPIN(hSession[1], NULL_PTR, 0, userPIN, strlen(userPIN));			
			sprintf(ret, "Llamada a C_SetPIN con sesion R/W abierta y user logueado con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));
				
			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), NULL_PTR, 0);			
			sprintf(ret, "Llamada a C_SetPIN con sesion R/W abierta y user logueado con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con cuarto argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));			

			rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), longPIN, infoToken.ulMaxPinLen + 1);
			sprintf(ret, "Llamada a C_SetPIN  con una sesion R/W SO abierta y logueada con normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un newPIN de largo 1 mas que el especificado en el ulMaxPinLen del resultado de C_GetTokenInfo", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, ret));
			free(longPIN);

			if (infoToken.ulMinPinLen > 0)
			{
				CK_UTF8CHAR shortPIN [] = {""};
				rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), shortPIN, 0);
				sprintf(ret, "Llamada a C_SetPIN  con una sesion R/W SO abierta y logueada con normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un newPIN de largo 0 (\"\")", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_PIN_LEN_RANGE, ret));
			}

			rv = C_SetPIN(hSession[1], badPIN, strlen(badPIN),userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_SetPIN  con una sesion R/W SO abierta y logueada en normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un oldPIN incorrecto", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_PIN_INCORRECT, ret));
			//_____

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_CloseSession(hSession[0]);
			sprintf(ret, "Llamado a C_CloseSession de una sesion R/O creada con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
			int ind = indice((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);			
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_SO y una R/W abierta", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//FUNNY TEST CK_RW_SO_FUNCTIONS
			rv = C_SetPIN(hSession[1], NULL_PTR, 0, soPINs[ind], strlen(soPINs[ind]));			
			sprintf(ret, "Llamada a C_SetPIN con sesion R/W abierta y SO logueado con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));
				
			rv = C_SetPIN(hSession[1], soPINs[ind], strlen(soPINs[ind]), NULL_PTR, 0);			
			sprintf(ret, "Llamada a C_SetPIN con sesion R/W abierta y SO logueado con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con cuarto argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));
		
			rv = C_SetPIN(hSession[1], badPIN, strlen(badPIN),userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_SetPIN  con una sesion R/W SO abierta y logueada en SO en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un oldPIN incorrecto", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_PIN_INCORRECT, ret));
			//_____
		}
	}
	free(buffer);
	
	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	rv = C_SetPIN(hSession[1], userPIN, strlen(userPIN), userPIN, strlen(userPIN));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_SetPIN luego de un llamado a C_Finalize"));

	printlnLevel(showMessage, "Fin: test C_SetPIN", level);
}

///
void esfuerzoSetPin(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_SetPIN", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testSetPin(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_SetPIN", level);
	}

}


//Test de funciones de administracion de objectos
//Estas son C_CreateObject, C_DestroyObject, C_GenerateKeyPair, C_GetAttribute,
//C_FindObjectsInit, C_FindObjects, C_FindObjectsFinal
void testObjectManagementFunctions(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test functiones que administran objectos", level);
	testCreateObject(level + 1, showMessage);
	esfuerzoCreateObject(level + 1, repeticiones, showMessage);
	testDestroyObject(level + 1, showMessage);
	esfuerzoDestroyObject(level + 1, repeticiones, showMessage);
	testGenerateKeyPair(level + 1, showMessage);
	esfuerzoGenerateKeyPair(level + 1, repeticiones, showMessage);
	testGetAttributeValue(level + 1, showMessage);
	esfuerzoGetAttributeValue(level + 1, repeticiones, showMessage);
	testFindObjectsMechanism(level + 1, showMessage);
	esfuerzoFindObjectsMechanism(level + 1, repeticiones, showMessage);
	printlnLevel(showMessage, "Fin: test de funciones que administran objetos", level);
}

///
void testCreateObject(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_CreateObject", level);
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
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_CreateObject sin un llamado previo a C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_CreateObject(CK_INVALID_HANDLE, pubTemplate, 10, &hObject[1]);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_CreateObject con handle de session invalido"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//BEFORELOGINNORMAL	
			pubTemplate[7] = (CK_ATTRIBUTE){CKA_PRIVATE, &true, sizeof(true)};
			
			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta no logueada en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar crear un objeto de session", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));

			rv = C_CreateObject(hSession[0], pubTemplate, 10, &hObject[0]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/O abierta no logueada en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar crear un objeto de session", (int)slot);
			assert2(behavior, verifyCode2(rv, CKR_USER_NOT_LOGGED_IN, CKR_SESSION_READ_ONLY, ret));


			pubTemplate[4] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			
			rv = C_CreateObject(hSession[0], pubTemplate, 10, &hObject[0]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/O abierta no logueada en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar crear un objeto de token", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, ret));


			pubTemplate[4] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			
			//BEFORELOGINNORMAL(FIN)	
			
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
				//____
			//AFTERLOGINNORMAL
			


			rv = C_CreateObject(hSession[1], NULL_PTR, 0, &hObject[1]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con segundo argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			rv = C_CreateObject(hSession[1], pubTemplate, 10, NULL_PTR);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con cuarto argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));
			
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
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un template que no especifica la clase del objeto que se creara", (int)slot);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT, ret));//BECAUSE PAGE 101

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
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un template que especifica CKA_TOKEN true y CKA_TOKEN false", (int)slot);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID ,CKR_TEMPLATE_INCONSISTENT, ret));//BECAUSE PAGE 101
			
			CK_OBJECT_CLASS invalid;
			invalid = 8;
			pubTemplate[0].pValue = &invalid;
			pubTemplate[0].ulValueLen = sizeof(invalid);

			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un template que especifica un atributo CKA_CLASS invalido(%d)", (int)slot, (int)invalid);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT, ret));//BECAUSE PAGE 101



			pubTemplate[0].pValue = &pubClass;
			pubTemplate[0].ulValueLen = sizeof(pubClass);

			
			pubTemplate[7] = (CK_ATTRIBUTE){CKA_CERTIFICATE_CATEGORY, NULL_PTR, 0};
			
			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un template que contiene un tipo de atributo invalido", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_TYPE_INVALID, ret));


			pubTemplate[7] = (CK_ATTRIBUTE){CKA_PRIVATE, &false, sizeof(false)};			
			
			pubTemplate[4] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			
			rv = C_CreateObject(hSession[0], pubTemplate, 10, &hObject[0]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/O abierta y normal user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, ret));


			pubTemplate[4] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			

			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, luego de crear un objeto identico a otro recien creado exitosamente", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			//AFTERLOGINNORMAL

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_CloseSession(hSession[0]);
			sprintf(ret, "Llamado a C_CloseSession de una sesion R/O creada con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
		}
	}
	free(buffer);
	



	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));

	rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_CreateObject luego de un llamado a C_Finalize"));

	printlnLevel(showMessage, "Fin: test C_CreateObject", level);
}


///
void esfuerzoCreateObject(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_CreateObject", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testCreateObject(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_CreateObject", level);
	}
}

///AND ANALISYS OF CAPABILITIES
void testDestroyObject(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_DestroyObject", level);
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
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_DestroyObject sin un llamado previo a C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_DestroyObject(CK_INVALID_HANDLE, hObject[1]);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_DestroyObject con handle de session invalido"));


	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//BEFORELOGINNORMAL	
			rv = C_DestroyObject(hSession[1], CK_INVALID_HANDLE);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con handle de objeto invalido", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));


			//BEFORELOGINNORMAL(FIN)	
			
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
				//____
			//AFTERLOGINNORMAL
			


			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[0]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado,  al intentar crear un objeto de token y privado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			//

			pubTemplate[2].pValue = &true;
			pubTemplate[2].ulValueLen = sizeof(true);
			pubTemplate[7].pValue = &false;
			pubTemplate[7].ulValueLen = sizeof(false);


			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[1]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar crear un objeto de token y publico", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[6]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al crear un objeto de token identico a uno creado anteriormente", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[7]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al crear un objeto de token identico a uno creado anteriormente", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			//
			pubTemplate[2].pValue = &false;
			pubTemplate[2].ulValueLen = sizeof(false);
			pubTemplate[7].pValue = &true;
			pubTemplate[7].ulValueLen = sizeof(true);

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[2]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar crear un objeto de sesion y privado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_CreateObject(hSession[0], pubTemplate, 9, &hObject[4]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/O abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al crear un objeto de sesion identico a uno creado anteriormente", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			//

			pubTemplate[2].pValue = &false;
			pubTemplate[2].ulValueLen = sizeof(false);
			pubTemplate[7].pValue = &false;
			pubTemplate[7].ulValueLen = sizeof(false);

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[3]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar crear un objeto de session y publico", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_CreateObject(hSession[0], pubTemplate, 9, &hObject[5]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/O abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar crear un objeto de sesion identico a uno creado anteriormente", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			//
			
			pubTemplate[2].pValue = &true;
			pubTemplate[2].ulValueLen = sizeof(true);
			pubTemplate[7].pValue = &true;
			pubTemplate[7].ulValueLen = sizeof(true);

			rv = C_DestroyObject(hSession[0], hObject[0]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/O abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de token privado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, ret));
			
			rv = C_DestroyObject(hSession[0], hObject[1]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/O abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de token publico", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, ret));
			//AFTERLOGINNORMAL

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));


			rv = C_DestroyObject(hSession[0], hObject[0]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/O abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de token privado", (int)slot);
			assert2(behavior, verifyCode2(rv, CKR_SESSION_READ_ONLY, CKR_OBJECT_HANDLE_INVALID, ret));//No hay un buen codigo de retorno para esto

			rv = C_DestroyObject(hSession[0], hObject[1]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/O abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de token publico", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, ret));
			
			rv = C_DestroyObject(hSession[0], hObject[2]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/O abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de sesion privado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));	

			rv = C_DestroyObject(hSession[1], hObject[0]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de token privado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));//No hay un buen codigo de retorno para esto

			rv = C_DestroyObject(hSession[1], hObject[2]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de sesion privado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));	
			
			rv = C_CloseSession(hSession[0]);
			sprintf(ret, "Llamado a C_CloseSession de una sesion R/O creada con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));

			int ind = indice((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);			
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_SO y una sesion R/W abierta", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_DestroyObject(hSession[1], hObject[0]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta y SO user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de token privado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));//No hay un buen codigo de retorno para esto

			rv = C_DestroyObject(hSession[1], hObject[2]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta y SO user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de sesion privado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));//No hay un buen codigo de retorno para esto

			

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_DestroyObject(hSession[1], hObject[1]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de token publico", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_DestroyObject(hSession[1], hObject[6]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de token publico", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_DestroyObject(hSession[1], hObject[3]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de sesion publico", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_DestroyObject(hSession[1], hObject[4]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un de sesion privado de una sesion que ya fue cerrada", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));//No hay un buen codigo de retorno

			rv = C_DestroyObject(hSession[1], hObject[5]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un de sesion publico de una sesion que ya fue cerrada", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));

			
						
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y una sesion R/W abierta", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_DestroyObject(hSession[1], hObject[0]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta y normal user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de token privado, luego de desloguarse y volver a loguearse", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_DestroyObject(hSession[1], hObject[2]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta y normal user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de sesion privado, luego de desloguarse y volver a loguearse", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_DestroyObject(hSession[1], hObject[2]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta y normal user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un objeto de sesion privado, anteriormente destruido", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));

			rv = C_DestroyObject(hSession[1], hObject[4]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta y normal user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un de sesion privado de una sesion que ya fue cerrada", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));

			rv = C_DestroyObject(hSession[1], hObject[5]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta y normal user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar destruir un de sesion publico de una sesion que ya fue cerrada(y abierta nuevamente)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));

			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
			

			char * textLabel = "A token";
        		CK_UTF8CHAR paddedLabel[32];
        		memset(paddedLabel, ' ', sizeof(paddedLabel));
        		memcpy(paddedLabel, textLabel, strlen(textLabel));
			
			sprintf(ret, "Llamada a C_InitToken con slotID(%d), el cual tiene un token inicializado en el", (int)slot);
			rv = C_InitToken(slot, soPINs[ind], strlen(soPINs[ind]), paddedLabel);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_InitPIN(hSession[1], userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_InitPIN con una sesion R/W SO abierta y logueada en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con segundo argumento %s y tercer argumento %d", (int)slot, (char *)userPIN, (int)strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_DestroyObject(hSession[1], hObject[7]);
			sprintf(ret, "Llamado a C_DestroyObject con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, luego de reinicializar el token", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));
			
		}
	}
	free(buffer);
	



	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));

	rv = C_CreateObject(hSession[1], pubTemplate, 10, &hObject[1]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_CreateObject luego de un llamado a C_Finalize"));
	
	printlnLevel(showMessage, "Fin: test C_DestroyObject", level);

}

///
void esfuerzoDestroyObject(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_DestroyObject", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testDestroyObject(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_DestroyObject", level);
	}

}

///
void testGenerateKeyPair(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_GenerateKeyPair", level);

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
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_GenerateKeyPair sin un llamado previo a C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_GenerateKeyPair(CK_INVALID_HANDLE, &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_GenerateKeyPair con handle de session invalido"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//BEFORELOGINNORMAL	
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));

			rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/O abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));


			privateKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			publicKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/O abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_USER_NOT_LOGGED_IN, ret));
			
			privateKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			publicKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			
			//BEFORELOGINNORMAL(FIN)	
			
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
				//____
			//AFTERLOGINNORMAL
			


			rv = C_GenerateKeyPair(hSession[1], &mechanism, NULL_PTR, 0, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GeneratePair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con tercer argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, NULL_PTR, 0, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GeneratePair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con quinto argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, NULL_PTR, &hPrivateKey);
			sprintf(ret, "Llamado a C_GeneratePair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con sexto argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, NULL_PTR);
			sprintf(ret, "Llamado a C_GeneratePair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con septimo argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));
			
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
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un template que no especifica el exponente ni los bits del modulo", (int)slot);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT, ret));//BECAUSE PAGE 101

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
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un template que especifica CKA_TOKEN true y CKA_TOKEN false", (int)slot);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT, ret));//BECAUSE PAGE 101
			
			CK_KEY_TYPE another;
			another = CKK_DSA;
			publicKeyTemplate[3].pValue = &another;
			publicKeyTemplate[3].ulValueLen = sizeof(another);
			privateKeyTemplate[3].pValue = &another;
			privateKeyTemplate[3].ulValueLen = sizeof(another);

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un template que  especifica en CKA_KEY_TYPE, CKK_DSA(y cuyo mecanismo es RSA)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_TEMPLATE_INCONSISTENT, ret));//SE ESPECIFICA EXPLICITAMENTE
			
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
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un template que  especifica en CKA_CLASS una invalida(%d)", (int)slot, (int)invalid);
			assert2(behavior, verifyCode(rv, CKR_TEMPLATE_INCONSISTENT, ret));//SE ESPECIFICA EXPLICITAMENTE
			
			publicKeyTemplate[2].pValue = &pubClass;
			publicKeyTemplate[2].ulValueLen = sizeof(pubClass);
			privateKeyTemplate[2].pValue = &priClass;
			privateKeyTemplate[2].ulValueLen = sizeof(priClass);

			
			publicKeyTemplate[3] = (CK_ATTRIBUTE){CKA_CERTIFICATE_CATEGORY, NULL_PTR, 0};
			privateKeyTemplate[3] = (CK_ATTRIBUTE){CKA_CERTIFICATE_CATEGORY, NULL_PTR, 0};
			
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con un template que contiene un tipo de atributo invalido", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_TYPE_INVALID, ret));
			
			publicKeyTemplate[3] = (CK_ATTRIBUTE){CKA_KEY_TYPE, &keyType, sizeof(keyType)};
			privateKeyTemplate[3] = (CK_ATTRIBUTE){CKA_KEY_TYPE, &keyType, sizeof(keyType)};
			
			//
			publicKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			privateKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &true, sizeof(true)};
			
			rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/O abierta y normal user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_SESSION_READ_ONLY, ret));

			publicKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			privateKeyTemplate[0] = (CK_ATTRIBUTE){CKA_TOKEN, &false, sizeof(false)};
			
			mechanism.mechanism = 0x9999;
				
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y normal user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con mecanismo invalido(%d)", (int)slot, (int)mechanism.mechanism);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_INVALID, ret));



			mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
			
			CK_BYTE otherPublicValue[128];
    			mechanism.pParameter = otherPublicValue ;
			mechanism.ulParameterLen = sizeof(otherPublicValue);
			//196			
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y normal user logueado en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con parametro del mecanismo invalido CKR_MECHANISM_PARAM_INVALID", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_PARAM_INVALID, ret));
				
			mechanism.pParameter = NULL_PTR ;
			mechanism.ulParameterLen = 0;
			
			///

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));


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
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, al intentar crear una par RSA, dando su modulo en el template", (int)slot);
			assert2(behavior, verifyCode3(rv, CKR_TEMPLATE_INCOMPLETE, CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT, ret));//No hay un buen codigo de retorno para esto

			//AFTERLOGINNORMAL

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_CloseSession(hSession[0]);
			sprintf(ret, "Llamado a C_CloseSession de una sesion R/O creada con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
		}
	}
	free(buffer);
	



	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));

	rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_GenerateKeyPair luego de un llamado a C_Finalize"));

	printlnLevel(showMessage, "Fin: test C_GenerateKeyPair", level);

}

///
void esfuerzoGenerateKeyPair(int level, int repeticiones, int showMessage)
{

	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_GenerateKeyPair", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testGenerateKeyPair(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_GenerateKeyPair", level);
	}

}

///
void testGetAttributeValue(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_GetAttributeValue", level);
	
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
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_GetAttributeValue sin un llamado previo a C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_GetAttributeValue(CK_INVALID_HANDLE, hPublicKey, template1, 1);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_GetAttributeValue con handle de session invalido"));


	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_GetAttributeValue(hSession[1], CK_INVALID_HANDLE, template1, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con handle de objecto invalido", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OBJECT_HANDLE_INVALID, ret));
			

			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_CreateObject(hSession[1], pubTemplate, 10, &hCreateKey);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 7, privateKeyTemplate, 9, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			privateKeyTemplate[7] = (CK_ATTRIBUTE){CKA_EXTRACTABLE, &true, sizeof(true)};
			privateKeyTemplate[8] = (CK_ATTRIBUTE){CKA_SENSITIVE, &true, sizeof(true)};
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 7, privateKeyTemplate, 9, &hPublicKey2, &hPrivateKey2);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			privateKeyTemplate[7] = (CK_ATTRIBUTE){CKA_EXTRACTABLE, &false, sizeof(false)};
			privateKeyTemplate[8] = (CK_ATTRIBUTE){CKA_SENSITIVE, &false, sizeof(false)};


			rv = C_GetAttributeValue(hSession[1], hCreateKey, NULL_PTR, 0);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, tercer argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			CK_ATTRIBUTE senTemplate[] = {
			{CKA_PRIME_1, NULL_PTR, 0}			
			};			

			rv = C_GetAttributeValue(hSession[1], hPrivateKey, senTemplate, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, de un objeto CKA_EXTRACTALBE false, al pedir un atributo sensible", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_SENSITIVE, ret));

			
			sprintf(ret, "Resultado de llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, de un objeto CKA_EXTRACTALBE false, al pedir un atributo sensible, debio tener en tu campo ulValueLen -1", (int)slot);
			assert2(behavior, message(((CK_LONG)senTemplate[0].ulValueLen) == -1, ret));
			
			senTemplate[0].ulValueLen == 0;

			rv = C_GetAttributeValue(hSession[1], hPrivateKey2, senTemplate, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, de un objeto CKA_SENSITIVE true, al pedir un atributo sensible", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_SENSITIVE, ret));

			
			sprintf(ret, "Resultado de llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, de un objeto CKA_SENSITIVE true, al pedir un atributo sensible, debio tener en tu campo ulValueLen -1", (int)slot);
			assert2(behavior, message(((CK_LONG)senTemplate[0].ulValueLen) == -1, ret));
			

			CK_ATTRIBUTE invalidTypeTemplate[] = {
			{CKA_CERTIFICATE_CATEGORY, NULL_PTR, 0}
			};
			
			rv = C_GetAttributeValue(hSession[1], hCreateKey, invalidTypeTemplate, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template que especifica un atributo invalido para el objeto", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_TYPE_INVALID, ret));

			sprintf(ret, "Resultado de llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template que especifica un atributo invalido para el objeto debio tener ulValueLen -1", (int)slot);
			assert2(behavior, message(((CK_LONG)invalidTypeTemplate[0].ulValueLen) == -1, ret));


			rv = C_GetAttributeValue(hSession[1], hCreateKey, template1, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template que pide atributo CKA_CLASS", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			CK_ULONG len = template1[0].ulValueLen;
			template1[0].pValue = (CK_BYTE_PTR)malloc(len);
			template1[0].ulValueLen = 0;

			rv = C_GetAttributeValue(hSession[1], hCreateKey, template1, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template con memoria suficiente pero con ulValueLen en 0", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_BUFFER_TOO_SMALL, ret));

			sprintf(ret, "Resultado de llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template con memoria suficiente pero con ulValueLen en 0 debio tener ulValueLen -1", (int)slot);
			assert2(behavior, message(((CK_LONG)template1[0].ulValueLen) == -1, ret));
			
			template1[0].ulValueLen = len;

			rv = C_GetAttributeValue(hSession[1], hCreateKey, template1, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template con memoria y ulValueLen suficiente", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			sprintf(ret, "Resultado de llamada a C_GetAttributeValue exitosa con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, tiene un valor diferente al especificado al crear el objeto", (int)slot);
			CK_OBJECT_CLASS_PTR result = (CK_OBJECT_CLASS_PTR)(template1[0].pValue);
			assert2(behavior, message(*result == pubClass, ret));


			free(template1[0].pValue);
			template1[0].pValue = NULL_PTR;
			template1[0].ulValueLen = 0;
			
			CK_ATTRIBUTE partialTemplate[] = {
			{CKA_CLASS, NULL_PTR, 0},
			{CKA_PRIME_1, NULL_PTR, 0}
			};

			rv = C_GetAttributeValue(hSession[1], hPrivateKey2, partialTemplate, 2);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template que pide el atributo CKA_CLASS y un atributo sensible", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ATTRIBUTE_SENSITIVE, ret));

			sprintf(ret, "Resultado de llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template que pide el atributo CKA_CLASS y un atributo sensible, debio tener en tu campo del atributo sensible ulValueLen -1", (int)slot);
			assert2(behavior, message(((CK_LONG)partialTemplate[1].ulValueLen) == -1, ret));

			sprintf(ret, "Resultado de llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template que pide el atributo CKA_CLASS y un atributo sensible, debio tener en tu campo del atributo CKA_CLASS ulValueLen distinto de -1 y 0", (int)slot);
			assert2(behavior, message(((CK_LONG)partialTemplate[0].ulValueLen) != -1 && ((CK_LONG)partialTemplate[0].ulValueLen) != 0, ret));

/////
			CK_ATTRIBUTE localTemplate[] = {
			{CKA_LOCAL, NULL_PTR, 0}
			};
			
			rv = C_GetAttributeValue(hSession[1], hCreateKey, localTemplate, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template que pide atributo CKA_LOCAL", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			localTemplate[0].pValue = (CK_BYTE_PTR)malloc(localTemplate[0].ulValueLen);
			
			rv = C_GetAttributeValue(hSession[1], hCreateKey, localTemplate, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template con memoria y ulValueLen suficiente", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			sprintf(ret, "Resultado de llamada a C_GetAttributeValue exitosa con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, de una llave publica creada con C_CreateObject deberia tener un valor de CKA_LOCAL, CK_FALSE", (int)slot);
			CK_BBOOL * result2 = (CK_BBOOL *)(localTemplate[0].pValue);
			assert2(behavior, message(*result2 == CK_FALSE, ret));


			free(localTemplate[0].pValue);
			localTemplate[0].pValue = NULL_PTR;
			localTemplate[0].ulValueLen = 0;


			rv = C_GetAttributeValue(hSession[1], hPublicKey, localTemplate, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template que pide atributo CKA_LOCAL", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			localTemplate[0].pValue = (CK_BYTE_PTR)malloc(localTemplate[0].ulValueLen);
			
			rv = C_GetAttributeValue(hSession[1], hPublicKey, localTemplate, 1);
			sprintf(ret, "Llamada a C_GetAttributeValue con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template con memoria y ulValueLen suficiente", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			sprintf(ret, "Resultado de llamada a C_GetAttributeValue exitosa con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, de una llave publica creada con C_GenerateKeyPair deberia tener un valor de CKA_LOCAL, CK_TRUE", (int)slot);
			result2 = (CK_BBOOL *)(localTemplate[0].pValue);
			assert2(behavior, message(*result2 == CK_TRUE, ret));


			free(localTemplate[0].pValue);
			localTemplate[0].pValue = NULL_PTR;
			localTemplate[0].ulValueLen = 0;
			
		}
	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));

	rv = C_GetAttributeValue(hSession[1], hPublicKey, template1, 1);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_GetAttributeValue luego de un llamado a C_Finalize"));

	printlnLevel(showMessage, "Fin: test C_GetAttributeValue", level);
}


///
void esfuerzoGetAttributeValue(int level, int repeticiones, int showMessage)
{

	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_GetAttributeValue", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testGetAttributeValue(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_GetAttributeValue", level);
	}

}


///
void testFindObjectsMechanism(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test Find Objects(C_FindObjects|Init|Final)", level);
	
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
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_FindObjectsInit sin un llamado previo a C_Initialize"));

	rv = C_FindObjects(hSession[1], &hReceiver[0], 1, &returned);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_FindObjects sin un llamado previo a C_Initialize"));	

	rv = C_FindObjectsFinal(hSession[1]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_FindObjectsFinal sin un llamado previo a C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_FindObjectsInit(CK_INVALID_HANDLE, NULL_PTR, 0);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_FindObjectsInit con handle de session invalido"));

	rv = C_FindObjects(CK_INVALID_HANDLE, &hReceiver[0], 1, &returned);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_FindObjects con handle de session invalido"));

	rv = C_FindObjectsFinal(CK_INVALID_HANDLE);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_FindObjectsFinal con handle de session invalido"));



	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 1);
			sprintf(ret, "Llamada a C_FindObjectInit con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR y tercero distinto de 0", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			

			////	
			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			////



			
			rv = C_FindObjects(hSession[1], &hReceiver[0], 1, &returned);
			sprintf(ret, "Llamado a C_FindObjects con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, (aun no se llama a C_FindObjectsInit)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));

			rv = C_FindObjectsFinal(hSession[1]);
			sprintf(ret, "Llamado a C_FindObjectsFinal con sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, (aun no se llama a C_FindObjectsInit)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));

			//First 0
			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
			sprintf(ret, "Llamada a C_FindObjectInit con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR y tercero 0(todos los objetos)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_FindObjects(hSession[1], NULL_PTR, 1, &returned);
			sprintf(ret, "Llamada a C_FindObjectInit con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			rv = C_FindObjects(hSession[1], &hReceiver[0], 1, NULL_PTR);
			sprintf(ret, "Llamada a C_FindObjectInit con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con cuarto argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));



			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
			sprintf(ret, "Llamada a C_FindObjectInit con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR y tercero 0(todos los objetos), y con una busqueda antes inicializada", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_ACTIVE, ret));


			rv = C_FindObjects(hSession[0], &hReceiver[0], 1, &returned);
			sprintf(ret, "Llamado a C_FindObjects con sesion R/O abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED(en esta sesion no se ha inicializado una operacion de busqueda)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));

			rv = C_FindObjectsFinal(hSession[0]);
			sprintf(ret, "Llamado a C_FindObjectsFinal con sesion R/O abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED(en esta sesion no se ha inicializado una operacion de busqueda)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));
			

			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			sprintf(ret, "Llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			
			sprintf(ret, "Resultado de llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, debio  retornar 0 en ulObjectCount, pues se buscaron objetos en un token recien inicializado, el resultado retornado fue %d", (int)slot, (int)returned);
			assert2(behavior, message(returned == 0, ret));


			rv = C_FindObjectsFinal(hSession[1]);
			sprintf(ret, "Llamado a C_FindObjectsFinal con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_FindObjects(hSession[1], &hReceiver[0], 1, &returned);
			sprintf(ret, "Llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED(se acaba de finalizar una operacion de busqueda)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));

			rv = C_FindObjectsFinal(hSession[1]);
			sprintf(ret, "Llamado a C_FindObjectsFinal con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED(se acaba de finalizar una operacion de busqueda)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));

			
			//CREATE OBJECTS
			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[0]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			//

			pubTemplate[2].pValue = &true;
			pubTemplate[2].ulValueLen = sizeof(true);
			pubTemplate[7].pValue = &false;
			pubTemplate[7].ulValueLen = sizeof(false);


			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[1]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[4]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//
			pubTemplate[2].pValue = &false;
			pubTemplate[2].ulValueLen = sizeof(false);
			pubTemplate[7].pValue = &true;
			pubTemplate[7].ulValueLen = sizeof(true);

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[2]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//

			pubTemplate[2].pValue = &false;
			pubTemplate[2].ulValueLen = sizeof(false);
			pubTemplate[7].pValue = &false;
			pubTemplate[7].ulValueLen = sizeof(false);

			rv = C_CreateObject(hSession[1], pubTemplate, 9, &hObject[3]);
			sprintf(ret, "Llamado a C_CreateObject con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//
			
			pubTemplate[2].pValue = &true;
			pubTemplate[2].ulValueLen = sizeof(true);
			pubTemplate[7].pValue = &true;
			pubTemplate[7].ulValueLen = sizeof(true);
			//CREATE OBJECTS(FIN)

			//CAP
			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
			sprintf(ret, "Llamada a C_FindObjectInit con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR y tercero 0(todos los objetos)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//CAPCHECK NORMAL
			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			sprintf(ret, "Llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			
			sprintf(ret, "Resultado de llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, debio  retornar 5 en ulObjectCount, pues se crearon 5 objetos en un token recien inicializado, el resultado retornado fue %d", (int)slot, (int)returned);
			assert2(behavior, message(returned == 5, ret));			



			rv = C_FindObjectsFinal(hSession[1]);
			sprintf(ret, "Llamado a C_FindObjectsFinal con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));


			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_CloseSession(hSession[0]);
			sprintf(ret, "Llamado a C_CloseSession de una sesion R/O creada con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));

			int ind = indice((int)slot, (int *)slotsWithInitToken, (int)numberOfSlotsWithInitToken);
			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_SO y con una R/W abierta", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//CAP
			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
			sprintf(ret, "Llamada a C_FindObjectInit con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR y tercero 0(todos los objetos)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			//CAPCHECK SO
			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			sprintf(ret, "Llamado a C_FindObjects con sesion R/W abierta y logueada en SO user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			
			sprintf(ret, "Resultado de llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, debio  retornar 3 en ulObjectCount, pues se crearon 5 objetos en un token, de los cuales 2 son privados, el resultado retornado fue %d", (int)slot, (int)returned);
			assert2(behavior, message(returned == 3, ret));

			rv = C_FindObjectsFinal(hSession[1]);
			sprintf(ret, "Llamado a C_FindObjectsFinal con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_SO una sesion R/W abierta", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));


			//RESULT CHECK
			CK_ATTRIBUTE classTemplate[] = {
			{CKA_CLASS, &pubClass, sizeof(pubClass)}
			};
			rv = C_FindObjectsInit(hSession[1], classTemplate, 1);
			sprintf(ret, "Llamada a C_FindObjectInit con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template que especifica el atributo CKA_CLASS", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			sprintf(ret, "Llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			
			sprintf(ret, "Resultado de llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, debio  retornar 3 en ulObjectCount, pues se crearon 5 objetos en un token, de los cuales 2 son privados y se especifico en el template una cierta CKA_CLASS que los 3 objetos antes mencionados tenian por igual, el resultado retornado fue %d", (int)slot, (int)returned);
			assert2(behavior, message(returned == 3, ret));

			rv = C_FindObjectsFinal(hSession[1]);
			sprintf(ret, "Llamado a C_FindObjectsFinal con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			

			classTemplate[0] = (CK_ATTRIBUTE){CKA_CLASS, &priClass, sizeof(priClass)};
			rv = C_FindObjectsInit(hSession[1], classTemplate, 1);
			sprintf(ret, "Llamada a C_FindObjectInit con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con un template que especifica el atributo CKA_CLASS", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			sprintf(ret, "Llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));			

			sprintf(ret, "Resultado de llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, debio  retornar 0 en ulObjectCount, pues se no se ha creado ningun objeto de la clase CKA_CLASS especificada en el template de C_FindObjetsInit, el resultado retornado fue %d", (int)slot, (int)returned);
			assert2(behavior, message(returned == 0, ret));

			rv = C_FindObjectsFinal(hSession[1]);
			sprintf(ret, "Llamado a C_FindObjectsFinal con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));			
	
			//REINIT
			rv = C_CloseAllSessions(slot);
			sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
			

			char * textLabel = "A token";
        		CK_UTF8CHAR paddedLabel[32];
        		memset(paddedLabel, ' ', sizeof(paddedLabel));
        		memcpy(paddedLabel, textLabel, strlen(textLabel));
	
			sprintf(ret, "Llamada a C_InitToken con slotID(%d), el cual tiene un token inicializado en el", (int)slot);
			rv = C_InitToken(slot, soPINs[ind], strlen(soPINs[ind]), paddedLabel);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Login(hSession[1], CKU_SO, soPINs[ind], strlen(soPINs[ind]));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_InitPIN(hSession[1], userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_InitPIN con una sesion R/W SO abierta y logueada en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, y con segundo argumento %s y tercer argumento %d", (int)slot, (char *)userPIN, (int)strlen(userPIN));
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			//CAP
			rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
			sprintf(ret, "Llamada a C_FindObjectInit con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, con segundo argumento NULL_PTR y tercero 0(todos los objetos)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));


			//CAPCHECK REINIT
			rv = C_FindObjects(hSession[1], hReceiver, 10, &returned);
			sprintf(ret, "Llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			
			sprintf(ret, "Resultado de llamado a C_FindObjects con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, debio  retornar 0 en ulObjectCount, pues se reinicializo el token, el resultado retornado fue %d", (int)slot, (int)returned);
			assert2(behavior, message(returned == 0, ret));
	
			rv = C_FindObjectsFinal(hSession[1]);
			sprintf(ret, "Llamado a C_FindObjectsFinal con sesion R/W abierta y logueada en normal user  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		}
	}
	free(buffer);


	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));

	rv = C_FindObjectsInit(hSession[1], NULL_PTR, 0);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_FindObjectsInit luego de un llamado a C_Finalize"));

	rv = C_FindObjects(hSession[1], &hReceiver[0], 1, &returned);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_FindObjects luego de un llamado a C_Finalize"));


	rv = C_FindObjectsFinal(hSession[1]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_FindObjectsFinal luego de un llamado a C_Finalize"));

	
	printlnLevel(showMessage, "Fin: test Find Objects(C_FindObjects|Init|Final)", level);
}


///
void esfuerzoFindObjectsMechanism(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo Find Objects(C_FindObjects|Init|Final)", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testFindObjectsMechanism(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo Find Objects(C_FindObjects|Init|Final)", level);
	}
}
///Se testean los mecanismos de Sign y Digest
void testMechanisms(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test Mecanismos", level);
	testSignMechanism(level + 1, showMessage);
	esfuerzoSignMechanism(level + 1, repeticiones, showMessage);
	testDigestMechanism(level + 1, showMessage);
	esfuerzoDigestMechanism(level + 1, repeticiones, showMessage);
	printlnLevel(showMessage, "Fin: test Mecanismos", level);
}

///
void testSignMechanism(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test Sign(C_Sign|Init)", level);
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
	static CK_BYTE value[8] = "aVALUEEE";//FIND(FIPS PUBS 46-3)


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
	CK_ULONG maxInput[4] = {0, 0, modulusBits/8 - 11, 0}; // Si es 0 no se hace el test
	CK_ULONG lengths [4] = {0, 0, modulusBits/8, modulusBits/8}; // Si es 0 no se hace el test
	CK_ULONG n = 4;
	CK_BYTE_PTR data = "Some data";
	CK_ULONG signatureLen;
		
	rv = C_SignInit(hSession[1], &signMechanism[2], hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_SignInit sin un llamado previo a C_Initialize"));

	rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_Sign sin un llamado previo a C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_SignInit(CK_INVALID_HANDLE, &signMechanism[2], hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_SignInit con handle de session invalido"));

	rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_Sign con handle de session invalido"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	int signInitialized;
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			//____
			//Create Keys
			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 10, &hPublicKey, &hPrivateKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplateNoSign, 9, &hPublicNoSignKey, &hPrivateNoSignKey);
			sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));


			rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
			sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , antes de una llamada a C_SignInit", (int)slot);			
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));
			
			rv = C_SignInit(hSession[1], &signMechanism[2], CK_INVALID_HANDLE);
			sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con handle de llave invalido", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_KEY_HANDLE_INVALID, ret));
			
			///	if (rv == CKR_OK)
	{
		rv = C_CloseAllSessions(slot);
		sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK ,ret));				

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
		sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 10, &hPublicKey, &hPrivateKey);
		sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplateNoSign, 9, &hPublicNoSignKey, &hPrivateNoSignKey);
		sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
	}
///

			rv = C_SignInit(hSession[1], NULL_PTR, hPrivateKey);
			sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con segundo argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));
///
	if (rv == CKR_OK)
	{
		rv = C_CloseAllSessions(slot);
		sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK ,ret));				

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
		sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 10, &hPublicKey, &hPrivateKey);
		sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplateNoSign, 9, &hPublicNoSignKey, &hPrivateNoSignKey);
		sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
	}
///			

			rv = C_SignInit(hSession[1], &signMechanism[0], hPrivateKey);
			sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con segundo argumento un mecanismo invalido(%d)", (int)slot, (int)signMechanism[0].mechanism);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_INVALID, ret));
///
	if (rv == CKR_OK)
	{
		rv = C_CloseAllSessions(slot);
		sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK ,ret));				

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
		sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 10, &hPublicKey, &hPrivateKey);
		sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplateNoSign, 9, &hPublicNoSignKey, &hPrivateNoSignKey);
		sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
	}
///
			
			rv = C_SignInit(hSession[1], &signMechanism[1], hPrivateKey);
			sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con segundo argumento un mecanismo valido pero con parametros invalidos", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_PARAM_INVALID, ret));
///
	if (rv == CKR_OK)
	{
		rv = C_CloseAllSessions(slot);
		sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK ,ret));				

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
		sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 10, &hPublicKey, &hPrivateKey);
		sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplateNoSign, 9, &hPublicNoSignKey, &hPrivateNoSignKey);
		sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
	}
///
			
			rv = C_SignInit(hSession[1], &signMechanism[2], hPrivateNoSignKey);
			sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , una llave que tiene en su atributo CKA_SIGN en CK_FALSE", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_KEY_FUNCTION_NOT_PERMITTED, ret));
///
	if (rv == CKR_OK)
	{
		rv = C_CloseAllSessions(slot);
		sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK ,ret));				

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
		sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplate, 10, &hPublicKey, &hPrivateKey);
		sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 9, privateKeyTemplateNoSign, 9, &hPublicNoSignKey, &hPrivateNoSignKey);
		sprintf(ret, "Llamado a C_GenerateKeyPair con sesion R/W abierta y logueada en normal user  n slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
	}
///
			

			rv = C_SignInit(hSession[1], &signMechanism[2], hPrivateKey);
			sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));


			rv = C_SignInit(hSession[1], &signMechanism[2], hPrivateKey);
			sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , inmediatamente luego de otra llamada a C_SignInit", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_ACTIVE, ret));


			rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, NULL_PTR);
			sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con cuarto argumento NULL_PTR", (int)slot);	
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
			sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , luego de una llamada erronea a C_Sign", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));
			
			if(rv == CKR_OPERATION_NOT_INITIALIZED)
			{			
				rv = C_SignInit(hSession[1], &signMechanism[2], hPrivateKey);
				sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED luego de finalizacion erronea de C_Sign", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
			}

			rv = C_Sign(hSession[0], data, strlen(data), NULL_PTR, &signatureLen);
			sprintf(ret, "Llamada a C_Sign con una sesion R/O abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,(esa session no ha inicializado ninguna operacion de Sign)", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));

			rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
    			sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			CK_BYTE_PTR pSignature = (CK_BYTE_PTR)malloc(signatureLen*sizeof(CK_BYTE));

			signatureLen = 0;
			rv = C_Sign(hSession[1], data, strlen(data), pSignature, &signatureLen);
    			sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , luego de setear el signatureLen en 0", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_BUFFER_TOO_SMALL, ret));

			rv = C_Sign(hSession[1], data, strlen(data), pSignature, &signatureLen);
    			sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con un signatureLen rellenado luego de un codigo CKR_BUFFER_TOO_SMALL", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
    			sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , luego de un llamado a C_Sign terminado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));
			free(pSignature);

			//COMPROBACIONES(with the first and then call succesfully)

			//TEST DE RESULTADOS
			int j;
			for(j = 2; j < n; ++j)
			{
				char meca [100];
				getMechanismName((signMechanism[j].mechanism), meca);
				
				rv = C_SignInit(hSession[1], &signMechanism[j], hPrivateKey);
				sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				if (maxInput[j])
				{
					CK_BYTE maxData[maxInput[j] + 1];
					rv = C_Sign(hSession[1], maxData, maxInput[j] + 1, NULL_PTR, &signatureLen);
    					sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con el mecanismo %s, con un input mas largo que el maximo permitido por el mecanismo", (int)slot, meca);	
					assert2(behavior, verifyCode(rv, CKR_DATA_LEN_RANGE, ret));	
					if(rv == CKR_DATA_LEN_RANGE)
					{						
						rv = C_SignInit(hSession[1], &signMechanism[j], hPrivateKey);
						sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, luego de un llamado fallido a C_Sign", (int)slot);
						assert2(behavior, verifyCode(rv, CKR_OK, ret));
					}
					
				}
				rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
    				sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				if (lengths[j])
				{	
					sprintf(ret, "Largo del sign dado por  C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, del mecanismo %s, debio ser %d", (int)slot, meca, (int)(lengths[j]));
					assert2(behavior, message(signatureLen == lengths[j],ret));				
				}
				pSignature = (CK_BYTE_PTR)malloc(signatureLen*sizeof(CK_BYTE));
				
				rv = C_Sign(hSession[1], data, strlen(data), pSignature, &signatureLen);
	    			sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

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
					sprintf(ret, "Llamada a C_GetAttributeValue con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));					
	
					
					modulo = (CK_BYTE_PTR)malloc(temp[0].ulValueLen);
					exponentePublico = (CK_BYTE_PTR)malloc(temp[1].ulValueLen);
					exponentePrivado = (CK_BYTE_PTR)malloc(temp[2].ulValueLen);

					temp[0].pValue = modulo;
					temp[1].pValue = exponentePublico;
					temp[2].pValue = exponentePrivado;

					rv = C_GetAttributeValue(hSession[1], hPrivateKey, temp, 3);
					sprintf(ret, "Llamada a C_GetAttributeValue con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));					
					
					
					
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
						printf("Error de OpenSSL\n");
						ERR_error_string(err,message);
						printf("\n%s\n",message);
						ERR_free_strings();	
						exit(0);	
					}
					else
					{
						sprintf(ret, "Resultado de hacer Sign con C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, del mecanismo %s, con el mismo input, debio arrojar el mismo resultado que una implementacion del mecanismo en OpenSSL", (int)slot, meca);
						assert2(behavior, message(strncmp(pSignature, signature, signatureLen) == 0,ret));				
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
				sprintf(ret, "Llamada a C_SignInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
    				sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
				pSignature2 = (CK_BYTE_PTR)malloc(signatureLen*sizeof(CK_BYTE));
				
				rv = C_Sign(hSession[1], data, strlen(data), pSignature2, &signatureLen);
	    			sprintf(ret, "Llamada a C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
				sprintf(ret, "Resultado de hacer Sign 2 veces con C_Sign con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, del mecanismo %x, con el mismo input y la misma key, debio arrojar el mismo resultado", (int)slot, (int)(signMechanism[j].mechanism));
				assert2(behavior, message(strncmp(pSignature, pSignature2, signatureLen) == 0,ret));

				free(pSignature);
				free(pSignature2);
			}			


			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_CloseSession(hSession[0]);
			sprintf(ret, "Llamado a C_CloseSession de una sesion R/O creada con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
		}
	}
	free(buffer);
	
	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));

	rv = C_SignInit(hSession[1], &signMechanism[0], hPrivateKey);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_SignInit luego de un llamado a C_Finalize"));

	rv = C_Sign(hSession[1], data, strlen(data), NULL_PTR, &signatureLen);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_Sign luego de un llamado a C_Finalize"));

	printlnLevel(showMessage, "Fin: test Sign(C_Sign|Init)", level);
}

///
void esfuerzoSignMechanism(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo Sign(C_Sign|Init)", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testSignMechanism(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo Sign(C_Sign|Init)", level);
	}
}


///
void testDigestMechanism(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test Digest(C_Digest|Init)", level);
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
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_DigestInit sin un llamado previo a C_Initialize "));

	rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_Digest sin un llamado previo a C_Initialize"));
		
	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_DigestInit(CK_INVALID_HANDLE, &digestMechanism[2]);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_DigestInit con handle de session invalido"));

	rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_Digest con handle de session invalido"));

	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
			sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			//____
			
			rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
			sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , antes de una llamada a C_DigestInit", (int)slot);			
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));

			rv = C_DigestInit(hSession[1], NULL_PTR);
			sprintf(ret, "Llamada a C_DigestInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con segundo argumento NULL_PTR", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));
///
	if (rv == CKR_OK)
	{
		rv = C_CloseAllSessions(slot);
		sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK ,ret));				

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
		sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

	}
///
			rv = C_DigestInit(hSession[1], &digestMechanism[0]);
			sprintf(ret, "Llamada a C_DigestInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con segundo argumento un mecanismo invalido(%d)", (int)slot, (int)digestMechanism[0].mechanism);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_INVALID, ret));
			
///
	if (rv == CKR_OK)
	{
		rv = C_CloseAllSessions(slot);
		sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK ,ret));				

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
		sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

	}
///

			rv = C_DigestInit(hSession[1], &digestMechanism[1]);
			sprintf(ret, "Llamada a C_DigestInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con segundo argumento un mecanismo valido pero con parametros invalidos", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_MECHANISM_PARAM_INVALID, ret));

///
	if (rv == CKR_OK)
	{
		rv = C_CloseAllSessions(slot);
		sprintf(ret, "Llamado a C_CloseAllSessions con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK ,ret));				

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
		sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

		rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
		sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));

	}
///

			rv = C_DigestInit(hSession[1], &digestMechanism[2]);
			sprintf(ret, "Llamada a C_DigestInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));


			rv = C_DigestInit(hSession[1], &digestMechanism[2]);
			sprintf(ret, "Llamada a C_DigestInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , inmediatamente luego de otra llamada a C_DigestInit", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_ACTIVE, ret));

			
			rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, NULL_PTR);
			sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con cuarto argumento NULL_PTR", (int)slot);	
			assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD, ret));

			rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
			sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , luego de una llamada erronea a C_Digest", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));
			
			if (rv == CKR_OPERATION_NOT_INITIALIZED)
			{
				rv = C_DigestInit(hSession[1], &digestMechanism[2]);
				sprintf(ret, "Llamada a C_DigestInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , luego de finalizacion erronea de C_Digest", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
			}			

			rv = C_Digest(hSession[0], data, strlen(data), NULL_PTR, &digestLen);
			sprintf(ret, "Llamada a C_Digest con una sesion R/O abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , pues esa session no ha inicializado ninguna operacion de Digest", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));

			rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
    			sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			CK_BYTE_PTR pDigest = (CK_BYTE_PTR)malloc(digestLen*sizeof(CK_BYTE));

			digestLen = 0;
			rv = C_Digest(hSession[1], data, strlen(data), pDigest, &digestLen);
    			sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , luego de setear el digestLen en 0", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_BUFFER_TOO_SMALL, ret));

			
			rv = C_Digest(hSession[1], data, strlen(data), pDigest, &digestLen);
    			sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con un DigestaturreLen rellenado luego de un codigo CKR_BUFFER_TOO_SMALL", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
    			sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , luego de un llamado a C_Digest terminado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OPERATION_NOT_INITIALIZED, ret));
			free(pDigest);

			//TEST DE RESULTADOS
			int j;
			for(j = 2; j < n; ++j)
			{
				char meca [100];
				getMechanismName((digestMechanism[j].mechanism), meca);
				rv = C_DigestInit(hSession[1], &digestMechanism[j]);
				sprintf(ret, "Llamada a C_DigestInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
    				sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
				sprintf(ret, "Largo del digest dado por  C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, del mecanismo %s, debio ser %d", (int)slot, meca, (int)(lengths[j]));
				assert2(behavior, message(digestLen == lengths[j], ret));				


				pDigest = (CK_BYTE_PTR)malloc(digestLen*sizeof(CK_BYTE));
				
				rv = C_Digest(hSession[1], data, strlen(data), pDigest, &digestLen);
	    			sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				//Es funcion?
				CK_BYTE_PTR pDigest2;

				rv = C_DigestInit(hSession[1], &digestMechanism[j]);
				sprintf(ret, "Llamada a C_DigestInit con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
    				sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
				pDigest2 = (CK_BYTE_PTR)malloc(digestLen*sizeof(CK_BYTE));
				
				rv = C_Digest(hSession[1], data, strlen(data), pDigest2, &digestLen);
	    			sprintf(ret, "Llamada a C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				
				sprintf(ret, "Resultado de hacer Digest 2 veces con C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, del mecanismo %s, con el mismo input, debio arrojar el mismo resultado", (int)slot, meca);
				assert2(behavior, message(strncmp(pDigest, pDigest2, digestLen) == 0,ret));
				if ( j == 2) //MD5
				{
					unsigned char obuf[16];
					MD5(data, strlen(data), obuf);
					sprintf(ret, "Resultado de hacer Digest con C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, del mecanismo %s, con el mismo input, debio arrojar el mismo resultado que una implementacion del mecanismo en OpenSSL", (int)slot, meca);
					assert2(behavior, message(strncmp(pDigest, obuf, digestLen) == 0,ret));

				}
				if (j == 3) //SHA1
				{
					unsigned char obuf[20];
					SHA1(data, strlen(data), obuf);
					sprintf(ret, "Resultado de hacer Digest con C_Digest con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado, del mecanismo %s, con el mismo input, debio arrojar el mismo resultado que una implementacion del mecanismo en OpenSSL", (int)slot, meca);
					assert2(behavior, message(strncmp(pDigest, obuf, digestLen) == 0,ret));
					
				}
				free(pDigest);
				free(pDigest2);
			}
			
			

			rv = C_Logout(hSession[1]);
			sprintf(ret, "Llamada a C_Logout con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
			rv = C_CloseSession(hSession[0]);
			sprintf(ret, "Llamado a C_CloseSession de una sesion R/O creada con un slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flag ,CKF_TOKEN_INITIALIZED prendido y CKF_WRITE_PROTECTED apagado", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK ,ret));
		}
	}
	free(buffer);
	
	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));

	rv = C_DigestInit(hSession[1], &digestMechanism[0]);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_DigestInit luego de un llamado a C_Finalize"));

	rv = C_Digest(hSession[1], data, strlen(data), NULL_PTR, &digestLen);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_Digest luego de un llamado a C_Finalize"));

	printlnLevel(showMessage, "Fin: test Digest(C_Digest|Init)", level);
}

void esfuerzoDigestMechanism(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo Digest(C_Digest|Init)", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testDigestMechanism(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo Digest(C_Digest|Init)", level);
	}
}


//Test de funciones que trabajan con aleatoridad
//Son C_SeedRandom y C_GenerateRandom
void testRNGFunctions(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test de funciones de aleatoridad", level);
	testSeedRandom(level + 1, showMessage);
	esfuerzoSeedRandom(level + 1, repeticiones, showMessage);

	testGenerateRandom(level + 1, showMessage);
	esfuerzoGenerateRandom(level + 1, repeticiones, showMessage);

	printlnLevel(showMessage, "Fin: test de funciones de aleatoridad", level);

}

///
void testSeedRandom(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_SeedRandom", level);
	
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	CK_BYTE seed[] = {"Some random data"};
	
	rv = C_SeedRandom(hSession[0], seed, strlen(seed));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_SeedRandom sin un llamado previo a C_InitializeD"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_SeedRandom(CK_INVALID_HANDLE, seed, strlen(seed));
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_SeedRandom con un handle de sesion invalido"));	

	
	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			if((infoToken.flags & CKF_RNG))
			{

				rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
				sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				//____
				
				rv = C_SeedRandom(hSession[1], NULL_PTR, 0);
				sprintf(ret, "Llamada a C_SeedRandom con una sesion R/W abierta y logueada en normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG encendido y con segundo argumento NULL_PTR", (int)slot);
				assert2(behavior, verifyCode2(rv,  CKR_ARGUMENTS_BAD, CKR_RANDOM_SEED_NOT_SUPPORTED, ret));

				
				rv = C_SeedRandom(hSession[1], seed, strlen(seed));
				sprintf(ret, "Llamada a C_SeedRandom con una sesion R/W abierta y logueada en normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG encendido", (int)slot);
				assert2(behavior, verifyCode2(rv,  CKR_OK, CKR_RANDOM_SEED_NOT_SUPPORTED, ret));
			
				rv = C_SeedRandom(hSession[0], seed, strlen(seed));
				sprintf(ret, "Llamada a C_SeedRandom con una sesion R/O abierta y logueada en normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG encendido", (int)slot);
				assert2(behavior, verifyCode2(rv,  CKR_OK, CKR_RANDOM_SEED_NOT_SUPPORTED, ret));
			}
			else
			{
				rv = C_SeedRandom(hSession[1], seed, strlen(seed));
				sprintf(ret, "Llamada a C_SeedRandom con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_RANDOM_NO_RNG, ret));
			
				rv = C_SeedRandom(hSession[0], seed, strlen(seed));
				sprintf(ret, "Llamada a C_SeedRandom con una sesion R/O abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_RANDOM_NO_RNG, ret));
			}
		}
	}
	free(buffer);

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	rv = C_SeedRandom(hSession[1], seed, strlen(seed));
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_SeedRandom luego de un llamado a C_Finalize"));

	printlnLevel(showMessage, "Fin: test C_SeedRandom", level);
}


void esfuerzoSeedRandom(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_SeedRandom", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testSeedRandom(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_SeedRandom", level);
	}

}

///
void testGenerateRandom(int level, int showMessage)
{
	printlnLevel(showMessage, "Inicio: test C_SeedRandom", level);
	
	CK_RV rv;
	CK_SESSION_HANDLE hSession[2];
	CK_BYTE randomData[40];
	
	rv = C_GenerateRandom(hSession[0], randomData, 40);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_GenerateRandom sin un llamado previo a C_Initialize"));
	
 	rv = C_Initialize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Initialize con NULL_PTR"));

	rv = C_GenerateRandom(CK_INVALID_HANDLE, randomData, 40);
	assert2(behavior, verifyCode(rv, CKR_SESSION_HANDLE_INVALID,"Llamado a C_GenerateRandom con un handle de sesion invalido"));	
	
	CK_ULONG size;
	unsigned int i;
	rv = C_GetSlotList(CK_TRUE, NULL_PTR, &size);	
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	CK_SLOT_ID_PTR buffer = (CK_SLOT_ID_PTR)malloc(size * sizeof(CK_SLOT_ID));
	rv = C_GetSlotList(CK_TRUE, buffer, &size);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamado a C_GetSlotList"));
	
	for (i = 0; i < size; ++i)
	{
		CK_SLOT_ID slot = buffer[i];
		CK_TOKEN_INFO infoToken;
		rv = C_GetTokenInfo(slot, &infoToken);
		sprintf(ret, "Llamado a C_GetTokenInfo con un slotID(%d) retornado por C_GetSlotList(CK_TRUE)", (int)slot);
		assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
		if ((infoToken.flags & CKF_TOKEN_INITIALIZED) && !(infoToken.flags & CKF_WRITE_PROTECTED))
		{
			rv = C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/W", (int)slot);
			assert2(behavior, verifyCode(rv,  CKR_OK, ret));

			rv = C_OpenSession(slot, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
			sprintf(ret, "Llamada a C_OpenSession con slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado al intentar abrir una sesion R/O", (int)slot);
			assert2(behavior, verifyCode(rv, CKR_OK, ret));

			if((infoToken.flags & CKF_RNG))
			{

				rv = C_Login(hSession[1], CKU_USER, userPIN, strlen(userPIN));
				sprintf(ret, "Llamada a C_Login con una sesion R/W abierta  en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado , con tipo de usuario CKU_USER y con una sesion R/O y una R/W abiertas", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
				//____
				
				rv = C_GenerateRandom(hSession[1], NULL_PTR, 0);
				sprintf(ret, "Llamada a C_GenerateRandom con una sesion R/W abierta y logueada en normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG encendido y con segundo argumento NULL_PTR", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_ARGUMENTS_BAD , ret));

				
				rv = C_GenerateRandom(hSession[1], randomData, 40);
				sprintf(ret, "Llamada a C_GenerateRandom con una sesion R/W abierta y logueada en normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG encendido", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));
			
				rv = C_GenerateRandom(hSession[0], randomData, 40);
				sprintf(ret, "Llamada a C_GenerateRandom con una sesion R/O abierta y logueada en normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG encendido", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_OK, ret));

				//LITTLE TEST OF RANDOMESS
				
				int hayRepetido = 0;
				int j;
				int repeticiones = 10;
				for(j = 0; j < repeticiones-1; ++j)
				{
					CK_BYTE otherRandomData[40];
					rv = C_GenerateRandom(hSession[0], otherRandomData, 40);
					sprintf(ret, "Llamada a C_GenerateRandom con una sesion R/O abierta y logueada en normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG encendido", (int)slot);
					assert2(behavior, verifyCode(rv, CKR_OK, ret));

					hayRepetido = hayRepetido ||  (strcmp((char *)randomData, (char *)otherRandomData) == 0);
				}

				sprintf(ret, "%d llamadas a C_GenerateRandom con una sesion R/O abierta y logueada en normal user en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG encendido retorno siempre el mismo valor",repeticiones, (int)slot);
				assert2(behavior, message(!hayRepetido, ret));
				
				//LITTLE TEST OF RANDOMESS
			}
			else
			{
				rv = C_GenerateRandom(hSession[1], randomData, 40);
				sprintf(ret, "Llamada a C_GenerateRandom con una sesion R/W abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_RANDOM_NO_RNG, ret));
			
				rv = C_GenerateRandom(hSession[0], randomData, 40);
				sprintf(ret, "Llamada a C_GenerateRandom con una sesion R/O abierta en slotID(%d) retornado por C_GetSlotList(CK_TRUE) y con flags CKF_TOKEN_INITIALIZED encendido y CKF_WRITE_PROTECTED apagado ,  y con CKF_RNG apagado", (int)slot);
				assert2(behavior, verifyCode(rv, CKR_RANDOM_NO_RNG, ret));
			}
		}
	}
	free(buffer);

	rv = C_Finalize(NULL_PTR);
	assert2(behavior, verifyCode(rv, CKR_OK, "Llamada a C_Finalize con NULL_PTR"));
	
	
	rv = C_GenerateRandom(hSession[1], randomData, 40);
	assert2(behavior, verifyCode(rv, CKR_CRYPTOKI_NOT_INITIALIZED,"Llamado a C_GenerateRandom luego de un llamado a C_Finalize"));

	printlnLevel(showMessage, "Fin: test C_SeedRandom", level);

}

///
void esfuerzoGenerateRandom(int level, int repeticiones, int showMessage)
{
	if(repeticiones)
	{	
		printlnLevel(showMessage, "Inicio: esfuerzo C_GenerateRandom", level);
		CK_RV rv;
		int i;
		for (i = 0; i < repeticiones; ++i)
		{
			testGenerateRandom(level + 1, 0);
		}

		printlnLevel(showMessage, "Fin: esfuerzo C_GenerateRandom", level);
	}
}

