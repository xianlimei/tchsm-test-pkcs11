#include "thirdTest.h"
//#include "cryptoki.h"


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

#include "pkcs11.h"//PREGUNTAR
#include <dlfcn.h>

#define C_Initialize (lib -> C_Initialize)
#define C_Finalize (lib -> C_Finalize)
#define C_GetInfo (lib -> C_GetInfo)
#define C_GetFunctionList (lib -> C_GetFunctionList)
#define C_InitToken (lib -> C_InitToken)
#define C_InitPIN (lib -> C_InitPIN)
#define C_SetPIN (lib -> C_setPIN)
#define C_GetSlotList (lib -> C_GetSlotList)
#define C_GetSlotInfo (lib -> C_GetSlotInfo)
#define C_GetTokenInfo (lib -> C_GetTokenInfo)
#define C_OpenSession (lib -> C_OpenSession)
#define C_CloseSession (lib -> C_CloseSession)
#define C_CloseAllSessions (lib -> C_CloseAllSessions)
#define C_GetSessionInfo (lib -> C_GetSessionInfo)
#define C_Login (lib -> C_Login)
#define C_Logout (lib -> C_Logout)
#define C_CreateObject (lib -> C_CreateObject)
#define C_DestroyObject (lib -> C_DestroyObject)
#define C_FindObjects (lib -> C_FindObjects)
#define C_FindObjectsFinal (lib -> C_FindObjectsFinal)
#define C_GetAttributeValue (lib -> C_GetAttributeValue)
#define C_DigestInit (lib -> C_DigestInit)
#define C_Digest (lib -> C_Digest)
#define C_SignInit (lib -> C_SignInit)
#define C_Sign (lib -> C_Sign)
#define C_GenerateKeyPair (lib -> C_GenerateKeyPair)
#define C_SeedRandom (lib -> C_SeedRandom)
#define C_GenerateRandom (lib -> C_GenerateRandom)

//NOT IN pmHSM
#define C_GetMechanismList (lib -> C_GetMechanismList)
#define C_GetMechanismInfo (lib -> C_GetMechanismInfo)
#define C_SignFinal (lib -> C_SignFinal)
#define C_SignUpdate (lib -> C_SignUpdate)
#define C_DigestFinal (lib -> C_DigestFinal)
#define C_DigestUpdate (lib -> C_DigestUpdate)
#define C_FindObjectsInit (lib -> C_FindObjectsInit)
#define C_SetAttributeValue (lib -> C_SetAttributeValue)
//PUNTERO A ESTRUCTURAS QUE TIENEN LAS FUNCIONES
CK_FUNCTION_LIST_PTR lib;
//PUNTERO A ESTRUCTURAS QUE TIENEN LAS FUNCIONES



CK_UTF8CHAR userPIN[] = {"123456"};
CK_UTF8CHAR soPIN[] = {"12345678"};

CK_ULONG slotWithToken = 1;
CK_ULONG slotWithNoToken = 0;
CK_ULONG slotWithNotInitToken = 2;
CK_ULONG slotInvalid = 9999;


int main(int argc, char **argv)
{
	#ifdef WIN32
  	_putenv("SOFTHSM_CONF=./softhsm.conf");
	#else
	setenv("SOFTHSM_CONF", "./softhsm.conf", 1);
	#endif
	
	if (argc != 2)
	{
		printf("Se debe especificar la ubicacion del archivo .so\n");
		printf("./thirdTest /usr/local/lib/softhsm/libsofthsm.so\n");
		exit(1);
	}

	void * openLib = dlopen(argv[1], RTLD_LAZY);
	
	void  (* getFunctionList)(CK_FUNCTION_LIST_PTR_PTR) =  dlsym(openLib, "C_GetFunctionList");
	if (dlerror() != NULL) 
	{
		printf("FRACASO\n");
		exit(1);
	}
	
	
	(* getFunctionList)(&lib);
	
	inittoken();

	runInitCheck(5);
	runInfoCheck(5);
	runSessionCheck(5);
	runUserCheck(5);
	runRandomCheck(5);
	runUserCheck(5);
	runObjectCheck(5);
	runDigestCheck(5);
	runSignCheck(5);

	dlclose(openLib);
	return 1;
}

void inittoken() { 
  CK_RV rv;
  CK_SESSION_HANDLE hSession;
  CK_UTF8CHAR paddedLabel[32];
  char *textLabel;

  rv = C_Initialize(NULL_PTR);//Indica a SoftHSM que esta sera una aplicacion cryptoki
  
  if(rv != CKR_OK) {
    printf("\nCan not initialize SoftHSM.\n");
    printf("There are probably some problem with the token config file located at: %s\n", "./softhsm.conf");
    exit(1);
}

  textLabel = "A token";
  memset(paddedLabel, ' ', sizeof(paddedLabel));//Copia en padded label 32 espacios en blanco
  memcpy(paddedLabel, textLabel, strlen(textLabel));//Copia A token en paddedLabel,esto genera que paddedLabel tenga esto y lo demas en espacio en blanco
  

  ////ARIEL CODE
  //rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);
  //if (rv == CKR_OK) printf("This is printed, why?\n");
  ////ARIEL CODE

 
 rv = C_InitToken(slotWithToken, soPIN, sizeof(soPIN) - 1, paddedLabel);
 //Inicializa el token, si no le hace las operaciones de abajo igual funcionan, excepto si es la primera vez
  switch(rv) {
    case CKR_OK:
      break;
    case CKR_SLOT_ID_INVALID:
      printf("Error: The given slot does not exist. Make sure that slot nr %lu is in the softhsm.conf\n", slotWithToken);
      exit(1);
      break;
    case CKR_PIN_INCORRECT:
      printf("Error: The given SO PIN does not match the one in the token.\n");
      exit(1);
      break;
    default:
      printf("Error: The library could not initialize the token.\n");
      exit(1);
      break;
  }



	
  rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession);//Abre una sesion en el slot 1, con las opciones de serial (es pmHSM paralelo?) y de RW. Y Guarde el handle session en hSession, sucede lo mismo en checks

  //ARIEL CODE
  //CK_TOKEN_INFO tokenInfo;
  //rv = C_GetTokenInfo(slotWithToken, &tokenInfo);
  //if(tokenInfo.flags &&  CKF_TOKEN_INITIALIZED) printf("token will be reinitialized and the client must supply the existing SO password in pPin\n");
  //ARIEL CODE
  if(rv != CKR_OK) {
    printf("Error: Could not open a session with the library.\n");
    exit(1);
  }

  rv = C_Login(hSession, CKU_SO, soPIN, sizeof(soPIN) - 1);
  //Se loguea en la sesion hSession con el tipo de usuario Security Officer dando el respectivo pin
  if(rv != CKR_OK) {
    printf("Error: Could not log in on the token.\n");
    exit(1);
  }

  rv = C_InitPIN(hSession, userPIN, sizeof(userPIN) - 1);
  if(rv != CKR_OK) {
    printf("Error: Could not initialize the user PIN.\n");
    exit(1);
  }
  
  rv = C_Finalize(NULL_PTR);
  if(rv != CKR_OK) {
    printf("Error: Could not finalize SoftHSM.\n");
    exit(1);
  }
}


void runInitCheck(unsigned int counter) { //INICIALIZA Y FINALIZA MUCHAS VECES TESTEANDO CASOS QUE NO FUNCIONAN TAMBIEN
  unsigned int i;

  printf("Checking C_Initialize and C_Finalize: ");

  for(i = 0; i < counter; i++) {
    CK_C_INITIALIZE_ARGS InitArgs; //Estructura que contiene los datos de inicializacion

    CK_RV rv;

    InitArgs.CreateMutex = NULL_PTR;//No hay funcion para crear mutex
    InitArgs.DestroyMutex = NULL_PTR;//No hay funcion para destruir mutex
    InitArgs.LockMutex = NULL_PTR;//No hay funcion para bloquear mutex
    InitArgs.UnlockMutex = (CK_UNLOCKMUTEX)1;//Puntero para desbloquear mutex es 1
    InitArgs.flags = CKF_OS_LOCKING_OK;//Flag que significa que se pueden usar operaciones de sistema con threading
    InitArgs.pReserved = (CK_VOID_PTR)1;//Para futura API, debe ser NULL

    rv = C_Finalize((CK_VOID_PTR)1);
    assert(rv == CKR_ARGUMENTS_BAD);//Puesto que en finalize se debe dar argumento null

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);//Puesto que no hay una inicializacion previa(es valido al principio y en las siguientes pasadas del ciclo tambien pues al final del ciclo hay una finalizacion)

    rv = C_Initialize((CK_VOID_PTR)&InitArgs);
    assert(rv == CKR_ARGUMENTS_BAD);//Puesto que todos los de InitArgs deben ser no null, excepto pReserved

    InitArgs.pReserved = NULL_PTR;
    rv = C_Initialize((CK_VOID_PTR)&InitArgs);
    assert(rv == CKR_ARGUMENTS_BAD);//Puesto que todos los de InitArgs deben ser no null, excepto pReserved

    InitArgs.UnlockMutex = NULL_PTR;
    rv = C_Initialize((CK_VOID_PTR)&InitArgs);
    assert(rv == CKR_OK);//Puesto que todos los de InitArgs deben ser no null, excepto pReserved

    rv = C_Initialize((CK_VOID_PTR)&InitArgs);
    assert(rv == CKR_CRYPTOKI_ALREADY_INITIALIZED);//Puesto que se inicializo antes

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);//ACA LO HACE BIEN
  }

  printf("OK\n");
}


void runInfoCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_GetInfo, C_GetFunctionList, C_GetSlotList, C_GetSlotInfo, C_GetTokenInfo, C_GetMechanismList, C_GetMechanismInfo: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_INFO ckInfo;
    CK_FUNCTION_LIST_PTR ckFuncList;
    CK_ULONG ulSlotCount = 0;
    CK_SLOT_ID_PTR pSlotList;
    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
    CK_ULONG ulCount;
    CK_MECHANISM_TYPE_PTR pMechanismList;
    CK_MECHANISM_INFO info;

    /* No init */

    rv = C_GetInfo(NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetSlotList(CK_FALSE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetSlotInfo(slotInvalid, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetTokenInfo(slotInvalid, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetMechanismList(slotInvalid, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetMechanismInfo(slotInvalid, CKM_VENDOR_DEFINED, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);//Se caen pues necesitan que el cryptoki este inicualizado

    /* C_GetFunctionList */
    
    rv = C_GetFunctionList(NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues se le debe dar como argumento un puntero a un CK_FUNCTION_LIST structure, donde se almacenara la informacion

    rv = C_GetFunctionList(&ckFuncList);
    assert(rv == CKR_OK);//Pasa pues getfunctionlist no necesita que la aplicacion sea una aplicacion cryptoki

    /* C_GetInfo */

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_GetInfo(NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues se le debe pasar como argumento una estructura CK_INFO en donde se almacenara la informacion

    rv = C_GetInfo(&ckInfo);
    assert(rv == CKR_OK);

    /* C_GetSlotList */

    rv = C_GetSlotList(CK_FALSE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita que el tercer parametro(ref a num de slots) no sea null
    rv = C_GetSlotList(CK_FALSE, NULL_PTR, &ulSlotCount);
    assert(rv == CKR_OK);

    pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));//Reserva memoria para la lista de slots
    ulSlotCount = 0;
    rv = C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    assert(rv == CKR_BUFFER_TOO_SMALL);
    rv = C_GetSlotList(CK_FALSE, pSlotList, &ulSlotCount);
    assert(rv == CKR_OK);
    free(pSlotList);

    rv = C_GetSlotList(CK_TRUE, NULL_PTR, &ulSlotCount);
    assert(rv == CKR_OK);
    pSlotList = (CK_SLOT_ID_PTR)malloc(ulSlotCount * sizeof(CK_SLOT_ID));
    ulSlotCount = 0;
    rv = C_GetSlotList(CK_TRUE, pSlotList, &ulSlotCount);
    assert(rv == CKR_BUFFER_TOO_SMALL);
    rv = C_GetSlotList(CK_TRUE, pSlotList, &ulSlotCount);
    assert(rv == CKR_OK);
    free(pSlotList);//Mismo procedimiento anterior

    /* C_GetSlotInfo */

    rv = C_GetSlotInfo(slotInvalid, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita una referencia a un CK_SLOT_INFO donde dejara la info
    rv = C_GetSlotInfo(slotInvalid, &slotInfo);
    assert(rv == CKR_SLOT_ID_INVALID);//Falla pues el slot especificado no existe
    rv = C_GetSlotInfo(slotWithToken, &slotInfo);
    assert(rv == CKR_OK);

    /* C_GetTokenInfo */

    rv = C_GetTokenInfo(slotInvalid, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita una referencia a un CK_TOKEN_INFO donde dejara la info
    rv = C_GetTokenInfo(slotInvalid, &tokenInfo);
    assert(rv == CKR_SLOT_ID_INVALID);//Falla pues el slot especificado no existe
    rv = C_GetTokenInfo(slotWithNoToken, &tokenInfo);
    assert(rv == CKR_TOKEN_NOT_PRESENT);//Falla pues el slot no tiene un token
    rv = C_GetTokenInfo(slotWithToken, &tokenInfo);
    assert(rv == CKR_OK);

    /* C_GetMechanismList */

    rv = C_GetMechanismList(slotInvalid, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita que el tercer parametro sea una referencia a CK_ULONG
    rv = C_GetMechanismList(slotInvalid, NULL_PTR, &ulCount);
    assert(rv == CKR_SLOT_ID_INVALID);//Falla pues el slot no es valido
    rv = C_GetMechanismList(slotWithToken, NULL_PTR, &ulCount);
    assert(rv == CKR_OK);
    pMechanismList = (CK_MECHANISM_TYPE_PTR)malloc(ulCount * sizeof(CK_MECHANISM_TYPE));//Guarda memoria para obtener los mecanismos
    ulCount = 0;
    rv = C_GetMechanismList(slotWithToken, pMechanismList, &ulCount);
    assert(rv == CKR_BUFFER_TOO_SMALL);//Se debe llamar a getmechanismlist 2 veces, esto sucede pues la funcion lo aloca memoria por si misma
    rv = C_GetMechanismList(slotWithToken, pMechanismList, &ulCount);
    assert(rv == CKR_OK);
    free(pMechanismList);

    /* C_GetMechanismInfo */
    
    rv = C_GetMechanismInfo(slotInvalid, CKM_VENDOR_DEFINED, NULL_PTR);
    assert(rv == CKR_SLOT_ID_INVALID);//Falla pues el slot no es valido
    rv = C_GetMechanismInfo(slotWithToken, CKM_VENDOR_DEFINED, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues el tercer argumento debe se un puntero a un CK_MECHANISM_INFO
    rv = C_GetMechanismInfo(slotWithToken, CKM_VENDOR_DEFINED, &info);
    assert(rv == CKR_MECHANISM_INVALID);//Falla pues el token no puede ser usado en el token
    rv = C_GetMechanismInfo(slotWithToken, CKM_RSA_PKCS_KEY_PAIR_GEN, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_MD5, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_RIPEMD160, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA_1, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA256, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA384, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA512, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_MD5_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_RIPEMD160_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA1_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA256_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA384_RSA_PKCS, &info);
    assert(rv == CKR_OK);
    rv = C_GetMechanismInfo(slotWithToken, CKM_SHA512_RSA_PKCS, &info);
    assert(rv == CKR_OK);//PASAN :)

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);
  }

  printf("OK\n");
}

void runSessionCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_OpenSession, C_CloseSession, C_CloseAllSessions, and C_GetSessionInfo: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];//Crea arreglo para almacenar 10 session handles
    CK_SESSION_INFO info;

    /* No init */

    rv = C_OpenSession(slotInvalid, 0, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);//Falla pues aun no es una aplicacion cryptoki
    rv = C_CloseSession(CK_INVALID_HANDLE); //Trata de cerrar sesion con un 0 como handle
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_CloseAllSessions(slotInvalid);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GetSessionInfo(CK_INVALID_HANDLE, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);//Transforma en una aplicacion cryptoki

    /* C_OpenSession */

    rv = C_OpenSession(slotInvalid, 0, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SLOT_ID_INVALID);//Falla pues el slot es invalido
    rv = C_OpenSession(slotWithNoToken, 0, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_TOKEN_NOT_PRESENT);//Falla pues el slot no tiene un token
    rv = C_OpenSession(slotWithNotInitToken, 0, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_TOKEN_NOT_RECOGNIZED);//Falla pues se le da un slot que tiene un token pero no esta inicializado
    rv = C_OpenSession(slotWithToken, 0, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_PARALLEL_NOT_SUPPORTED);//Falla pues inteneta abrir una sesion sin el valor CKF_SERIAL_SESSION
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita una referencia a un CK_SESSION_HANDLE, donde dejara el handle de la session que se abrira
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);

    /* C_CloseSession */

    rv = C_CloseSession(CK_INVALID_HANDLE);
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues se cierra la session de un handle(0) invalido
    rv = C_CloseSession(hSession[0]);
    assert(rv == CKR_OK);

    /* C_CloseAllSessions */

    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[2]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[3]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[4]);
    assert(rv == CKR_OK);
    rv = C_CloseSession(hSession[3]);
    assert(rv == CKR_OK);
    rv = C_CloseAllSessions(slotInvalid);
    assert(rv == CKR_SLOT_ID_INVALID);//Falla pues se cierra la session de un handle(0) invalido
    rv = C_CloseAllSessions(slotWithNoToken);
    assert(rv == CKR_OK);
    rv = C_CloseSession(hSession[2]);
    assert(rv == CKR_OK);
    rv = C_CloseAllSessions(slotWithToken);//Y test de interoperabilidad?
    assert(rv == CKR_OK);
    
    /* C_GetSessionInfo */

    rv = C_GetSessionInfo(CK_INVALID_HANDLE, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues se cierra la session de un handle(0) invalido
    //Obtener info de una session no abierta(no de una invalida)
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);
    rv = C_GetSessionInfo(hSession[0], NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita una referencia a un CK_SESSION_INFO en donde se guardara la info
    rv = C_GetSessionInfo(hSession[0], &info);
    assert(rv == CKR_OK);
    rv = C_GetSessionInfo(hSession[1], &info);
    assert(rv == CKR_OK);//Y ver que tiene ese CK_SESSION_INFO

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

  }

  printf("OK\n");
}


void runUserCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_Login and C_Logout: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];

    /* No init */

    rv = C_Login(CK_INVALID_HANDLE, 9999, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_Logout(CK_INVALID_HANDLE);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);//Falla pues no es una aplicacion cryptoki en este punto

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);//Se abren dos sesiones, la primera(hSession[0]) read-only y la segunda(hSession[1]) read-write, los permisos son referidos al manejo de los token y no de las sesiones

    /* C_Login */

    rv = C_Login(CK_INVALID_HANDLE, 9999, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID); //Falla pues trata de logearse en con un handle de sesion invalido(0)
    rv = C_Login(hSession[0], 9999, NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);//
    rv = C_Login(hSession[0], 9999, userPIN, MIN_PIN_LEN - 1);
    assert(rv == CKR_PIN_INCORRECT);//Falla pues el largo es menor que el minimo especificado para el HSM
    rv = C_Login(hSession[0], 9999, userPIN, MAX_PIN_LEN + 1);
    assert(rv == CKR_PIN_INCORRECT);//Falla pues el largo es menor que el minimo especificado para el HSM
    rv = C_Login(hSession[0], 9999, userPIN, sizeof(userPIN) - 2);
    assert(rv == CKR_USER_TYPE_INVALID);//Falla pues 9999 no es un tipo de usuario valido, lo son CKU_SO, CKU_USER y CKU_CONTEX_SPECIFIC
    rv = C_Login(hSession[0], CKU_CONTEXT_SPECIFIC, userPIN, sizeof(userPIN) - 2);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);//Falla pues se quiere loguear como usuario especifico del contexto, pero no hay una operacion que permita decidir que tipo de usuario sera(no hay un contexto)
    rv = C_Login(hSession[0], CKU_USER, userPIN, sizeof(userPIN) - 2);
    assert(rv == CKR_PIN_INCORRECT);//Falla pues el largo del pin es diferente al largo de userPin, (-1 pues no incluye null character al final)
    rv = C_Login(hSession[0], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[0], CKU_CONTEXT_SPECIFIC, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);//Ahora no falla pues ya se habia logueado un usuario tipo USER(recordar que los tipos de usuarios se comparten entre las sesiones)
    rv = C_Login(hSession[1], CKU_SO, soPIN, sizeof(soPIN) - 2);
    assert(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN);//Falla pues se trata de loguear como SO y hay un USER logueado (no pueden haber sesiones __abiertas__ de distinto tipo)
    rv = C_Logout(hSession[0]);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_SO, soPIN, sizeof(soPIN) - 2);
    assert(rv == CKR_SESSION_READ_ONLY_EXISTS);//Falla pues si se logueara como un SO, obligaria a hSession[0] a ser SO, sin embargo hSession[0] es read-only y el estado SO R/O no existe
    rv = C_CloseSession(hSession[0]); //Se cierra la sesion R/O
    assert(rv == CKR_OK);

    //ARIEL CODE
    rv = C_Login(hSession[0], CKU_USER, userPIN, sizeof(userPIN)-1);
    assert(rv == CKR_SESSION_HANDLE_INVALID); //Diferencia entre abrir una sesion y loguearse(Aunque creo que deberia ser CKR_SESSION_CLOSED
    //ARIEL CODE

    rv = C_Login(hSession[1], CKU_SO, soPIN, sizeof(soPIN) - 2);
    assert(rv == CKR_PIN_INCORRECT);//Falla pues el largo del pin es diferente al largo de userPin, (-1 pues no incluye null character al final)
    rv = C_Login(hSession[1], CKU_SO, soPIN, sizeof(soPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_CONTEXT_SPECIFIC, soPIN, sizeof(soPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 2);
    assert(rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN);//Falla pues se estaba logueado como SO, lo correcto es desloguearse y luego loguearse como USER
    ////ASI
    //rv = C_Logout(hSession[1]);
    //rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    //assert(rv == CKR_OK);

    
    /* C_Logout */

    rv = C_Logout(CK_INVALID_HANDLE);    
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues se quiere desloguearse con un handle de sesion invalido
    rv = C_Logout(hSession[1]);
    assert(rv == CKR_OK);


    //PEQUENA PRUEBA
    //VER QUE SUCEDE CUANDO CONECTO 2 USUARIOS SO, DESCONECTO EL PRIMERO E INTENTO ABRIR SESION USER CON EL SEGUNDO, ESO DEBIESE FUNCIONAR, PUES DESCONECTAR UNA SESSION DESCONECTA LAS DEMAS
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[2]);
    rv = C_Login(hSession[0], CKU_USER, userPIN, sizeof(userPIN)-1);
    assert(rv == CKR_OK); //Diferencia entre abrir una sesion y loguearse
    rv = C_Login(hSession[1], CKU_CONTEXT_SPECIFIC, userPIN, sizeof(userPIN)-1);
    rv = C_Logout(hSession[0]);
    rv = C_Login(hSession[1], CKU_SO, userPIN, sizeof(userPIN)-1);
    assert(rv == CKR_SESSION_READ_ONLY_EXISTS); //ESTO SUCEDE AUNQUE LA SESION h[0] (R/O) no este abierta, y deja de manifiesto que el abrir una sesion cambia todos los tipos de sesion a la sesion abierta(Si una sesion se loguea todas lo hacen, si se loguotea todas lo hacen y asi.//ESTE TEST NO HACE LO QUE DICE EN EL ENCABEZADO
    //PEQUENA PRUEBA

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

  }
  
  printf("OK\n");
}



void runRandomCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_SeedRandom and C_GenerateRandom: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    CK_BYTE seed[] = {"Some random data"};
    CK_BYTE randomData[40];

    /* No init */

    rv = C_SeedRandom(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);
    rv = C_GenerateRandom(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);//Fallan pues en este punto la aplicacion no es una aplicacion cryptoki

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);

    /* C_SeedRandom */

    rv = C_SeedRandom(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues se le da un handle de session invalido
    rv = C_SeedRandom(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla, pues la funcion necesita de un seed
    rv = C_SeedRandom(hSession[0], seed, sizeof(seed));
    assert(rv == CKR_OK);

    /* C_GenerateRandom */

    rv = C_GenerateRandom(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues se le da un handle de session invalido
    rv = C_GenerateRandom(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues requiere en su segundo argumentoun puntero a CK_BYTE en node almacenara el resultado
    rv = C_GenerateRandom(hSession[0], randomData, 40);
    assert(rv == CKR_OK);
    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

  }
  printf("OK\n");
}


void runGenerateCheck(unsigned int counter) {
  unsigned int i;
  static CK_ULONG modulusBits = 768;
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
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_ENCRYPT, &true, sizeof(true)},
    {CKA_VERIFY, &true, sizeof(true)},
    {CKA_WRAP, &true, sizeof(true)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_PRIVATE, &true, sizeof(true)},
    {CKA_ID, id, sizeof(id)},
    {CKA_SENSITIVE, &true, sizeof(true)},
    {CKA_DECRYPT, &true, sizeof(true)},
    {CKA_SIGN, &true, sizeof(true)},
    {CKA_UNWRAP, &true, sizeof(true)},
    {CKA_TOKEN, &true, sizeof(true)}
  };
  CK_ATTRIBUTE pubTemplate[] = {
    {CKA_CLASS, &pubClass, sizeof(pubClass)},
    {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
    {CKA_LABEL, label, sizeof(label)},
    {CKA_ID, id, sizeof(id)},
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_VERIFY, &true, sizeof(true)},
    {CKA_ENCRYPT, &false, sizeof(false)},
    {CKA_WRAP, &false, sizeof(false)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_MODULUS, modulus, sizeof(modulus)},
    {CKA_CERTIFICATE_CATEGORY, NULL_PTR, 0}
  };

  printf("Checking C_GenerateKeyPair, C_DestroyObject, and C_CreateObject: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    CK_OBJECT_HANDLE hPublicKey, hPrivateKey, hCreateKey;
    CK_MECHANISM mechanism = {CKM_VENDOR_DEFINED, NULL_PTR, 0};

    /* No init */

    rv = C_GenerateKeyPair(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);//Falla pues la aplicacion no es una aplicacion cryptoki
    rv = C_DestroyObject(CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);//Falla pues la aplicacion no es una aplicacion cryptoki
    rv = C_CreateObject(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);//Falla pues la aplicacion no es una aplicacion cryptoki

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);

    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);//Abre la sesion hSession[0] como r/o y la sesion hSession[1] como r/w

    /* C_GenerateKeyPair */

    rv = C_GenerateKeyPair(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues se le da un handle de sesion invalido
    rv = C_GenerateKeyPair(hSession[0], NULL_PTR, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);// Falla pues necesita un puntero a un CK_MECHANISM QUE SERA EL ALGORITMO QUE HARA LA OPERACION
    rv = C_GenerateKeyPair(hSession[0], &mechanism, NULL_PTR, 0, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);// Falla pues necesita un puntero a un CK_ATRIBUTE donde estan los atributos de la clave publica
    rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 6, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);// Falla pues necesita un puntero a un CK_ATRIBUTE donde estan los atributos de la clave privada
    rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a un CK_OBJECT_HANDLE que es el handle del objeto que tendra contendra llave publica
    rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a un CK_OBJECT_HANDLE que es el handle del objeto que tendra contendra llave publica
    rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_USER_NOT_LOGGED_IN);// Falla pues para realizar esta operacion necesita que el usuario de la sesion este logueado
    rv = C_Login(hSession[0], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_GenerateKeyPair(hSession[0], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_USER_NOT_LOGGED_IN);//Falla pues hSession[0] es r/o, aunque a mi parecer debiese entregar un CKR_SESSION_READ_ONLY
    rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_MECHANISM_INVALID);//Falla pues CKM_VENDOR_DEFINED no es un tipo de mecanismo validp
    mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 5, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_TEMPLATE_INCOMPLETE);//Falla pues el numero de atributos en el template de la llave publica es 6 y se indica que es 5
    rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_OK);

    /* C_DestroyObject */

    rv = C_DestroyObject(CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    assert(rv == CKR_SESSION_HANDLE_INVALID); //Falla pues se le da un handle de session invalido
    rv = C_DestroyObject(hSession[0], CK_INVALID_HANDLE);
    assert(rv == CKR_OBJECT_HANDLE_INVALID); //Falla pues se le da un handle de objeto invalido
    rv = C_DestroyObject(hSession[0], hPrivateKey);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);//Falla pues hSession[0] es una r/o que solo puede destruir objetos de sesion
    rv = C_DestroyObject(hSession[1], hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_DestroyObject(hSession[1], hPublicKey);
    assert(rv == CKR_OK);

    /* C_CreateObject */

    rv = C_Logout(hSession[0]);
    assert(rv == CKR_OK);
    rv = C_CreateObject(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID); //Falla pues el handle de sesion es invalido
    rv = C_CreateObject(hSession[0], NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita de un template a partir del cual creara el objeto
    rv = C_CreateObject(hSession[0], pubTemplate, 0, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues el numero de atributos del template y el numero especificado no coinciden
    rv = C_CreateObject(hSession[0], pubTemplate, 5, &hCreateKey);
    assert(rv == CKR_SESSION_READ_ONLY);//Falla pues hSession[0] es una sesion r/o, en la cual solo se pueden crear objetos de sesion
    rv = C_CreateObject(hSession[1], pubTemplate, 5, &hCreateKey);
    assert(rv == CKR_USER_NOT_LOGGED_IN);//Falla pues hSession[1] no se encuentra logueado
    rv = C_Login(hSession[0], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_CreateObject(hSession[1], pubTemplate, 0, &hCreateKey);
    assert(rv == CKR_ATTRIBUTE_VALUE_INVALID);
    rv = C_CreateObject(hSession[1], pubTemplate, 1, &hCreateKey);
    assert(rv == CKR_ATTRIBUTE_VALUE_INVALID);
    rv = C_CreateObject(hSession[1], pubTemplate, 2, &hCreateKey);
    assert(rv == CKR_TEMPLATE_INCOMPLETE);
    rv = C_CreateObject(hSession[1], pubTemplate, 11, &hCreateKey);
    assert(rv == CKR_ATTRIBUTE_TYPE_INVALID);// Fallan pues el numero de atributos del template es diferente al especificado
    rv = C_CreateObject(hSession[1], pubTemplate, 10, &hCreateKey);
    assert(rv == CKR_OK);
    rv = C_DestroyObject(hSession[1], hCreateKey);
    assert(rv == CKR_OK);
    
    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);

  }

  printf("OK\n");
}

void runObjectCheck(unsigned int counter) {
  CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  static CK_ULONG modulusBits = 768;
  static CK_BYTE publicExponent[] = { 3 };
  static CK_BYTE id[] = {123};
  static CK_BBOOL true = CK_TRUE;
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_ENCRYPT, &true, sizeof(true)},
    {CKA_VERIFY, &true, sizeof(true)},
    {CKA_WRAP, &true, sizeof(true)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_PRIVATE, &true, sizeof(true)},
    {CKA_ID, id, sizeof(id)},
    {CKA_SENSITIVE, &true, sizeof(true)},
    {CKA_DECRYPT, &true, sizeof(true)},
    {CKA_SIGN, &true, sizeof(true)},
    {CKA_UNWRAP, &true, sizeof(true)},
    {CKA_TOKEN, &true, sizeof(true)}
  };

  unsigned int i;

  printf("Checking C_GetAttributeValue, C_SetAttributeValue, C_FindObjectsInit, C_FindObjects, and C_FindObjectsFinal: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    static CK_OBJECT_CLASS oClass = CKO_PUBLIC_KEY;
    CK_ATTRIBUTE searchTemplate[] = {
      {CKA_CLASS, &oClass, sizeof(oClass)}
    };
    CK_OBJECT_HANDLE hObject;
    CK_ULONG ulObjectCount;
    CK_ATTRIBUTE getAttr = {CKA_PRIME_1, NULL_PTR, 0};
    CK_ULONG attValueLen;
    static CK_UTF8CHAR label[] = {"New label"};
    CK_ATTRIBUTE template1[] = {
      {CKA_LABEL, label, sizeof(label)-1}
    };
    CK_ATTRIBUTE template2[] = {
      {CKA_CLASS, NULL_PTR, 0}
    };


    /* No init */

    rv = C_FindObjectsInit(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);// Falla pues la aplicacion aun no es una cryptoki
    rv = C_FindObjects(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);// Falla pues la aplicacion aun no es una cryptoki
    rv = C_FindObjectsFinal(CK_INVALID_HANDLE);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);// Falla pues la aplicacion aun no es una cryptoki
    rv = C_GetAttributeValue(CK_INVALID_HANDLE, CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);// Falla pues la aplicacion aun no es una cryptoki
    rv = C_SetAttributeValue(CK_INVALID_HANDLE, CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);// Falla pues la aplicacion aun no es una cryptoki

    /* Initializing */

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);//Abre la sesion hSession[0] como r/o y la sesion hSession[1] como r/w
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_GenerateKeyPair(hSession[1], &mechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);//Genera un par de clave publica y privada guardandola con sus respectivos handles hPublicKey y hPrivateKey
    assert(rv == CKR_OK);
    rv = C_Logout(hSession[1]);//Se desloguea, por lo que hSession[0] y hSession[1] pasan a ser sesiones publicas
    assert(rv == CKR_OK);

    /* C_FindObjectsInit */

    rv = C_FindObjectsInit(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID); //Falla pues se le da un handle de sesion invalido
    rv = C_FindObjectsInit(hSession[0], NULL_PTR, 1);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita en su segundo argumento un puntero a CK_ATTRIBUTE, que contiene el template con las propiedades de los objetos a buscar
    rv = C_FindObjectsInit(hSession[0], searchTemplate, 1);
    assert(rv == CKR_OK);
    rv = C_FindObjectsInit(hSession[0], searchTemplate, 1);
    assert(rv == CKR_OPERATION_ACTIVE);//Falla pues ya hay otra busqueda en curso en esa sesion

    /* C_FindObjects */

    rv = C_FindObjects(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues se le dio un hadle de sesion invalido
    rv = C_FindObjects(hSession[1], NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);//Falla pues la sesion hSession[1] no ha iniciado ninguna operacion de busqueda
    rv = C_FindObjects(hSession[0], NULL_PTR, 0, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a un CK_OBJECT_HANDLE arreglo en el cual se recibira la lista de handles de los objetos encontrados
    rv = C_FindObjects(hSession[0], &hObject, 0, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues el numero de handles que se recibiran se especifica como 0 y se necesita un puntero a un CK_ULONG que contiene el numero actual de handles retornados
    rv = C_FindObjects(hSession[0], &hObject, 1, &ulObjectCount);
    assert(rv == CKR_OK);

    /* C_FindObjectsFinal */

    rv = C_FindObjectsFinal(CK_INVALID_HANDLE);
    assert(rv == CKR_SESSION_HANDLE_INVALID);// Falla pues el handle de sesion es invalido
    rv = C_FindObjectsFinal(hSession[1]);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);// Falla pues la sesion hSession[1] no ha iniciado ninguna busqueda
    rv = C_FindObjectsFinal(hSession[0]);//Para especificar que la operacion de busqueda ha finalizado
    assert(rv == CKR_OK);

    /* C_GetAttributeValue */

    rv = C_GetAttributeValue(CK_INVALID_HANDLE, CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);// Falla pues el handle de sesion es invalido
    rv = C_GetAttributeValue(hSession[0], CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);// Falla pues el handle de objeto es invalido
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, NULL_PTR, 0);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);//Falla pues necesita estar logueado para realizar esta operacion
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a un CK_ATTRIBUTE que contiene los atributos que se quieren obtener del objeto
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, &getAttr, 1);
    assert(rv == CKR_ATTRIBUTE_SENSITIVE);//Falla pues se quiere obtener el CKA_PRIME_1 el cual es sensitive o unextractable
    getAttr.type = 45678; /* Not valid attribute? */
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, &getAttr, 1);
    assert(rv == CKR_ATTRIBUTE_TYPE_INVALID);// Falla pues 45678 no es un tipo de atributo valido
    getAttr.type = CKA_ID;
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, &getAttr, 1);
    assert(rv == CKR_OK);//En este punto getAttr tiene su largo ok, pero no ha obtenido aun el atributo
    getAttr.pValue = (CK_BYTE_PTR)malloc(getAttr.ulValueLen);//Para esto aloca memoria
    attValueLen = getAttr.ulValueLen;
    getAttr.ulValueLen = 0;
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, &getAttr, 1);
    assert(rv == CKR_BUFFER_TOO_SMALL);//Sucede pues se establecio ulValueLen como 0
    getAttr.ulValueLen = attValueLen;//Se vuelve el largo al obtenido en el primer llamado de getAtt
    rv = C_GetAttributeValue(hSession[0], hPrivateKey, &getAttr, 1);
    assert(rv == CKR_OK);
    free(getAttr.pValue);
    rv = C_Logout(hSession[1]);
    assert(rv == CKR_OK);

    /* C_SetAttributeValue */

    rv = C_SetAttributeValue(CK_INVALID_HANDLE, CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);// Falla pues el handle de sesion es invalido
    rv = C_SetAttributeValue(hSession[0], CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);// Falla pues el handle de objeto es invalido
    rv = C_SetAttributeValue(hSession[0], hPrivateKey, NULL_PTR, 0);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);// Falla pues la sesion no esta logueada, creo que deberia ser CKR_USER_NOT_LOGGED_IN, o CKR_SESSION_CLOSED
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_SetAttributeValue(hSession[0], hPrivateKey, NULL_PTR, 0);
    assert(rv == CKR_OBJECT_HANDLE_INVALID);// Falla pues hSession[0] es r/o, creo que deberia se CKR_SESSION_READ_ONLY
    rv = C_SetAttributeValue(hSession[1], hPrivateKey, NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);// Falla pues necesita un puntero a CK_ATTRIBUTE, en donde se especifican los atributos a modificar y sus nuevos valores
    rv = C_SetAttributeValue(hSession[1], hPrivateKey, template2, 1);
    assert(rv == CKR_ATTRIBUTE_READ_ONLY);// Falla pues se quiere modificar la clase del objeto, el cual es un atributo r/o
    rv = C_SetAttributeValue(hSession[1], hPrivateKey, template1, 1);//Se modifica el CK_LABEL del objeto
    assert(rv == CKR_OK);

    /* Finalizing */

    rv = C_DestroyObject(hSession[1], hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_DestroyObject(hSession[1], hPublicKey);
    assert(rv == CKR_OK);
    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK); //-.- no se testeo acerca de los objeto que se buscaron -.-
  }

  printf("OK\n");
}


void runDigestCheck(unsigned int counter) {
  unsigned int i;

  printf("Checking C_DigestInit, C_Digest, C_DigestUpdate, and C_DigestFinal: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    CK_MECHANISM mechanism = {
      CKM_VENDOR_DEFINED, NULL_PTR, 0
    };
    CK_ULONG digestLen;
    CK_BYTE_PTR digest;
    CK_BYTE data[] = {"Text to digest"};

    /* No init */

    rv = C_DigestInit(CK_INVALID_HANDLE, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED); //Falla pues no es una aplicacion cryptoki
    rv = C_Digest(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED); //Falla pues no es una aplicacion cryptoki
    rv = C_DigestUpdate(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED); //Falla pues no es una aplicacion cryptoki
    rv = C_DigestFinal(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED); //Falla pues no es una aplicacion cryptoki

    /* Initializing */

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);//Habre dos sesiones r/o hSession[0] y hSession[1]

    /* C_DigestInit */

    rv = C_DigestInit(CK_INVALID_HANDLE, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID); //Falla pues se le da un handle de sesion invalido
    rv = C_DigestInit(hSession[0], NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD); //Falla pues necesita un puntero a un CK_MECHANISM que corresponde al mecanismo que se usara
    rv = C_DigestInit(hSession[0], &mechanism);
    assert(rv == CKR_MECHANISM_INVALID);//Falla pues CKM_VENDOR_DEFINED no es un mecanismo valido
    mechanism.mechanism = CKM_SHA512;
    rv = C_DigestInit(hSession[0], &mechanism);
    assert(rv == CKR_OK);
    rv = C_DigestInit(hSession[0], &mechanism);
    assert(rv == CKR_OPERATION_ACTIVE);//Falla pues ya hay un digest en curso en esta sesion hSession[0]

    /* C_Digest */

    rv = C_Digest(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues el handle de sesion es invalido
    rv = C_Digest(hSession[1], NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);//Falla pues en la sesion hSession[1] no se ha inicializado una operacion de digest
    rv = C_Digest(hSession[0], NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a CK_ULONG en donde almacenara el largo del digest
    rv = C_Digest(hSession[0], NULL_PTR, 0, NULL_PTR, &digestLen);
    assert(rv == CKR_OK);

    //ARIEL CODE
    //printf("%u",digestLen);
    //ARIEL CODE

    digest = (CK_BYTE_PTR)malloc(digestLen);
    digestLen = 0;
    rv = C_Digest(hSession[0], NULL_PTR, 0, digest, &digestLen);
    assert(rv == CKR_BUFFER_TOO_SMALL);//Falla pues se cambio el largo del digest a 0(no suficiente-- test esto)
    rv = C_Digest(hSession[0], NULL_PTR, 0, digest, &digestLen);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a un CK_BYTE en donde se encuentra la data a la cual se le hara el digest
    rv = C_Digest(hSession[0], data, sizeof(data)-1, digest, &digestLen);
    assert(rv == CKR_OK);
    rv = C_Digest(hSession[0], data, sizeof(data)-1, digest, &digestLen);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);//Falla pues para hacer digest denuevo en este enfoque, se debe inicializar denuevo
    free(digest);

    /* C_DigestUpdate *///OTRO ENFOQUE MAS LARGO QUE DIGEST

    rv = C_DigestUpdate(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);// Falla pues el handle de session es invalido
    rv = C_DigestUpdate(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED); //Falla pues la sesion hSession[0] no ha inicializado ningun digest
    rv = C_DigestInit(hSession[0], &mechanism);
    assert(rv == CKR_OK);
    rv = C_DigestUpdate(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a CK_BYTE en donde se encuentra la parte de la data a la cual se le hara digest
    rv = C_DigestUpdate(hSession[0], data, sizeof(data)-1);
    assert(rv == CKR_OK);//EN LA DOCUMENTACION SE ESPECIFICA QUE UNA LLAMADA A C_DIGESTUPDATE QUE ENTREGA UN ERROR TERMINA LA OPERACION DE DIGEST
    /* C_DigestFinal *///RETORNA EL RESULTADO FINAL

    rv = C_DigestFinal(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues se le da un handle de sesion invalido
    rv = C_DigestFinal(hSession[1], NULL_PTR, NULL_PTR);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);//Falla pues la sesion hSession[1] no ha iniciado una operacion de digest
    rv = C_DigestFinal(hSession[0], NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a CK_ULONG, en donde dejar el largo del resultado del digest y una a CK_BYTE donde dejar el resultado mismo
    rv = C_DigestFinal(hSession[0], NULL_PTR, &digestLen);
    assert(rv == CKR_OK);
    digest = (CK_BYTE_PTR)malloc(digestLen);
    digestLen = 0;
    rv = C_DigestFinal(hSession[0], digest, &digestLen);
    assert(rv == CKR_BUFFER_TOO_SMALL);//Falla pues se setea el largo esperado del digest a 0 el cual no es suficiente
    rv = C_DigestFinal(hSession[0], digest, &digestLen);
    assert(rv == CKR_OK);
    free(digest);

    /* Finalizing */

    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);
  }

  printf("OK\n");
}

void runSignCheck(unsigned int counter) {
  CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
  CK_MECHANISM keyGenMechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  static CK_ULONG modulusBits = 768;
  static CK_BYTE publicExponent[] = { 3 };
  static CK_BYTE id[] = {123};
  static CK_BBOOL true = CK_TRUE;
  CK_ATTRIBUTE publicKeyTemplate[] = {
    {CKA_ENCRYPT, &true, sizeof(true)},
    {CKA_VERIFY, &true, sizeof(true)},
    {CKA_WRAP, &true, sizeof(true)},
    {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
    {CKA_TOKEN, &true, sizeof(true)},
    {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)}
  };
  CK_ATTRIBUTE privateKeyTemplate[] = {
    {CKA_PRIVATE, &true, sizeof(true)},
    {CKA_ID, id, sizeof(id)},
    {CKA_SENSITIVE, &true, sizeof(true)},
    {CKA_DECRYPT, &true, sizeof(true)},
    {CKA_SIGN, &true, sizeof(true)},
    {CKA_UNWRAP, &true, sizeof(true)},
    {CKA_TOKEN, &true, sizeof(true)}
  };

  unsigned int i;

  printf("Checking C_SignInit, C_Sign, C_SignUpdate, and C_SignFinal: ");

  for(i = 0; i < counter; i++) {
    CK_RV rv;
    CK_SESSION_HANDLE hSession[10];
    CK_MECHANISM mechanism = {
      CKM_VENDOR_DEFINED, NULL_PTR, 0
    };
    CK_ULONG length;
    CK_BYTE_PTR pSignature;
    CK_BYTE data[] = {"Text"};

    /* No init */

    rv = C_SignInit(CK_INVALID_HANDLE, NULL_PTR, CK_INVALID_HANDLE);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);// Falla pues no es una aplicacion cryptoki
    rv = C_Sign(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);// Falla pues no es una aplicacion cryptoki
    rv = C_SignUpdate(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);// Falla pues no es una aplicacion cryptoki
    rv = C_SignFinal(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR);
    assert(rv == CKR_CRYPTOKI_NOT_INITIALIZED);// Falla pues no es una aplicacion cryptoki

    /* Initializing */

    rv = C_Initialize(NULL_PTR);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &hSession[0]);
    assert(rv == CKR_OK);
    rv = C_OpenSession(slotWithToken, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession[1]);
    assert(rv == CKR_OK);//Abre una sesion hSession[0] r/o y otra r/w hSession[1]
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_GenerateKeyPair(hSession[1], &keyGenMechanism, publicKeyTemplate, 6, privateKeyTemplate, 7, &hPublicKey, &hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_Logout(hSession[1]);//Desloguea las sesiones
    assert(rv == CKR_OK);

    /* C_SignInit */

    rv = C_SignInit(CK_INVALID_HANDLE, NULL_PTR, CK_INVALID_HANDLE);
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues el handle de sesion no es valido
    rv = C_SignInit(hSession[0], NULL_PTR, CK_INVALID_HANDLE);
    assert(rv == CKR_KEY_HANDLE_INVALID);//Falla pues el handle de objeto llave que se le dio no es valido
    rv = C_SignInit(hSession[0], NULL_PTR, hPrivateKey);
    assert(rv == CKR_KEY_HANDLE_INVALID);//Falla pues el handle de llave esta asociado a una sesion deslogueada
    rv = C_Login(hSession[1], CKU_USER, userPIN, sizeof(userPIN) - 1);
    assert(rv == CKR_OK);
    rv = C_SignInit(hSession[0], NULL_PTR, hPrivateKey);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a CK_MECHANISM en su segundo argumento
    rv = C_SignInit(hSession[0], &mechanism, hPrivateKey);
    assert(rv == CKR_MECHANISM_INVALID);//Falla pues el mecanismo CKM_VENDOR_DEFINED no es un mecanismo valido
    mechanism.mechanism = CKM_SHA512_RSA_PKCS;//Esto encripta el digest?
    rv = C_SignInit(hSession[0], &mechanism, hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_SignInit(hSession[0], &mechanism, hPrivateKey);
    assert(rv == CKR_OPERATION_ACTIVE);//Esto falla pues la sesion hSession[0] aun no finaliza el sign anterior

    /* C_Sign */

    rv = C_Sign(CK_INVALID_HANDLE, NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues se le dio un handle de sesion invalido
    rv = C_Sign(hSession[1], NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);//Falla pues la sesion hSession[1] no ha iniciado una sign
    rv = C_Sign(hSession[0], NULL_PTR, 0, NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a un CK_ULONG que guardara el largo del signature
    rv = C_Sign(hSession[0], NULL_PTR, 0, NULL_PTR, &length);
    assert(rv == CKR_OK);
    pSignature = (CK_BYTE_PTR)malloc(length);
    length = 0;
    rv = C_Sign(hSession[0], NULL_PTR, 0, pSignature, &length);
    assert(rv == CKR_BUFFER_TOO_SMALL);//Falla pues se reinicializa el largo a 0
    rv = C_Sign(hSession[0], NULL_PTR, 0, pSignature, &length);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a un CK_BYTE del cual obtendra la data, y su respectivo largo
    rv = C_Sign(hSession[0], data, sizeof(data)-1, pSignature, &length);
    assert(rv == CKR_OK);
    rv = C_Sign(hSession[0], data, sizeof(data)-1, pSignature, &length);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);//Falla pues al hacer Sign se cierra la operacion, y para Sign denuevo se debe llamar a SigInit nuevamente
    free(pSignature);

    /* C_SignUpdate *///OTRO ENFOQUE PARA SIGN

    rv = C_SignUpdate(CK_INVALID_HANDLE, NULL_PTR, 0);
    assert(rv == CKR_SESSION_HANDLE_INVALID);// Falla pues el handle de sesion es invalido
    rv = C_SignUpdate(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED);//Falla pues no se ha inicializado ninguna operacion de sign
    rv = C_SignInit(hSession[0], &mechanism, hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_SignUpdate(hSession[0], NULL_PTR, 0);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita de un puntero a CK_BYTE en donde esta la parte que se firmara y su respectivo largo
    rv = C_SignUpdate(hSession[0], data, sizeof(data)-1);
    assert(rv == CKR_OK);

    /* C_SignFinal */

    rv = C_SignFinal(CK_INVALID_HANDLE, NULL_PTR, NULL_PTR); 
    assert(rv == CKR_SESSION_HANDLE_INVALID);//Falla pues el handle de sesion no es valido
    rv = C_SignFinal(hSession[1], NULL_PTR, NULL_PTR);
    assert(rv == CKR_OPERATION_NOT_INITIALIZED); // Falla pues no se ha inicializado ninguna operacion Sign en la sesion hSession[1]
    rv = C_SignFinal(hSession[0], NULL_PTR, NULL_PTR);
    assert(rv == CKR_ARGUMENTS_BAD);//Falla pues necesita un puntero a CK_BYTE en donde almacenara la signature final ademas de un numero igual o superior al largo de esta signature
    rv = C_SignFinal(hSession[0], NULL_PTR, &length);
    assert(rv == CKR_OK);
    pSignature = (CK_BYTE_PTR)malloc(length);
    length = 0;
    rv = C_SignFinal(hSession[0], pSignature, &length);
    assert(rv == CKR_BUFFER_TOO_SMALL);//Falla pues se reinicializo el largo a 0
    rv = C_SignFinal(hSession[0], pSignature, &length);
    assert(rv == CKR_OK);
    free(pSignature);

    /* Finalizing */

    rv = C_DestroyObject(hSession[1], hPrivateKey);
    assert(rv == CKR_OK);
    rv = C_DestroyObject(hSession[1], hPublicKey);
    assert(rv == CKR_OK);
    rv = C_Finalize(NULL_PTR);
    assert(rv == CKR_OK);
  }

  printf("OK\n");
}


