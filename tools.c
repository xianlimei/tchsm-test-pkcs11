#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <string.h>
#include "pkcs11.h"
#include "tools.h"


//PUNTERO A ESTRUCTURAS QUE TIENEN LAS FUNCIONES
extern CK_FUNCTION_LIST_PTR lib;
//PUNTERO A ESTRUCTURAS QUE TIENEN LAS FUNCIONES
void* openLib;

//Funcion que recibe una condicion y un mensaje,
//si la condicion es falsa, esta se imprime.
//Retorna el valor de la condicion.
//Funcion sirve para imprimir un mensaje descriptivo
//cuando no se pasa algun test
int message(int cond, char* message)
{
	if (!cond)
		fprintf(stderr, "* %s\n\n",message);
	return cond;
}


//Funcion que recibe dos codigos de retorno y un mensaje previo,
//Si los codigos son distintos imprime el mensaje previo junto con
//los codigos
//Retorna true si los codigos son iguales.
int verifyCode(CK_RV geted, CK_RV expected, char * previus)
{
	if (!(geted == expected))
	{
		char sGeted[100];
		char sExpected[100];
		getCodeName(geted, sGeted);
		getCodeName(expected, sExpected);		
		fprintf(stderr, "* %s, debio arrojar %s, pero arrojo %s\n\n", previus, sExpected, sGeted);
		
	}
	return geted == expected;
}

//Funcion que recibe tres codigos de retorno y un mensaje previo,
//Si el geted es diferente a todos los expected imprime el mensaje previo junto con
//los codigos
//Retorna true si el geted es igual a alguno de los expected
int verifyCode2(CK_RV geted, CK_RV expected, CK_RV expected2, char * previus)
{
	if (!(geted == expected || geted == expected2))
	{
		char sGeted[100];
		char sExpected[100];
		char sExpected2[100];
		getCodeName(geted, sGeted);
		getCodeName(expected, sExpected);		
		getCodeName(expected, sExpected2);				
		fprintf(stderr, "* %s, debio arrojar %s o %s, pero arrojo %s\n\n", previus, sExpected, sExpected2, sGeted);
		
	}
	return geted == expected || geted == expected2;
}


//Funcion que recibe tres codigos de retorno y un mensaje previo,
//Si el geted es diferente a todos los expected imprime el mensaje previo junto con
//los codigos
//Retorna true si el geted es igual a alguno de los expected
int verifyCode3(CK_RV geted, CK_RV expected, CK_RV expected2, CK_RV expected3, char * previus)
{
	if (!(geted == expected || geted == expected2 || geted == expected3))
	{
		char sGeted[100];
		char sExpected[100];
		char sExpected2[100];
		char sExpected3[100];
		getCodeName(geted, sGeted);
		getCodeName(expected, sExpected);		
		getCodeName(expected, sExpected2);	
		getCodeName(expected, sExpected3);				
		fprintf(stderr, "* %s, debio arrojar %s, %s o %s, pero arrojo %s\n\n", previus, sExpected, sExpected2, sExpected3, sGeted);
		
	}
	return geted == expected || geted == expected2 || geted == expected3;
}


//Inicializa la libreria dinamica
//Retorna 1 si la operacion fue exitosa
//0 si no
int initDynamicLibrary(char* path)
{
	openLib = dlopen(path, RTLD_LAZY);
	if (openLib == NULL)
	{
		fprintf(stderr, "Error al abrir la libreria %s\n",path);
		fprintf(stderr, "Codigo de error dlopen : %s\n",dlerror());
		return 0;
	}

	dlerror(); //Limpiar errores existentes
	void  (* getFunctionList)(CK_FUNCTION_LIST_PTR_PTR) =  dlsym(openLib, "C_GetFunctionList");
	char *e;	
	if ((e = dlerror()) != NULL) 
	{
		fprintf(stderr, "Error al acceder dinamicamente a la funcion C_GetFunctionList\n");
		fprintf(stderr, "Codigo de error dlsym : %s\n", e);
		return 0;
	}
	
	(* getFunctionList)(&lib); 
	return 1;	
}

//Cierra la libreria dinamica
//Retorna 1 si la operacion fue exitosa
//0 si no
int closeDynamicLibrary()
{
	if (dlclose(openLib) != 0)
	{
		fprintf(stderr, "Error al cerrar la libreria dinamica\n");
		fprintf(stderr, "Codigo de error dlclose : %s\n", dlerror());
		return 0;
	}
	return 1;
}

//Funcion imprime en salida estandar
//el string en data, con un nivel de
//indentacion level
//Si showMessage es 0 no se muestra el mensage
void printlnLevel(int showMessage, char* data ,int level)
{
	if(showMessage)
	{	
		int i;
		for (i= 0; i < level; i++)
	    		printf("    ");
	  	printf("%s\n", data);
	}
}

//Chequea que todos los punteros a fuciones de la estructura
//sean validos(si una funcion no se encuentra implementada, 
//el puntero debe apuntar a una funcion que retorne CKR_FUNCTION_
//NOT_SUPPORTED)
//Retorna NULL_PTR en caso de exito, y el nombre de una funcion no implementada en caso contrario
char* checkCkFunctionList(CK_FUNCTION_LIST_PTR pFunctions)
{
	char* temp = NULL_PTR;
	#undef C_Initialize
	#undef C_Finalize
	#undef C_GetInfo
	#undef C_GetFunctionList
	#undef C_InitToken
	#undef C_InitPIN
	#undef C_SetPIN
	#undef C_GetSlotList
	#undef C_GetSlotInfo
	#undef C_GetTokenInfo
	#undef C_OpenSession
	#undef C_CloseSession
	#undef C_CloseAllSessions
	#undef C_GetSessionInfo
	#undef C_Login
	#undef C_Logout
	#undef C_CreateObject
	#undef C_DestroyObject
	#undef C_FindObjectsInit
	#undef C_FindObjects
	#undef C_FindObjectsFinal
	#undef C_GetAttributeValue
	#undef C_DigestInit
	#undef C_Digest
	#undef C_SignInit
	#undef C_Sign
	#undef C_GenerateKeyPair
	#undef C_SeedRandom
	#undef C_GenerateRandom
	
	if (pFunctions -> C_Initialize == NULL_PTR) temp = "C_Initialize";
	else if(pFunctions -> C_Finalize == NULL_PTR) temp = "C_Finalize";
	else if(pFunctions -> C_GetInfo == NULL_PTR) temp = "C_GetInfo";
	else if(pFunctions -> C_GetFunctionList == NULL_PTR) temp = "C_GetFunctionList";
	else if(pFunctions -> C_GetSlotList == NULL_PTR) temp = "C_GetSlotList";
	else if(pFunctions -> C_GetSlotInfo == NULL_PTR) temp = "C_GetSlotInfo";
	else if(pFunctions -> C_GetTokenInfo == NULL_PTR) temp = "C_GetTokenInfo";	
	else if(pFunctions -> C_WaitForSlotEvent == NULL_PTR) temp = "C_WaitForSlotEvent";
	else if(pFunctions -> C_GetMechanismList == NULL_PTR) temp = "C_GetMechanismList";
	else if(pFunctions -> C_GetMechanismInfo == NULL_PTR) temp = "C_GetMechanismInfo";
	else if(pFunctions -> C_InitToken == NULL_PTR) temp = "C_InitToken";
	else if(pFunctions -> C_InitPIN == NULL_PTR) temp = "C_InitPIN";
	else if(pFunctions -> C_SetPIN == NULL_PTR) temp = "C_SetPIN";
	else if(pFunctions -> C_OpenSession == NULL_PTR) temp = "C_OpenSession";
	else if(pFunctions -> C_CloseSession == NULL_PTR) temp = "C_CloseSession";
	else if(pFunctions -> C_CloseAllSessions == NULL_PTR) temp = "C_CloseAllSessions";
	else if(pFunctions -> C_GetSessionInfo == NULL_PTR) temp = "C_GetSessionInfo";
	else if(pFunctions -> C_GetOperationState == NULL_PTR) temp = "C_GetOperationState";
	else if(pFunctions -> C_SetOperationState == NULL_PTR) temp = "C_SetOperationState";
	else if(pFunctions -> C_Login == NULL_PTR) temp = "C_Login";
	else if(pFunctions -> C_Logout == NULL_PTR) temp = "C_Logout";
	else if(pFunctions -> C_CreateObject == NULL_PTR) temp = "C_CreateObject";
	else if(pFunctions -> C_CopyObject == NULL_PTR) temp = "C_CopyObject";
	else if(pFunctions -> C_DestroyObject == NULL_PTR) temp = "C_DestroyObject";
	else if(pFunctions -> C_GetObjectSize == NULL_PTR) temp = "C_GetObjectSize";
	else if(pFunctions -> C_GetAttributeValue == NULL_PTR) temp = "C_GetAttributeValue";
	else if(pFunctions -> C_SetAttributeValue == NULL_PTR) temp = "C_SetAttributeValue";	
	else if(pFunctions -> C_FindObjectsInit == NULL_PTR) temp = "C_FindObjectsInit";
	else if(pFunctions -> C_FindObjects == NULL_PTR) temp = "C_FindObjects";
	else if(pFunctions -> C_FindObjectsFinal == NULL_PTR) temp = "C_FindObjectsFinal";
	else if(pFunctions -> C_EncryptInit == NULL_PTR) temp = "C_EncryptInit";
	else if(pFunctions -> C_Encrypt == NULL_PTR) temp = "C_Encrypt";
	else if(pFunctions -> C_EncryptUpdate == NULL_PTR) temp = "C_EncryptUpdate";
	else if(pFunctions -> C_EncryptFinal == NULL_PTR) temp = "C_EncryptFinal";
	else if(pFunctions -> C_DecryptInit == NULL_PTR) temp = "C_DecryptInit";
	else if(pFunctions -> C_Decrypt == NULL_PTR) temp = "C_Decrypt";
	else if(pFunctions -> C_DecryptUpdate == NULL_PTR) temp = "C_DecryptUpdate";
	else if(pFunctions -> C_DecryptFinal == NULL_PTR) temp = "C_DecryptFinal";
	else if(pFunctions -> C_DigestInit == NULL_PTR) temp = "C_DigestInit";
	else if(pFunctions -> C_Digest == NULL_PTR) temp = "C_Digest";
	else if(pFunctions -> C_DigestUpdate == NULL_PTR) temp = "C_DigestUpdate";
	else if(pFunctions -> C_DigestKey == NULL_PTR) temp = "C_DigestKey";
	else if(pFunctions -> C_DigestFinal == NULL_PTR) temp = "C_DigestFinal";
	else if(pFunctions -> C_SignInit == NULL_PTR) temp = "C_SignInit";
	else if(pFunctions -> C_Sign == NULL_PTR) temp = "C_Sign";
	else if(pFunctions -> C_SignUpdate == NULL_PTR) temp = "C_SignUpdate";
	else if(pFunctions -> C_SignFinal == NULL_PTR) temp = "C_SignFinal";	
	else if(pFunctions -> C_SignRecoverInit == NULL_PTR) temp = "C_SignRecoverInit";
	else if(pFunctions -> C_SignRecover == NULL_PTR) temp = "C_SignRecover";
	else if(pFunctions -> C_VerifyInit == NULL_PTR) temp = "C_VerifyInit";
	else if(pFunctions -> C_Verify == NULL_PTR) temp = "C_Verify";
	else if(pFunctions -> C_VerifyUpdate == NULL_PTR) temp = "C_VerifyUpdate";
	else if(pFunctions -> C_VerifyFinal == NULL_PTR) temp = "C_VirifyFinal";
	else if(pFunctions -> C_VerifyRecoverInit == NULL_PTR) temp = "C_VerifyRecoverInit";
	else if(pFunctions -> C_VerifyRecover == NULL_PTR) temp = "C_VerifyRecover";
	else if(pFunctions -> C_DigestEncryptUpdate == NULL_PTR) temp = "C_DigestEncryptUpdate";
	else if(pFunctions -> C_DecryptDigestUpdate == NULL_PTR) temp = "C_DecryptDigestUpdate";
	else if(pFunctions -> C_SignEncryptUpdate == NULL_PTR) temp = "C_SignEncryptUpdate";
	else if(pFunctions -> C_DecryptVerifyUpdate == NULL_PTR) temp = "C_DecriptVerifyUpdate";
	else if(pFunctions -> C_GenerateKey == NULL_PTR) temp = "C_GenerateKey";
	else if(pFunctions -> C_GenerateKeyPair == NULL_PTR) temp = "C_GenerateKeyPair";
	else if(pFunctions -> C_WrapKey == NULL_PTR) temp = "C_WrapKey";
	else if(pFunctions -> C_UnwrapKey == NULL_PTR) temp = "C_UnwrapKey";
	else if(pFunctions -> C_DeriveKey == NULL_PTR) temp = "C_DeriveKey";
	else if(pFunctions -> C_SeedRandom == NULL_PTR) temp = "C_SeedRandom";
	else if(pFunctions -> C_GenerateRandom == NULL_PTR) temp = "C_GenerateRandom";
	else if(pFunctions -> C_GetFunctionStatus == NULL_PTR) temp = "C_GetFunctionStatus";
	else if(pFunctions -> C_CancelFunction == NULL_PTR) temp = "C_CancelFunction";
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
	#define C_FindObjectsInit (lib -> C_FindObjectsInit)
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
	if(temp == NULL_PTR)
	{	
		return NULL_PTR;
	}
	char* retu;
	retu = (char *) malloc( ( strlen(temp)+1 )*sizeof(char) );
	strcpy(retu, temp);
	return retu;
}

//Retorna 1 si el set tiene a elem como elemento
//0 en caso contrario
int contains(int * set, int size, int elem)
{
	int i;
	for (i = 0; i < size; ++i)
	{
		if (set[i] == elem) return 1;
	}
	return 0;
}

//Retorna 1 si el string src no tiene NULL_PTR,
//0 en otro caso
int isBlankPadded(unsigned char * src, int n)
{
	int i;
	for (i = 0; i < n; ++i)
	{
		if (src[i] == (unsigned char)0) return 0;
	}
	return 1;
}

//From the source in byte mode build the same in str mode and keep 
// the result into the result param if the sourceLen is N then the 
//result should have enough memory to keep 2N + 1 spaces
void toStr(unsigned char * source, int sourceLen, char * result)
{
	int j;
	for (j = 0; j < sourceLen; ++j)
	{
		char pre [3];
		sprintf(pre, "%02x", source[j]);
		result[2*j] = toupper(pre[0]);
		result[2*j+1] = toupper(pre[1]);
	
	}
	result[2*sourceLen] = 0;
}

//Retorna el indice del primer elemento elem en el arreglo array de n elementos
//-1 si no existe
int indice(int elem, int * array, int n)
{
	int x;
	for(x = 0; x < n; ++x)
	{
		if (array[x] == elem) return x;
	}
	return -1;
}

//assert 2 recibe un comportamiento y una condicion
//Si el comportamiento es ASK, se pregunta al usuario si se sigue con la ejecucion del test
//Si el comportamiento es FAIL, el test termina
//Si el comportamiento es PASS, el test continua
void assert2(int beh, int cond)
{
	switch(beh)
	{
		case ASK :
			if(!cond)
			{
				char o [2];
				printf("Desea continuar?(y/n)(Una falla en un test puede ocasionar fallas en los siguientes)\n");
				scanf("%s", o);
   				if(o[0] == 'n')exit(1);
			}
		break;

		case FAIL :
			if(!cond)exit(1);
		break;

	}

}

//Rellena el nombre de una clase dado su valor(especificado en PKCS11)
void getClassName(CK_OBJECT_CLASS elem, char * buffer)
{
	switch(elem)
	{
		case CKO_PUBLIC_KEY :
			memcpy(buffer,"CKO_PUBLIC_KEY", strlen("CKO_PUBLIC_KEY")+1);
			return;
		
		case CKO_PRIVATE_KEY :
			memcpy(buffer,"CKO_PRIVATE_KEY", strlen("CKO_PRIVATE_KEY")+1);
			return;

		case CKO_HW_FEATURE :
			memcpy(buffer,"CKO_HW_FEATURE", strlen("CKO_HW_FEATURE")+1);
			return;
		
		case CKO_SECRET_KEY:
			memcpy(buffer,"CKO_SECRET_KEY", strlen("CKO_SECRET_KEY")+1);
			return;
		default :
			memcpy(buffer,"Not Found", strlen("Not Found")+1);
			return;
		
	}
}


//Rellena el nombre de un tipo de usuario dado su valor(especificado en PKCS11)
void getUserName(CK_USER_TYPE elem, char * buffer)
{
	switch(elem)
	{
		case CKU_SO :
			memcpy(buffer,"CKU_SO", strlen("CKU_SO")+1);
			return;
		
		case CKU_USER :
			memcpy(buffer,"CKU_USER", strlen("CKU_USER")+1);
			return;

		case CKU_CONTEXT_SPECIFIC :
			memcpy(buffer,"CKU_CONTEXT_SPECIFIC", strlen("CKU_CONTEXT_SPECIFIC")+1);
			return;
	
		default :
			memcpy(buffer,"Not Found", strlen("Not Found")+1);
			return;
		
	}
}

//Rellena el nombre de un estado dado su valor(especificado en PKCS11)
void getStateName(CK_STATE elem, char * buffer)
{
	switch(elem)
	{
		case CKS_RO_PUBLIC_SESSION :
			memcpy(buffer,"CKS_RO_PUBLIC_SESSION", strlen("CKS_RO_PUBLIC_SESSION")+1);
			return;
		
		case CKS_RO_USER_FUNCTIONS :
			memcpy(buffer,"CKS_RO_USER_FUNCTIONS", strlen("CKS_RO_USER_FUNCTIONS")+1);
			return;

		case CKS_RW_PUBLIC_SESSION :
			memcpy(buffer,"CKS_RW_PUBLIC_SESSION", strlen("CKS_RW_PUBLIC_SESSION")+1);
			return;
		
		case CKS_RW_USER_FUNCTIONS:
			memcpy(buffer,"CKS_RW_USER_FUNCTIONS", strlen("CKS_RW_USER_FUNCTIONS")+1);
			return;
		
		case CKS_RW_SO_FUNCTIONS:
			memcpy(buffer,"CKS_RW_SO_FUNCTIONS", strlen("CKS_RW_SO_FUNCTIONS")+1);
			return;
		default :
			memcpy(buffer,"Not Found", strlen("Not Found")+1);
			return;
		
	}
}

//Rellena el nombre de un hadware dado su valor(especificado en PKCS11)
void getHadwareName(CK_HW_FEATURE_TYPE elem, char * buffer)
{
	switch(elem)
	{
		case CKH_MONOTONIC_COUNTER:
			memcpy(buffer,"CKH_MONOTONIC_COUNTER", strlen("CKH_MONOTONIC_COUNTER")+1);
			return;
		default :
			memcpy(buffer,"Not Found", strlen("Not Found")+1);
			return;
		
	}
}

//Rellena el nombre de una key dado su valor(especificado en PKCS11)
void getKeyName(CK_KEY_TYPE elem, char * buffer)
{
	switch(elem)
	{
		case CKK_RSA:
			memcpy(buffer,"CKK_RSA", strlen("CKK_RSA")+1);
			return;

		case CKK_DSA:
			memcpy(buffer,"CKK_DSA", strlen("CKK_DSA")+1);
			return;
		
		case CKK_DES:
			memcpy(buffer,"CKK_DES", strlen("CKK_DES")+1);
			return;

		default :
			memcpy(buffer,"Not Found", strlen("Not Found")+1);
			return;
		
	}
}

//Rellena el nombre de un atributo dado su valor(especificado en PKCS11)
void getAttributeName(CK_ATTRIBUTE_TYPE elem, char * buffer)
{
	switch(elem)
	{
		case CKA_CLASS:
			memcpy(buffer,"CKA_CLASS", strlen("CKA_CLASS")+1);
			return;

		case CKA_KEY_TYPE:
			memcpy(buffer,"CKA_KEY_TYPE", strlen("CKA_KEY_TYPE")+1);
			return;

		case CKA_LABEL:
			memcpy(buffer,"CKA_LABEL", strlen("CKA_LABEL")+1);
			return;

		case CKA_ID:
			memcpy(buffer,"CKA_ID", strlen("CKA_ID")+1);
			return;

		case CKA_TOKEN:
			memcpy(buffer,"CKA_TOKEN", strlen("CKA_TOKEN")+1);
			return;

		case CKA_VERIFY:
			memcpy(buffer,"CKA_VERIFY", strlen("CKA_VERIFY")+1);
			return;

		case CKA_ENCRYPT:
			memcpy(buffer,"CKA_ENCRYPT", strlen("CKA_ENCRYPT")+1);
			return;

		case CKA_PRIVATE:
			memcpy(buffer,"CKA_PRIVATE", strlen("CKA_PRIVATE")+1);
			return;

		case CKA_PUBLIC_EXPONENT:
			memcpy(buffer,"CKA_PUBLIC_EXPONENT", strlen("CKA_PUBLIC_EXPONENT")+1);
			return;

		case CKA_MODULUS:
			memcpy(buffer,"CKA_MODULUS", strlen("CKA_MODULUS")+1);
			return;

		case CKA_WRAP:
			memcpy(buffer,"CKA_WRAP", strlen("CKA_WRAP")+1);
			return;

		case CKA_CERTIFICATE_CATEGORY:
			memcpy(buffer,"CKA_CERTIFICATE_CATEGORY", strlen("CKA_CERTIFICATE_CATEGORY")+1);
			return;

		case CKA_HW_FEATURE_TYPE:
			memcpy(buffer,"CKA_HW_FEATURE_TYPE", strlen("CKA_HW_FEATURE_TYPE")+1);
			return;

		case CKA_SENSITIVE:
			memcpy(buffer,"CKA_SENSITIVE", strlen("CKA_SENSITIVE")+1);
			return;

		case CKA_DECRYPT:
			memcpy(buffer,"CKA_DECRYPT", strlen("CKA_DECRYPT")+1);
			return;

		case CKA_SIGN:
			memcpy(buffer,"CKA_SIGN", strlen("CKA_SIGN")+1);
			return;

		case CKA_UNWRAP:
			memcpy(buffer,"CKA_UNWRAP", strlen("CKA_UNWRAP")+1);
			return;

		case CKA_MODULUS_BITS:
			memcpy(buffer,"CKA_MODULUS_BITS", strlen("CKA_MODULUS_BITS")+1);
			return;

		case CKA_EXTRACTABLE:
			memcpy(buffer,"CKA_EXTRACTABLE", strlen("CKA_EXTRACTABLE")+1);
			return;

		case CKA_PRIME_1:
			memcpy(buffer,"CKA_PRIME_1", strlen("CKA_PRIME_1")+1);
			return;

		case CKA_LOCAL:
			memcpy(buffer,"CKA_LOCAL", strlen("CKA_LOCAL")+1);
			return;

		case CKA_VALUE:
			memcpy(buffer,"CKA_VALUE", strlen("CKA_VALUE")+1);
			return;

		case CKA_PRIVATE_EXPONENT:
			memcpy(buffer,"CKA_PRIVATE_EXPONENT", strlen("CKA_PRIVATE_EXPONENT")+1);
			return;

		default :
			memcpy(buffer,"Not Found", strlen("Not Found")+1);
			return;
		
	}
}

//Rellena el nombre de un mecanismo dado su valor(especificado en PKCS11)
void getMechanismName(CK_MECHANISM_TYPE elem, char * buffer)
{
	switch(elem)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			memcpy(buffer,"CKM_RSA_PKCS_KEY_PAIR_GEN", strlen("CKM_RSA_PKCS_KEY_PAIR_GEN")+1);
			return;

		case CKM_RSA_PKCS:
			memcpy(buffer,"CKM_RSA_PKCS", strlen("CKM_RSA_PKCS")+1);
			return;

		case CKM_SHA1_RSA_PKCS:
			memcpy(buffer,"CKM_SHA1_RSA_PKCS", strlen("CKM_SHA1_RSA_PKCS")+1);
			return;

		case CKM_MD5:
			memcpy(buffer,"CKM_MD5", strlen("CKM_MD5")+1);
			return;

		case CKM_SHA_1:
			memcpy(buffer,"CKM_SHA_1", strlen("CKM_SHA_1")+1);
			return;

		case CKM_SHA256:
			memcpy(buffer,"CKM_SHA256", strlen("CKM_SHA256")+1);
			return;

		case CKM_SHA384:
			memcpy(buffer,"CKM_SHA384", strlen("CKM_SHA384")+1);
			return;

		case CKM_SHA512:
			memcpy(buffer,"CKM_SHA512", strlen("CKM_SHA512")+1);
			return;

		default :
			memcpy(buffer,"Not Found", strlen("Not Found")+1);
			return;
		
	}
}

//Rellena el nombre de un mecanismo dado su valor(especificado en PKCS11)
void getCodeName(CK_RV elem, char * buffer)
{
	switch(elem)
	{
		case CKR_OK:
			memcpy(buffer,"CKR_OK", strlen("CKR_OK")+1);
			return;
		
		case CKR_HOST_MEMORY:
			memcpy(buffer,"CKR_HOST_MEMORY", strlen("CKR_HOST_MEMORY")+1);
			return;

		case CKR_SLOT_ID_INVALID:
			memcpy(buffer,"CKR_SLOT_ID_INVALID", strlen("CKR_SLOT_ID_INVALID")+1);
			return;

		case CKR_GENERAL_ERROR:
			memcpy(buffer,"CKR_GENERAL_ERROR", strlen("CKR_GENERAL_ERROR")+1);
			return;

		case CKR_FUNCTION_FAILED:
			memcpy(buffer,"CKR_FUNCTION_FAILED", strlen("CKR_FUNCTION_FAILED")+1);
			return;

		case CKR_ARGUMENTS_BAD:
			memcpy(buffer,"CKR_ARGUMENTS_BAD", strlen("CKR_ARGUMENTS_BAD")+1);
			return;

		case CKR_ATTRIBUTE_READ_ONLY:
			memcpy(buffer,"CKR_ATTRIBUTE_READ_ONLY", strlen("CKR_ATTRIBUTE_READ_ONLY")+1);
			return;
		
		case CKR_ATTRIBUTE_SENSITIVE:
			memcpy(buffer,"CKR_ATTRIBUTE_SENSITIVE", strlen("CKR_ATTRIBUTE_SENSITIVE")+1);
			return;

		case CKR_ATTRIBUTE_TYPE_INVALID:
			memcpy(buffer,"CKR_ATTRIBUTE_TYPE_INVALID", strlen("CKR_ATTRIBUTE_TYPE_INVALID")+1);
			return;

		case CKR_ATTRIBUTE_VALUE_INVALID:
			memcpy(buffer,"CKR_ATTRIBUTE_VALUE_INVALID", strlen("CKR_ATTRIBUTE_VALUE_INVALID")+1);
			return;

		case CKR_DATA_LEN_RANGE:
			memcpy(buffer,"CKR_DATA_LEN_RANGE", strlen("CKR_DATA_LEN_RANGE")+1);
			return;

		case CKR_DEVICE_ERROR:
			memcpy(buffer,"CKR_", strlen("CKR_")+1);
			return;

		case CKR_DEVICE_MEMORY:
			memcpy(buffer,"CKR_DEVICE_MEMORY", strlen("CKR_DEVICE_MEMORY")+1);
			return;

		case CKR_DEVICE_REMOVED:
			memcpy(buffer,"CKR_DEVICE_REMOVED", strlen("CKR_DEVICE_REMOVED")+1);
			return;

		case CKR_FUNCTION_CANCELED:
			memcpy(buffer,"CKR_FUNCTION_CANCELED", strlen("CKR_FUNCTION_CANCELED")+1);
			return;

		case CKR_FUNCTION_NOT_SUPPORTED:
			memcpy(buffer,"CKR_", strlen("CKR_FUNCTION_NOT_SUPPORTED")+1);
			return;

		case CKR_KEY_HANDLE_INVALID:
			memcpy(buffer,"CKR_KEY_HANDLE_INVALID", strlen("CKR_KEY_HANDLE_INVALID")+1);
			return;

		case CKR_KEY_TYPE_INCONSISTENT:
			memcpy(buffer,"CKR_KEY_TYPE_INCONSISTENT", strlen("CKR_KEY_TYPE_INCONSISTENT")+1);
			return;

		case CKR_MECHANISM_INVALID:
			memcpy(buffer,"CKR_MECHANISM_INVALID", strlen("CKR_MECHANISM_INVALID")+1);
			return;

		case CKR_MECHANISM_PARAM_INVALID:
			memcpy(buffer,"CKR_MECHANISM_PARAM_INVALID", strlen("CKR_MECHANISM_PARAM_INVALID")+1);
			return;

		case CKR_OBJECT_HANDLE_INVALID:
			memcpy(buffer,"CKR_OBJECT_HANDLE_INVALID", strlen("CKR_OBJECT_HANDLE_INVALID")+1);
			return;

		case CKR_OPERATION_ACTIVE:
			memcpy(buffer,"CKR_OPERATION_ACTIVE", strlen("CKR_OPERATION_ACTIVE")+1);
			return;

		case CKR_OPERATION_NOT_INITIALIZED:
			memcpy(buffer,"CKR_OPERATION_NOT_INITIALIZED", strlen("CKR_OPERATION_NOT_INITIALIZED")+1);
			return;

		case CKR_PIN_INCORRECT:
			memcpy(buffer,"CKR_PIN_INCORRECT", strlen("CKR_PIN_INCORRECT")+1);
			return;

		case CKR_PIN_LEN_RANGE:
			memcpy(buffer,"CKR_PIN_LEN_RANGE", strlen("CKR_PIN_LEN_RANGE")+1);
			return;

		case CKR_SESSION_COUNT:
			memcpy(buffer,"CKR_CKR_SESSION_COUNT", strlen("CKR_CKR_SESSION_COUNT")+1);
			return;

		case CKR_SESSION_HANDLE_INVALID:
			memcpy(buffer,"CKR_SESSION_HANDLE_INVALID", strlen("CKR_SESSION_HANDLE_INVALID")+1);
			return;

		case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
			memcpy(buffer,"CKR_SESSION_PARALLEL_NOT_SUPPORTED", strlen("CKR_SESSION_PARALLEL_NOT_SUPPORTED")+1);
			return;

		case CKR_SESSION_READ_ONLY:
			memcpy(buffer,"CKR_SESSION_READ_ONLY", strlen("CKR_SESSION_READ_ONLY")+1);
			return;

		case CKR_SESSION_EXISTS:
			memcpy(buffer,"CKR_SESSION_EXISTS", strlen("CKR_SESSION_EXISTS")+1);
			return;

		case CKR_SESSION_READ_ONLY_EXISTS:
			memcpy(buffer,"CKR_SESSION_READ_ONLY_EXISTS", strlen("CKR_SESSION_READ_ONLY_EXISTS")+1);
			return;

		case CKR_TEMPLATE_INCOMPLETE:
			memcpy(buffer,"CKR_TEMPLATE_INCOMPLETE", strlen("CKR_TEMPLATE_INCOMPLETE")+1);
			return;

		case CKR_TEMPLATE_INCONSISTENT:
			memcpy(buffer,"CKR_TEMPLATE_INCONSISTENT", strlen("CKR_TEMPLATE_INCONSISTENT")+1);
			return;

		case CKR_TOKEN_NOT_PRESENT:
			memcpy(buffer,"CKR_TOKEN_NOT_PRESENT", strlen("CKR_TOKEN_NOT_PRESENT")+1);
			return;

		case CKR_TOKEN_NOT_RECOGNIZED:
			memcpy(buffer,"CKR_TOKEN_NOT_RECOGNIZED", strlen("CKR_TOKEN_NOT_RECOGNIZED")+1);
			return;

		case CKR_USER_ALREADY_LOGGED_IN:
			memcpy(buffer,"CKR_USER_ALREADY_LOGGED_IN", strlen("CKR_USER_ALREADY_LOGGED_IN")+1);
			return;

		case CKR_USER_NOT_LOGGED_IN:
			memcpy(buffer,"CKR_USER_NOT_LOGGED_IN", strlen("CKR_USER_NOT_LOGGED_IN")+1);
			return;

		case CKR_USER_TYPE_INVALID:
			memcpy(buffer,"CKR_USER_TYPE_INVALID", strlen("CKR_USER_TYPE_INVALID")+1);
			return;

		case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
			memcpy(buffer,"CKR_USER_ANOTHER_ALREADY_LOGGED_IN", strlen("CKR_USER_ANOTHER_ALREADY_LOGGED_IN")+1);
			return;

		case CKR_RANDOM_SEED_NOT_SUPPORTED:
			memcpy(buffer,"CKR_RANDOM_SEED_NOT_SUPPORTED", strlen("CKR_RANDOM_SEED_NOT_SUPPORTED")+1);
			return;

		case CKR_RANDOM_NO_RNG:
			memcpy(buffer,"CKR_RANDOM_NO_RNG", strlen("CKR_RANDOM_NO_RNG")+1);
			return;

		case CKR_BUFFER_TOO_SMALL:
			memcpy(buffer,"CKR_BUFFER_TOO_SMALL", strlen("CKR_BUFFER_TOO_SMALL")+1);
			return;

		case CKR_CRYPTOKI_NOT_INITIALIZED:
			memcpy(buffer,"CKR_CRYPTOKI_NOT_INITIALIZED", strlen("CKR_CRYPTOKI_NOT_INITIALIZED")+1);
			return;

		case CKR_CRYPTOKI_ALREADY_INITIALIZED:
			memcpy(buffer,"CKR_CRYPTOKI_ALREADY_INITIALIZED", strlen("CKR_CRYPTOKI_ALREADY_INITIALIZED")+1);
			return;

		case CKR_VENDOR_DEFINED:
			memcpy(buffer,"CKR_VENDOR_DEFINED", strlen("CKR_VENDOR_DEFINED")+1);
			return;
		case CKR_KEY_FUNCTION_NOT_PERMITTED:
			memcpy(buffer,"CKR_KEY_FUNCTION_NOT_PERMITTED", strlen("CKR_KEY_FUNCTION_NOT_PERMITTED")+1);
			return;
		default :
			memcpy(buffer,"Not Found", strlen("Not Found")+1);
			return;
		
	}
}

