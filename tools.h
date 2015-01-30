int message(int cond, char* message);
int verifyCode(CK_RV geted, CK_RV expected, char * previus);
int verifyCode2(CK_RV geted, CK_RV expected, CK_RV expected2, char * previus);
int verifyCode3(CK_RV geted, CK_RV expected, CK_RV expected2, CK_RV expected3, char * previus);
int initDynamicLibrary(char* path);
int closeDynamicLibrary();
void printlnLevel(int showMessage, char* data ,int level);
char* checkCkFunctionList(CK_FUNCTION_LIST_PTR pFunctions);
int contains(int * set, int size, int elem);
int isBlankPadded(unsigned char * src, int n);
void toStr(unsigned char * source, int sourceLen, char * result);
int indexOfElem(int elem, int * array, int n);
void assert2(int beh, int cond);

void getClassName(CK_OBJECT_CLASS elem, char * buffer);
void getUserName(CK_USER_TYPE elem, char * buffer);
void getStateName(CK_STATE elem, char * buffer);
void getHadwareName(CK_HW_FEATURE_TYPE elem, char * buffer);
void getKeyName(CK_KEY_TYPE elem, char * buffer);
void getAttributeName(CK_ATTRIBUTE_TYPE elem, char * buffer);
void getMechanismName(CK_MECHANISM_TYPE elem, char * buffer);
void getCodeName(CK_RV elem, char * buffer);

#define C_Initialize (lib -> C_Initialize)
#define C_Finalize (lib -> C_Finalize)
#define C_GetInfo (lib -> C_GetInfo)
#define C_GetFunctionList (lib -> C_GetFunctionList)
#define C_InitToken (lib -> C_InitToken)
#define C_InitPIN (lib -> C_InitPIN)
#define C_SetPIN (lib -> C_SetPIN)
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
#define ASK 0
#define FAIL 1
#define PASS 2

