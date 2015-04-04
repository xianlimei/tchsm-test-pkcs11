void inittoken();
void runInitCheck(unsigned int counter);
void runInfoCheck(unsigned int counter);
void runSessionCheck(unsigned int counter);
void runUserCheck(unsigned int counter);
void runRandomCheck(unsigned int counter);
void runGenerateCheck(unsigned int counter);
void runObjectCheck(unsigned int counter);
void runDigestCheck(unsigned int counter);
void runSignCheck(unsigned int counter);

//VALORES DEBEN VENIR CON JUNTO CON LA IMPLEMENTACION DE HSM
/* Maximum PIN length */
#define MAX_PIN_LEN 255

/* Minimum PIN length */
#define MIN_PIN_LEN 4
