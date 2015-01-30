# TestPKCS11
tests for HSMs that implement the API PKCS11v2.20

# Dependencies
- libssl-dev (openssl library)

# Usage
- FirstArgument: (one or more)option/s
	-f(FAIL) if an error happens the test stops
	-a(ASK) if an error happens the test asks for continuing
	-p(PASS) if an error happens the test continues
	-r(REPEAT) run stress tests
	-h(HIDE) hide the progress report
- Second Argument: [path to the dynamic cryptoki library]
- Third Argument: [n], positive number which indicates the HSM's number of slots
- Following 2n arguments: slotID-information tuples. Options:
	 slotID NOTOKEN when the slot does not have a token inside
	 slotID NOINIT when the slot has a token, but it is not initialized
	 slotID [soPIN] when the slot has a token and its soPIN(Security Officer PIN) is given
- Eg: Using the SoftHSM cryptoki library in PASS mode, hiding the progress report, with 3 slots(0 does not have a token, 1 has a token and soPIN 12345678 and 2 has a token but it is not initialized)
./testPKCS11 -ph /usr/lib/softhsm/libsofthsm.so 3 0 NOTOKEN 1 12345678 2 NOINIT
