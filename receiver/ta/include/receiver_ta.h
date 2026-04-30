#ifndef TA_RECEIVER_H
#define TA_RECEIVER_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 87a9cc3f-4854-477d-99dd-112f3cc15194
 */
#define TA_RECEIVER_UUID \
	{ 0x87a9cc3f, 0x4854, 0x477d, \
		{ 0x99, 0xdd, 0x11, 0x2f, 0x3c, 0xc1, 0x51, 0x94} }

/* The function IDs implemented in this TA */
#define CMD_IMPORT_PUBLIC_KEY		0
#define CMD_VERIFY_SIGNATURE		1

#endif /*TA_RECEIVER_H*/
