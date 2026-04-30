#ifndef TA_SENDER_H
#define TA_SENDER_H


/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
/*ca09a961-8880-49e8-ac9b-b028f54cdd74*/
#define TA_SENDER_UUID \
	{ 0xca09a961, 0x8880, 0x49e8, \
		{ 0xac, 0x9b, 0xb0, 0x28, 0xf5, 0x4c, 0xdd, 0x74} }

/* The function IDs implemented in this TA */
#define CMD_GEN_KEY         0
#define CMD_SIGN_DATA       1
#define CMD_GET_PUBLIC_KEY  2

#endif /*TA_SENDER_H*/
