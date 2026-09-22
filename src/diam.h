/* SPDX-License-Identifier: MIT */
/* Minimal Diameter (RFC 6733) encoding for the Ro credit-control
 * application (RFC 4006). Only what the charging engines need. */
#ifndef DIAM_H
#define DIAM_H

#include <stddef.h>
#include <stdint.h>

#define DIAM_HDR_LEN 20
#define DIAM_AVP_HDR 8
#define DIAM_FLAG_REQUEST 0x80
#define DIAM_AVP_FLAG_M 0x40
#define DIAM_CMD_CC 272
#define DIAM_APP_CC 4

enum {
	AVP_SESSION_ID = 263,
	AVP_ORIGIN_HOST = 264,
	AVP_RESULT_CODE = 268,
	AVP_ORIGIN_REALM = 296,
	AVP_CC_REQUEST_NUMBER = 415,
	AVP_CC_REQUEST_TYPE = 416,
	AVP_CC_TIME = 420,
	AVP_GRANTED_SERVICE_UNIT = 431,
	AVP_REQUESTED_SERVICE_UNIT = 437,
	AVP_SUBSCRIPTION_ID = 443,
	AVP_SUBSCRIPTION_ID_DATA = 444,
	AVP_USED_SERVICE_UNIT = 446,
	AVP_SUBSCRIPTION_ID_TYPE = 450,
};

enum { CC_INITIAL = 1, CC_UPDATE = 2, CC_TERMINATION = 3 };

enum {
	DIAMETER_SUCCESS = 2001,
	DIAMETER_UNABLE_TO_COMPLY = 5012,
	DIAMETER_UNKNOWN_SESSION_ID = 5002,
	DIAMETER_CREDIT_LIMIT_REACHED = 4012,
	DIAMETER_USER_UNKNOWN = 5030,
};

#define ORIGIN_HOST "ocs.example.org"
#define ORIGIN_REALM "example.org"

static inline uint32_t rd24(const uint8_t *p) { return (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2]; }
static inline uint32_t rd32(const uint8_t *p) { return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3]; }
static inline void wr24(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 16); p[1] = (uint8_t)(v >> 8); p[2] = (uint8_t)v; }
static inline void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
static inline size_t pad4(size_t n) { return (n + 3) & ~(size_t)3; }

/* A view of one AVP inside a message buffer: no copies. */
struct avp {
	uint32_t code;
	const uint8_t *data;
	size_t len;
};

/* Iterates the AVPs in [p, end). Returns 1 and fills *a, 0 at the end,
 * -1 if the next AVP is malformed (bad length, vendor flag, overrun). */
int diam_avp_next(const uint8_t **p, const uint8_t *end, struct avp *a);

/* Checks the Diameter header of a CCR. Returns the message length, or 0. */
size_t diam_check_ccr(const uint8_t *msg, size_t len);

/* Writers used by the client/test side and by the baseline engine. */
size_t diam_put_hdr(uint8_t *out, uint8_t flags, uint32_t hbh, uint32_t e2e);
size_t diam_put_avp(uint8_t *out, uint32_t code, const void *data, size_t len);
size_t diam_put_u32(uint8_t *out, uint32_t code, uint32_t v);
void diam_finish(uint8_t *msg, size_t len);

/* Builds a CCR as a P-CSCF/TAS would send it. Returns its length. */
size_t diam_build_ccr(uint8_t *out, const char *session_id, uint32_t req_type,
		      uint32_t req_num, const char *msisdn, uint32_t requested_s,
		      uint32_t used_s, uint32_t hbh, uint32_t e2e);

#endif
