/* SPDX-License-Identifier: MIT */
#include "diam.h"

#include <string.h>

int diam_avp_next(const uint8_t **p, const uint8_t *end, struct avp *a)
{
	if (*p == end)
		return 0;
	if ((size_t)(end - *p) < DIAM_AVP_HDR)
		return -1;
	uint32_t code = rd32(*p);
	uint8_t flags = (*p)[4];
	uint32_t len = rd24(*p + 5);
	size_t hdr = DIAM_AVP_HDR;

	if (flags & 0x80) /* vendor-specific: not used by these AVPs */
		hdr += 4;
	if (len < hdr || len > (size_t)(end - *p))
		return -1;
	a->code = code;
	a->data = *p + hdr;
	a->len = len - hdr;
	size_t step = pad4(len);
	*p = step > (size_t)(end - *p) ? end : *p + step;
	return 1;
}

size_t diam_check_ccr(const uint8_t *msg, size_t len)
{
	if (len < DIAM_HDR_LEN || msg[0] != 1)
		return 0;
	uint32_t mlen = rd24(msg + 1);
	if (mlen < DIAM_HDR_LEN || mlen > len || (mlen & 3))
		return 0;
	if (!(msg[4] & DIAM_FLAG_REQUEST) || rd24(msg + 5) != DIAM_CMD_CC ||
	    rd32(msg + 8) != DIAM_APP_CC)
		return 0;
	return mlen;
}

size_t diam_put_hdr(uint8_t *out, uint8_t flags, uint32_t hbh, uint32_t e2e)
{
	out[0] = 1;
	wr24(out + 1, DIAM_HDR_LEN);
	out[4] = flags;
	wr24(out + 5, DIAM_CMD_CC);
	wr32(out + 8, DIAM_APP_CC);
	wr32(out + 12, hbh);
	wr32(out + 16, e2e);
	return DIAM_HDR_LEN;
}

size_t diam_put_avp(uint8_t *out, uint32_t code, const void *data, size_t len)
{
	wr32(out, code);
	out[4] = DIAM_AVP_FLAG_M;
	wr24(out + 5, (uint32_t)(DIAM_AVP_HDR + len));
	memcpy(out + DIAM_AVP_HDR, data, len);
	size_t total = pad4(DIAM_AVP_HDR + len);
	memset(out + DIAM_AVP_HDR + len, 0, total - DIAM_AVP_HDR - len);
	return total;
}

size_t diam_put_u32(uint8_t *out, uint32_t code, uint32_t v)
{
	uint8_t b[4];
	wr32(b, v);
	return diam_put_avp(out, code, b, 4);
}

void diam_finish(uint8_t *msg, size_t len)
{
	wr24(msg + 1, (uint32_t)len);
}

static size_t put_unit(uint8_t *out, uint32_t code, uint32_t seconds)
{
	uint8_t inner[12];
	size_t n = diam_put_u32(inner, AVP_CC_TIME, seconds);
	return diam_put_avp(out, code, inner, n);
}

size_t diam_build_ccr(uint8_t *out, const char *session_id, uint32_t req_type,
		      uint32_t req_num, const char *msisdn, uint32_t requested_s,
		      uint32_t used_s, uint32_t hbh, uint32_t e2e)
{
	size_t n = diam_put_hdr(out, DIAM_FLAG_REQUEST, hbh, e2e);
	n += diam_put_avp(out + n, AVP_SESSION_ID, session_id, strlen(session_id));
	n += diam_put_u32(out + n, AVP_CC_REQUEST_TYPE, req_type);
	n += diam_put_u32(out + n, AVP_CC_REQUEST_NUMBER, req_num);

	uint8_t sub[64];
	size_t s = diam_put_u32(sub, AVP_SUBSCRIPTION_ID_TYPE, 0); /* END_USER_E164 */
	s += diam_put_avp(sub + s, AVP_SUBSCRIPTION_ID_DATA, msisdn, strlen(msisdn));
	n += diam_put_avp(out + n, AVP_SUBSCRIPTION_ID, sub, s);

	if (req_type != CC_TERMINATION)
		n += put_unit(out + n, AVP_REQUESTED_SERVICE_UNIT, requested_s);
	if (req_type != CC_INITIAL)
		n += put_unit(out + n, AVP_USED_SERVICE_UNIT, used_s);
	diam_finish(out, n);
	return n;
}
